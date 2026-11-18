"""Tests for the directed rogue-DHCP probe.

Real UDP is used end to end: fake responders (including delayed and
identifier-spoofing ones) run in threads, and the FastAPI app drives the same
probe engine the web console uses.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid

from fastapi.testclient import TestClient

from app.config import Settings
from app.dhcp.packet import (
    DHCPDISCOVER,
    DHCPOFFER,
    OPTION_CLIENT_ID,
    OPTION_ROUTER,
    OPTION_SERVER_ID,
    build_packet,
    build_reply,
    parse_packet,
)
from app.dhcp.probe import (
    VERDICT_ID_MISMATCH,
    VERDICT_ROGUE,
    VERDICT_SPOOF,
    VERDICT_TRUSTED,
    classify_reply,
)
from app.main import create_app
from tests.test_dhcp import SERVER, mac_bytes

TRUSTED_SID = SERVER  # 192.0.2.2


def _free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class FakeDhcpResponder:
    """Minimal DHCP server on a thread; behaviour is configurable."""

    def __init__(
        self,
        *,
        server_id: str,
        offer_ip: str = "198.51.100.230",
        router: str = "198.51.100.1",
        delay: float = 0.0,
        bad_xid: bool = False,
        serve_forever: bool = True,
    ) -> None:
        self.server_id = server_id
        self.offer_ip = offer_ip
        self.router = router
        self.delay = delay
        self.bad_xid = bad_xid
        self.serve_forever = serve_forever
        self.port = _free_udp_port()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.seen: list[dict] = []
        self._stop = threading.Event()

    def start(self) -> "FakeDhcpResponder":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                request = parse_packet(data)
            except Exception:
                continue
            self.seen.append({"xid": request.xid, "mac": request.mac})
            if request.message_type != DHCPDISCOVER:
                continue
            if self.delay:
                if self._stop.wait(self.delay):
                    return
            self._answer(request, addr)
            if not self.serve_forever:
                return

    def _answer(self, request, addr: tuple[str, int]) -> None:
        assert self._sock is not None
        xid = (request.xid + 1) & 0xFFFFFFFF if self.bad_xid else request.xid
        reply = build_reply(
            request,
            message_type=DHCPOFFER,
            yiaddr=ipaddress.IPv4Address(self.offer_ip),
            server_id=ipaddress.IPv4Address(self.server_id),
            lease_time=60,
            subnet_mask=ipaddress.IPv4Address("255.255.255.0"),
            router=ipaddress.IPv4Address(self.router),
            dns=(ipaddress.IPv4Address(self.router),),
        )
        if self.bad_xid:
            # Rebuild with the altered xid while keeping identity fields.
            reply = build_packet(
                op=2,
                xid=xid,
                chaddr=request.chaddr,
                htype=request.htype,
                hlen=request.hlen,
                message_type=DHCPOFFER,
                yiaddr=ipaddress.IPv4Address(self.offer_ip),
                giaddr=request.giaddr,
                flags=request.flags,
                options={
                    OPTION_SERVER_ID: ipaddress.IPv4Address(self.server_id).packed,
                    OPTION_ROUTER: ipaddress.IPv4Address(self.router).packed,
                },
            )
        self._sock.sendto(reply, addr)


class ProbeTestBase(unittest.TestCase):
    probe_timeout = 1.5

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = Settings(
            pool_start=ipaddress.IPv4Address("192.0.2.100"),
            pool_end=ipaddress.IPv4Address("192.0.2.105"),
            server_identifier=ipaddress.IPv4Address(TRUSTED_SID),
            broadcast=ipaddress.IPv4Address("192.0.2.255"),
            lease_time=120,
            offer_ttl=60,
            db_path=os.path.join(self.tmp.name, "db.sqlite3"),
            udp_port=0,
            sim_target_port=0,
            sim_timeout=2.0,
            probe_timeout=self.probe_timeout,
        )
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.health = self.client.get("/api/health").json()
        self.responders: list[FakeDhcpResponder] = []

    def tearDown(self) -> None:
        for responder in self.responders:
            responder.stop()
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def _endpoint(self, responder: FakeDhcpResponder, *, trusted: bool,
                  expected_sid: str | None, name: str | None = None) -> dict:
        body = {
            "name": name or f"ep-{uuid.uuid4().hex[:8]}",
            "host": "127.0.0.1",
            "port": responder.port,
            "trusted": trusted,
            "expected_server_id": expected_sid,
        }
        res = self.client.post("/api/probe/endpoints", json=body)
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def _start_responder(self, **kwargs) -> FakeDhcpResponder:
        responder = FakeDhcpResponder(**kwargs).start()
        self.responders.append(responder)
        return responder

    def _start_round(self, endpoints: list[dict]) -> dict:
        res = self.client.post(
            "/api/probe/rounds",
            json={"endpoint_ids": [ep["id"] for ep in endpoints]},
        )
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def _wait_round(self, round_id: int, timeout: float | None = None) -> dict:
        deadline = time.time() + (timeout or self.probe_timeout + 4.0)
        while time.time() < deadline:
            detail = self.client.get(f"/api/probe/rounds/{round_id}").json()
            if detail["status"] != "running":
                return detail
            time.sleep(0.05)
        self.fail(f"round {round_id} still running after deadline")

    def _target(self, detail: dict, endpoint_id: int) -> dict:
        return next(t for t in detail["targets"] if t["endpoint_id"] == endpoint_id)


class ProbeVerdictTests(ProbeTestBase):
    def test_trusted_and_rogue_and_spoof_classification(self) -> None:
        trusted = self._start_responder(server_id=TRUSTED_SID, offer_ip="192.0.2.100")
        rogue = self._start_responder(server_id="198.51.100.2")
        spoof = self._start_responder(server_id=TRUSTED_SID, offer_ip="198.51.100.231")

        ep_trusted = self._endpoint(trusted, trusted=True, expected_sid=TRUSTED_SID,
                                    name="受信")
        ep_rogue = self._endpoint(rogue, trusted=False, expected_sid=TRUSTED_SID,
                                  name="陌生")
        ep_spoof = self._endpoint(spoof, trusted=False, expected_sid=TRUSTED_SID,
                                  name="冒名")

        detail = self._wait_round(
            self._start_round([ep_trusted, ep_rogue, ep_spoof])["id"]
        )
        self.assertIn(detail["status"], ("completed", "timeout"))  # hard window or early finish
        verdicts = {
            t["name"]: [r["verdict"] for r in t["replies"]] for t in detail["targets"]
        }
        self.assertEqual(verdicts["受信"], [VERDICT_TRUSTED])
        self.assertEqual(verdicts["陌生"], [VERDICT_ROGUE])
        self.assertEqual(verdicts["冒名"], [VERDICT_SPOOF])

        # Evidence fields are populated for the audit view.
        spoof_target = self._target(detail, ep_spoof["id"])
        reply = spoof_target["replies"][0]
        self.assertEqual(reply["server_id"], TRUSTED_SID)
        self.assertEqual(reply["yiaddr"], "198.51.100.231")
        self.assertEqual(reply["router"], "198.51.100.1")
        self.assertIn("冒用", reply["reason"])

    def test_spoofed_identifier_from_untrusted_endpoint_never_trusted(self) -> None:
        spoof = self._start_responder(server_id=TRUSTED_SID)
        ep = self._endpoint(spoof, trusted=False, expected_sid=TRUSTED_SID, name="冒名2")
        detail = self._wait_round(self._start_round([ep])["id"])
        target = self._target(detail, ep["id"])
        self.assertEqual(target["state"], "answered")
        self.assertEqual(target["replies"][0]["verdict"], VERDICT_SPOOF)
        self.assertNotEqual(target["replies"][0]["verdict"], VERDICT_TRUSTED)

    def test_wrong_xid_is_identity_mismatch_and_target_unverified(self) -> None:
        bad = self._start_responder(server_id="198.51.100.2", bad_xid=True)
        ep = self._endpoint(bad, trusted=False, expected_sid=TRUSTED_SID, name="错xid")
        detail = self._wait_round(self._start_round([ep])["id"])
        target = self._target(detail, ep["id"])
        # Evidence retained, but it never counted as an answer.
        self.assertEqual(len(target["replies"]), 1)
        self.assertEqual(target["replies"][0]["verdict"], VERDICT_ID_MISMATCH)
        self.assertEqual(target["state"], "unverified")

    def test_silent_endpoint_is_marked_unverified_but_evidence_kept(self) -> None:
        noisy = self._start_responder(server_id=TRUSTED_SID)
        silent_port = _free_udp_port()  # nothing listens
        ep_noisy = self._endpoint(noisy, trusted=True, expected_sid=TRUSTED_SID,
                                  name="有应答")
        silent_body = {
            "name": "静默", "host": "127.0.0.1", "port": silent_port,
            "trusted": False, "expected_server_id": None,
        }
        ep_silent = self.client.post("/api/probe/endpoints", json=silent_body).json()

        detail = self._wait_round(
            self._start_round([ep_noisy, ep_silent])["id"]
        )
        silent_target = self._target(detail, ep_silent["id"])
        self.assertEqual(silent_target["state"], "unverified")
        self.assertEqual(silent_target["replies"], [])
        answered = self._target(detail, ep_noisy["id"])
        self.assertEqual(answered["state"], "answered")
        self.assertEqual(answered["replies"][0]["verdict"], VERDICT_TRUSTED)

    def test_late_reply_does_not_leak_into_next_round(self) -> None:
        # First responder answers well outside the probe window.
        late = self._start_responder(server_id="198.51.100.2", delay=4.0)
        ep = self._endpoint(late, trusted=False, expected_sid=TRUSTED_SID, name="迟到")
        first = self._wait_round(self._start_round([ep])["id"])
        first_target = self._target(first, ep["id"])
        self.assertEqual(first_target["state"], "unverified")
        self.assertEqual(first_target["replies"], [])
        first_identity = first["mac"]
        first_xid = first["xid"]

        # Let the late OFFER of round 1 arrive at the now-closed socket.
        time.sleep(4.5)

        # Round 2 against the same endpoint must not see round 1's datagram.
        second = self._wait_round(self._start_round([ep])["id"])
        self.assertNotEqual(second["mac"], first_identity)
        self.assertNotEqual(second["xid"], first_xid)
        second_target = self._target(second, ep["id"])
        # The responder answers every DISCOVER 4s late, so round 2 also times
        # out; the point is that round 1's packet never contaminated it.
        self.assertEqual(
            [r for r in second_target["replies"] if r["xid"] == first_xid], []
        )

    def test_round_cancel_keeps_evidence_and_marks_unverified(self) -> None:
        slow = self._start_responder(server_id="198.51.100.2", delay=3.0)
        ep = self._endpoint(slow, trusted=False, expected_sid=TRUSTED_SID, name="慢")
        started = self._start_round([ep])
        # Cancel almost immediately; no answer could have arrived yet.
        time.sleep(0.2)
        cancelled = self.client.post(
            f"/api/probe/rounds/{started['id']}/cancel"
        ).json()
        self.assertEqual(cancelled["status"], "cancelled")
        target = self._target(cancelled, ep["id"])
        self.assertEqual(target["state"], "unverified")
        # The delayed answer after cancellation must not resurrect the round.
        time.sleep(3.5)
        again = self.client.get(f"/api/probe/rounds/{started['id']}").json()
        self.assertEqual(again["status"], "cancelled")
        self.assertEqual(
            self._target(again, ep["id"])["replies"], []
        )

    def test_local_offer_is_withdrawn_and_bound_lease_untouched(self) -> None:
        port = self.health["udp_port"]
        ep_body = {
            "name": "本服务", "host": "127.0.0.1", "port": port,
            "trusted": True, "expected_server_id": TRUSTED_SID,
        }
        ep = self.client.post("/api/probe/endpoints", json=ep_body).json()

        # A real device holds a confirmed lease before the probe.
        real_mac = "02:00:00:00:77:01"
        discover = build_packet(
            op=1, xid=0x11111111, chaddr=mac_bytes(real_mac),
            message_type=DHCPDISCOVER, flags=0x8000,
            options={OPTION_CLIENT_ID: b"\x01" + mac_bytes(real_mac)},
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(discover, ("127.0.0.1", port))
            offer_raw, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        offered_ip = str(parse_packet(offer_raw).yiaddr)
        request_packet = build_packet(
            op=1, xid=0x22222222, chaddr=mac_bytes(real_mac),
            message_type=3, flags=0x8000,
            ciaddr=ipaddress.IPv4Address("0.0.0.0"),
            options={
                OPTION_CLIENT_ID: b"\x01" + mac_bytes(real_mac),
                OPTION_SERVER_ID: ipaddress.IPv4Address(TRUSTED_SID).packed,
                50: ipaddress.IPv4Address(offered_ip).packed,
            },
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(request_packet, ("127.0.0.1", port))
            ack_raw, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        self.assertEqual(parse_packet(ack_raw).message_type, 5)  # DHCPACK

        leases_before = {l["ip"]: l for l in
                         self.client.get("/api/leases").json()["leases"]}
        self.assertEqual(leases_before[offered_ip]["status"], "bound")

        detail = self._wait_round(self._start_round([ep])["id"])
        target = self._target(detail, ep["id"])
        self.assertEqual(target["replies"][0]["verdict"], VERDICT_TRUSTED)
        self.assertTrue(target["withdrawn_ips"], "probe offer must be withdrawn")

        leases_after = {l["ip"]: l for l in
                        self.client.get("/api/leases").json()["leases"]}
        # The synthetic probe identity's offer is gone...
        probe_macs = {l["client_mac"] for l in leases_after.values()}
        self.assertNotIn(detail["mac"], probe_macs)
        # ...and the real device's bound lease is completely untouched.
        self.assertIn(offered_ip, leases_after)
        self.assertEqual(leases_after[offered_ip]["status"], "bound")
        self.assertEqual(leases_after[offered_ip]["client_mac"], real_mac)

        events = self.client.get("/api/events").json()["events"]
        self.assertTrue(
            any(e["message_type"] == "PROBE_WITHDRAW" for e in events)
        )


class ProbeRegistryTests(ProbeTestBase):
    def test_endpoint_crud_and_validation(self) -> None:
        body = {
            "name": "登记1", "host": "127.0.0.1", "port": 6768,
            "trusted": False, "expected_server_id": "192.0.2.2",
        }
        created = self.client.post("/api/probe/endpoints", json=body)
        self.assertEqual(created.status_code, 201)
        endpoint_id = created.json()["id"]

        bad = self.client.post(
            "/api/probe/endpoints",
            json={**body, "expected_server_id": "not-an-ip"},
        )
        self.assertEqual(bad.status_code, 422)

        dup = self.client.post("/api/probe/endpoints", json=body)
        self.assertEqual(dup.status_code, 409)

        updated = self.client.put(
            f"/api/probe/endpoints/{endpoint_id}",
            json={**body, "trusted": True, "note": "已核实"},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertTrue(updated.json()["trusted"])

        listing = self.client.get("/api/probe/endpoints").json()["endpoints"]
        self.assertTrue(any(e["id"] == endpoint_id for e in listing))

        self.assertEqual(
            self.client.delete(f"/api/probe/endpoints/{endpoint_id}").status_code, 204
        )
        self.assertEqual(
            self.client.delete(f"/api/probe/endpoints/{endpoint_id}").status_code, 404
        )

    def test_start_round_rejects_unknown_endpoint(self) -> None:
        res = self.client.post("/api/probe/rounds", json={"endpoint_ids": [9999]})
        self.assertEqual(res.status_code, 404)

    def test_start_round_rejects_duplicate_peers(self) -> None:
        body = {
            "name": "对端A", "host": "127.0.0.1", "port": 6768,
            "trusted": False, "expected_server_id": None,
        }
        first = self.client.post("/api/probe/endpoints", json=body).json()
        second = self.client.post(
            "/api/probe/endpoints", json={**body, "name": "对端A-别名"}
        ).json()
        res = self.client.post(
            "/api/probe/rounds",
            json={"endpoint_ids": [first["id"], second["id"]]},
        )
        self.assertEqual(res.status_code, 422)

    def test_concurrent_rounds_have_independent_identities(self) -> None:
        responder = self._start_responder(server_id="198.51.100.2", delay=1.0)
        ep = self._endpoint(responder, trusted=False, expected_sid=TRUSTED_SID,
                            name="并发对端")
        r1 = self.client.post(
            "/api/probe/rounds", json={"endpoint_ids": [ep["id"]]}
        ).json()
        r2 = self.client.post(
            "/api/probe/rounds", json={"endpoint_ids": [ep["id"]]}
        ).json()
        self.assertNotEqual(r1["id"], r2["id"])
        self.assertNotEqual(r1["xid"], r2["xid"])
        self.assertNotEqual(r1["mac"], r2["mac"])
        d1 = self._wait_round(r1["id"])
        d2 = self._wait_round(r2["id"])
        # Each round's evidence only carries its own transaction id.
        for detail in (d1, d2):
            xids = {r["xid"] for t in detail["targets"] for r in t["replies"]}
            self.assertTrue(xids.issubset({detail["xid"]}))

    def test_seed_endpoints_registered_from_settings(self) -> None:
        self.tmp.cleanup()
        self.client.__exit__(None, None, None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        settings = Settings(
            pool_start=ipaddress.IPv4Address("192.0.2.100"),
            pool_end=ipaddress.IPv4Address("192.0.2.102"),
            server_identifier=ipaddress.IPv4Address(TRUSTED_SID),
            db_path=os.path.join(tmp.name, "db.sqlite3"),
            udp_port=0,
            sim_target_port=0,
            probe_seed_endpoints="受信|127.0.0.1|6767|1|192.0.2.2;坏条目;陌生|127.0.0.1|6768|0|",
        )
        app = create_app(settings)
        with TestClient(app) as client:
            endpoints = client.get("/api/probe/endpoints").json()["endpoints"]
            names = {e["name"] for e in endpoints}
            self.assertIn("受信", names)
            self.assertIn("陌生", names)
            trusted = next(e for e in endpoints if e["name"] == "受信")
            self.assertTrue(trusted["trusted"])
            self.assertEqual(trusted["expected_server_id"], "192.0.2.2")


class ClassifyReplyUnitTests(unittest.TestCase):
    def _offer(self, *, server_id: str | None, message_type: int = DHCPOFFER):
        mac = b"\x02\x00\x00\x00\x00\x09"
        options = {}
        if server_id is not None:
            options[OPTION_SERVER_ID] = ipaddress.IPv4Address(server_id).packed
        raw = build_packet(
            op=2, xid=1, chaddr=mac, message_type=message_type,
            yiaddr=ipaddress.IPv4Address("198.51.100.50"), options=options,
        )
        return parse_packet(raw)

    def test_classify_matrix(self) -> None:
        trusted_match = classify_reply(
            trusted=True, expected_server_id="192.0.2.2",
            packet=self._offer(server_id="192.0.2.2"),
        )
        self.assertEqual(trusted_match[0], VERDICT_TRUSTED)

        trusted_wrong_sid = classify_reply(
            trusted=True, expected_server_id="192.0.2.2",
            packet=self._offer(server_id="10.0.0.9"),
        )
        self.assertEqual(trusted_wrong_sid[0], VERDICT_SPOOF)

        untrusted_spoof = classify_reply(
            trusted=False, expected_server_id="192.0.2.2",
            packet=self._offer(server_id="192.0.2.2"),
        )
        self.assertEqual(untrusted_spoof[0], VERDICT_SPOOF)

        untrusted_own = classify_reply(
            trusted=False, expected_server_id="192.0.2.2",
            packet=self._offer(server_id="198.51.100.2"),
        )
        self.assertEqual(untrusted_own[0], VERDICT_ROGUE)

        non_offer = classify_reply(
            trusted=False, expected_server_id=None,
            packet=self._offer(server_id="198.51.100.2", message_type=5),  # ACK
        )
        self.assertEqual(non_offer[0], "unexpected-message-type")


if __name__ == "__main__":
    unittest.main(verbosity=2)
