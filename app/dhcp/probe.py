"""Directed rogue-DHCP probe engine.

A probe round sends real DHCPDISCOVER datagrams to a chosen set of registered
UDP endpoints and classifies every datagram that comes back.

Correctness rules enforced here:

* Every round mints a fresh transaction id (xid) and a synthetic probe device
  identity (MAC + Client Identifier). Replies must carry both back; anything
  that does not match is recorded as evidence but never accepted as an answer.
* Trust is decided from the *network endpoint* that answered. A response from
  an unregistered/non-trusted endpoint that copies a trusted Server Identifier
  is classified as a spoof, never as trusted.
* Each round owns a single unconnected UDP socket and demultiplexes incoming
  datagrams by their source (host, port) in userspace. A connected socket per
  endpoint would not work: several such sockets on 0.0.0.0 end up competing
  for the same wildcard delivery, so replies land on an arbitrary one. The
  per-round socket also guarantees that a late reply of an old round cannot
  land in a new round; round id, xid and chaddr are checked again in
  userspace as defence in depth, and late datagrams are dropped.
* Only DISCOVER is sent: no REQUEST is ever emitted, so no lease is confirmed.
  When a round ends (completed/cancelled/timeout) the unconfirmed offers that
  the local, trusted service reserved for the synthetic identity are withdrawn
  via the lease store; bound leases of real devices are never touched.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings
from .packet import (
    BOOTREPLY,
    DHCPDISCOVER,
    DHCPOFFER,
    OPTION_CLIENT_ID,
    OPTION_HOSTNAME,
    OPTION_ROUTER,
    OPTION_SERVER_ID,
    DhcpPacket,
    PacketError,
    build_packet,
    parse_packet,
)
from .store import LeaseStore

log = logging.getLogger("dhcp.probe")

# Verdict labels (persisted and shown verbatim in the UI).
VERDICT_TRUSTED = "trusted"
VERDICT_ROGUE = "rogue"
VERDICT_SPOOF = "spoofed-identifier"
VERDICT_ID_MISMATCH = "identity-mismatch"
VERDICT_MALFORMED = "malformed"
VERDICT_NON_OFFER = "unexpected-message-type"

ROUND_COMPLETED = "completed"
ROUND_CANCELLED = "cancelled"
ROUND_TIMEOUT = "timeout"

_TARGET_ANSWERED = "answered"
_TARGET_UNVERIFIED = "unverified"
_TARGET_ERROR = "error"


@dataclass(frozen=True)
class ProbeIdentity:
    mac: str
    mac_bytes: bytes
    client_key: str
    xid: int

    @classmethod
    def mint(cls, settings: Settings, xid: int) -> "ProbeIdentity":
        oui = settings.probe_mac_oui.replace(":", "").lower()
        suffix = secrets.token_hex(3)
        mac = ":".join(
            [oui[0:2], oui[2:4], oui[4:6], suffix[0:2], suffix[2:4], suffix[4:6]]
        )
        mac_bytes = bytes.fromhex(mac.replace(":", ""))
        return cls(
            mac=mac,
            mac_bytes=mac_bytes,
            client_key="mac:" + mac,
            xid=xid,
        )


@dataclass
class _TargetCtx:
    target_id: int
    endpoint: dict[str, Any]
    answered: bool = False
    first_seen: float | None = None


@dataclass
class _RoundCtx:
    round_id: int
    identity: ProbeIdentity
    timeout: float
    endpoints: list[dict[str, Any]]
    targets: dict[int, _TargetCtx] = field(default_factory=dict)
    # Target id keyed by the *configured* peer of each endpoint.
    by_peer: dict[tuple[str, int], int] = field(default_factory=dict)
    transport: asyncio.DatagramTransport | None = None
    done_event: asyncio.Event = field(default_factory=asyncio.Event)
    cancelled: bool = False
    cleanup_done: bool = False


def classify_reply(
    *,
    trusted: bool,
    expected_server_id: str | None,
    packet: DhcpPacket,
) -> tuple[str, str]:
    """Pure verdict logic for a parseable reply that matched xid and identity."""
    server_id = packet.option_ip(OPTION_SERVER_ID)
    server_id_text = str(server_id) if server_id is not None else None
    if packet.message_type != DHCPOFFER:
        return (
            VERDICT_NON_OFFER,
            f"应答类型为 {packet.message_type}，不是 DHCPOFFER",
        )
    if trusted:
        if expected_server_id and server_id_text != expected_server_id:
            return (
                VERDICT_SPOOF,
                f"受信端点应答的 Server Identifier 为 {server_id_text or '缺失'}，"
                f"与登记值 {expected_server_id} 不符",
            )
        return (
            VERDICT_TRUSTED,
            f"应答来自受信端点，Server Identifier {server_id_text or '缺失'} 与登记一致",
        )
    if expected_server_id and server_id_text == expected_server_id:
        return (
            VERDICT_SPOOF,
            f"非受信端点冒用受信 Server Identifier {server_id_text}，端点本身不在受信清单内",
        )
    return (
        VERDICT_ROGUE,
        f"应答来自非受信端点，Server Identifier {server_id_text or '缺失'}，拟分配 "
        f"{packet.yiaddr}",
    )


class ProbeManager:
    """Owns running probe rounds and the sockets that collect their evidence."""

    def __init__(self, settings: Settings, store: LeaseStore) -> None:
        self.settings = settings
        self.store = store
        self._rounds: dict[int, _RoundCtx] = {}
        self._lock = asyncio.Lock()

    # -- round lifecycle ---------------------------------------------------

    async def start_round(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        async with self._lock:
            xid = self.store.new_xid()
            identity = ProbeIdentity.mint(self.settings, xid)
            timeout = float(self.settings.probe_timeout)
            round_id = self.store.create_probe_round(
                xid=identity.xid,
                mac=identity.mac,
                client_key=identity.client_key,
                timeout=timeout,
            )
            ctx = _RoundCtx(
                round_id=round_id, identity=identity, timeout=timeout,
                endpoints=endpoints,
            )
            discover = self._build_discover(identity)
            loop = asyncio.get_running_loop()

            # One unconnected socket for the whole round. All endpoint replies
            # arrive here and are demultiplexed by source address below.
            try:
                transport, _proto = await loop.create_datagram_endpoint(
                    lambda: _ProbeProtocol(self, ctx),
                    local_addr=("0.0.0.0", 0),
                )
            except OSError as exc:
                self.store.finish_probe_round(
                    round_id, status=ROUND_TIMEOUT,
                    reason=f"无法建立探测 UDP 套接字: {exc}",
                )
                return self.store.get_probe_round_detail(round_id)  # type: ignore[return-value]
            ctx.transport = transport

            for endpoint in endpoints:
                target_id = self.store.create_probe_target(
                    round_id=round_id, endpoint=endpoint
                )
                target = _TargetCtx(target_id=target_id, endpoint=endpoint)
                ctx.targets[target_id] = target
                peer = (str(endpoint["host"]), int(endpoint["port"]))
                # First registration wins if the same peer was listed twice.
                ctx.by_peer.setdefault(peer, target_id)
                try:
                    transport.sendto(discover, peer)
                except OSError as exc:
                    log.warning(
                        "probe round %s: sendto %s failed: %s",
                        round_id, peer, exc,
                    )
                    # No datagram exists for this failure, so keep it on the
                    # target state instead of fabricating an evidence row.
                    self.store.update_probe_target(target_id, state=_TARGET_ERROR)

            self._rounds[round_id] = ctx
            # Background watcher: timeout and evidence collection.
            asyncio.create_task(self._watch(ctx))
            return self.store.get_probe_round_detail(round_id)  # type: ignore[return-value]

    async def cancel_round(self, round_id: int) -> dict[str, Any]:
        async with self._lock:
            ctx = self._rounds.get(round_id)
            if ctx is None:
                # Already finished: return the preserved evidence untouched.
                detail = self.store.get_probe_round_detail(round_id)
                if detail is None:
                    raise KeyError(round_id)
                return detail
            ctx.cancelled = True
            ctx.done_event.set()
            await self._finalize(ctx, ROUND_CANCELLED, "用户取消：保留已收证据")
            return self.store.get_probe_round_detail(round_id)  # type: ignore[return-value]

    async def shutdown(self) -> None:
        for round_id in list(self._rounds):
            try:
                await self.cancel_round(round_id)
            except Exception:  # pragma: no cover - best effort shutdown
                log.exception("probe round %s shutdown failed", round_id)

    # -- internals ---------------------------------------------------------

    def _build_discover(self, identity: ProbeIdentity) -> bytes:
        return build_packet(
            op=1,
            xid=identity.xid,
            chaddr=identity.mac_bytes,
            message_type=DHCPDISCOVER,
            flags=0x8000,
            options={
                OPTION_CLIENT_ID: b"\x01" + identity.mac_bytes,
                OPTION_HOSTNAME: b"dhcp-probe",
            },
        )

    async def _watch(self, ctx: _RoundCtx) -> None:
        try:
            await asyncio.wait_for(ctx.done_event.wait(), timeout=ctx.timeout)
            early = True
        except asyncio.TimeoutError:
            early = False
        # Serialize against cancel_round(): whoever wins the lock finalises.
        async with self._lock:
            if ctx.cleanup_done:
                return
            if ctx.cancelled:
                return
            if early:
                await self._finalize(
                    ctx, ROUND_COMPLETED,
                    "所有目标均已取得与本轮 XID/身份匹配的应答",
                )
            else:
                await self._finalize(
                    ctx, ROUND_TIMEOUT, "等待窗口结束：未应答端点标记为未核实"
                )

    async def _finalize(self, ctx: _RoundCtx, status: str, reason: str) -> None:
        # Stop receiving first, then give in-flight datagrams one loop turn.
        if ctx.transport is not None:
            ctx.transport.close()
            ctx.transport = None
        await asyncio.sleep(0)

        for target in ctx.targets.values():
            if not target.answered:
                self.store.update_probe_target(
                    target.target_id, state=_TARGET_UNVERIFIED
                )

        # Withdraw only this round's unconfirmed offers at the local service.
        # Bound leases are excluded inside the store method.
        try:
            withdrawn = self.store.withdraw_probe_offers(
                round_id=ctx.round_id,
                client_key=ctx.identity.client_key,
                mac=ctx.identity.mac,
            )
        except Exception:  # pragma: no cover - cleanup must not crash the loop
            log.exception("probe round %s: offer withdrawal failed", ctx.round_id)
            withdrawn = []
        if withdrawn:
            # The reservation lives at the local trusted service; record the
            # cleanup on that target for the evidence view.
            for target in ctx.targets.values():
                if target.endpoint.get("trusted"):
                    self.store.update_probe_target(
                        target.target_id,
                        state=_TARGET_ANSWERED if target.answered else _TARGET_UNVERIFIED,
                        withdrawn_ips=withdrawn,
                    )

        self.store.finish_probe_round(ctx.round_id, status=status, reason=reason)
        ctx.cleanup_done = True
        self._rounds.pop(ctx.round_id, None)
        log.info(
            "probe round %s finished as %s; withdrew offers %s",
            ctx.round_id, status, withdrawn,
        )

    def handle_datagram(
        self,
        ctx: _RoundCtx,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Demultiplex one datagram received on the round's shared socket."""
        # Round-level guard: rounds are removed from the active map at
        # finalize(), so a late datagram of a dead round never reaches storage.
        if ctx.cleanup_done or self._rounds.get(ctx.round_id) is not ctx:
            log.info(
                "probe round %s: dropping late datagram (%d bytes) from %s",
                ctx.round_id, len(data), addr,
            )
            return

        target_id = ctx.by_peer.get(addr)
        if target_id is None:
            # Source we never probed. Keep it out of every target, but log so
            # an unexpected talker is still visible.
            log.info(
                "probe round %s: datagram from unregistered peer %s dropped",
                ctx.round_id, addr,
            )
            return
        target = ctx.targets[target_id]
        identity = ctx.identity

        try:
            packet = parse_packet(data)
        except PacketError as exc:
            self._persist_reply(
                ctx, target, data, addr,
                parsed=None,
                verdict=VERDICT_MALFORMED,
                reason=f"报文无法解析: {exc}",
                parse_error=str(exc),
            )
            target.answered = True
            return

        # Transaction + device identity check. Either mismatch means this
        # datagram is not an answer to *this* probe, even from the right peer.
        identity_ok = (
            packet.op == BOOTREPLY
            and packet.xid == identity.xid
            and packet.mac == identity.mac
        )
        if not identity_ok:
            reason = (
                f"事务号/设备身份不符：应答 xid=0x{packet.xid:08x}、"
                f"chaddr={packet.mac}，本轮要求 xid=0x{identity.xid:08x}、"
                f"chaddr={identity.mac}"
            )
            self._persist_reply(
                ctx, target, data, addr,
                parsed=packet,
                verdict=VERDICT_ID_MISMATCH,
                reason=reason,
                parse_error=None,
            )
            # Identity mismatches are evidence, not answers.
            return

        endpoint = target.endpoint
        verdict, reason = classify_reply(
            trusted=bool(endpoint["trusted"]),
            expected_server_id=endpoint.get("expected_server_id"),
            packet=packet,
        )
        self._persist_reply(
            ctx, target, data, addr,
            parsed=packet,
            verdict=verdict,
            reason=reason,
            parse_error=None,
        )
        target.answered = True
        target.first_seen = time.time()
        self.store.update_probe_target(target.target_id, state=_TARGET_ANSWERED)
        # Once every target has produced evidence we can finish early; the
        # timeout path still guarantees a hard upper bound.
        if all(t.answered for t in ctx.targets.values()):
            ctx.done_event.set()

    def _persist_reply(
        self,
        ctx: _RoundCtx,
        target: _TargetCtx,
        data: bytes,
        addr: tuple[str, int],
        *,
        parsed: DhcpPacket | None,
        verdict: str,
        reason: str,
        parse_error: str | None,
    ) -> None:
        router = None
        if parsed is not None:
            router_opt = parsed.option_ip(OPTION_ROUTER)
            router = str(router_opt) if router_opt is not None else None
        self.store.add_probe_reply(
            target_id=target.target_id,
            round_id=ctx.round_id,
            at=time.time(),
            source_host=addr[0],
            source_port=addr[1],
            xid=parsed.xid if parsed is not None else None,
            chaddr=parsed.mac if parsed is not None else None,
            message_type=(
                parsed.summary().get("message_type_name") if parsed is not None else None
            ),
            server_id=(
                str(parsed.option_ip(OPTION_SERVER_ID))
                if parsed is not None and parsed.option_ip(OPTION_SERVER_ID) is not None
                else None
            ),
            yiaddr=str(parsed.yiaddr) if parsed is not None else None,
            router=router,
            verdict=verdict,
            reason=reason,
            packet_hex=data.hex(),
            parse_error=parse_error,
        )


class _ProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager: ProbeManager, ctx: _RoundCtx) -> None:
        self.manager = manager
        self.ctx = ctx

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self.manager.handle_datagram(self.ctx, data, addr)
        except Exception:  # pragma: no cover - listener must survive
            log.exception("probe round %s: failed to handle datagram", self.ctx.round_id)

    def error_received(self, exc: Exception) -> None:
        log.warning("probe round %s: UDP error %s", self.ctx.round_id, exc)
