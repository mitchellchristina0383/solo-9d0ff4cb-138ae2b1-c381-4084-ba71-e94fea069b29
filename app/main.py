"""FastAPI app: web UI, lease/event API, and a real-UDP test console."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .config import Settings
from .dhcp.packet import (
    DHCPDISCOVER,
    DHCPRELEASE,
    DHCPREQUEST,
    OPTION_CLIENT_ID,
    OPTION_HOSTNAME,
    OPTION_REQUESTED_IP,
    OPTION_SERVER_ID,
    PacketError,
    build_packet,
    parse_packet,
)
from .dhcp.probe import ProbeManager
from .dhcp.server import DhcpService, UdpDhcpServer
from .dhcp.store import LeaseStore

log = logging.getLogger("dhcp.web")


class _Notifier:
    """Wakes long-polling web clients after any lease change."""

    def __init__(self) -> None:
        self._version = 0
        self._changed = asyncio.Event()

    @property
    def version(self) -> int:
        return self._version

    def bump(self) -> None:
        self._version += 1
        self._changed.set()

    async def wait(self, after: int, timeout: float = 20.0) -> int:
        if self._version != after:
            return self._version
        try:
            await asyncio.wait_for(self._changed.wait(), timeout)
        except asyncio.TimeoutError:
            pass
        self._changed.clear()
        return self._version


class SimRequest(BaseModel):
    """Build and send a real DHCP datagram from the web UI."""

    kind: Literal["DISCOVER", "REQUEST", "RELEASE"]
    mac: str = Field(default="02:00:00:00:00:01", min_length=11, max_length=17)
    hostname: str | None = Field(default=None, max_length=63)
    requested_ip: str | None = None
    ciaddr: str | None = None
    server_id: str | None = None
    use_client_id: bool = True
    xid: int | None = Field(default=None, ge=1, le=0xFFFFFFFF)
    target: Literal["loopback", "custom"] = "loopback"
    target_host: str | None = Field(default=None, max_length=255)
    target_port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str) -> str:
        parts = value.replace("-", ":").split(":")
        if len(parts) != 6 or any(
            len(part) != 2 or any(c not in "0123456789abcdefABCDEF" for c in part)
            for part in parts
        ):
            raise ValueError("MAC must be six hex octets, e.g. 02:00:00:00:00:01")
        return ":".join(part.lower() for part in parts)


class SimResponse(BaseModel):
    sent_hex: str
    target: str
    reply: dict | None
    reply_hex: str | None
    action: str | None
    note: str


class EndpointBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    trusted: bool = False
    expected_server_id: str | None = None
    note: str | None = Field(default=None, max_length=255)

    @field_validator("expected_server_id")
    @classmethod
    def _server_id(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ValueError as exc:
            raise ValueError(f"expected_server_id is not IPv4: {value}") from exc


class ProbeStartBody(BaseModel):
    endpoint_ids: list[int] = Field(min_length=1, max_length=32)


def _parse_ip(value: str | None, field: str):
    if not value:
        return None
    try:
        return ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{field} is not IPv4: {value}") from exc


def _seed_endpoints(settings: Settings, store: LeaseStore) -> None:
    """Register the trust list declared via DHCP_PROBE_SEED_ENDPOINTS once."""
    if not settings.probe_seed_endpoints.strip():
        return
    existing = {row["name"] for row in store.list_endpoints()}
    # Format: name|host|port|trusted(0/1)|server-id(optional);...
    for chunk in settings.probe_seed_endpoints.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = [part.strip() for part in chunk.split("|")]
        if len(parts) < 4:
            log.warning("ignoring malformed probe seed entry: %r", chunk)
            continue
        name, host, port_raw, trusted_raw = parts[:4]
        server_id = parts[4] if len(parts) > 4 and parts[4] else None
        if name in existing:
            continue
        try:
            port = int(port_raw)
            trusted = trusted_raw in ("1", "true", "yes", "on")
            if not 1 <= port <= 65535:
                raise ValueError("port out of range")
            if server_id:
                ipaddress.IPv4Address(server_id)
        except ValueError:
            log.warning("ignoring malformed probe seed entry: %r", chunk)
            continue
        try:
            store.create_endpoint(
                name=name, host=host, port=port, trusted=trusted,
                expected_server_id=server_id, note="compose 种子登记",
            )
        except ValueError:
            continue


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    state: dict[str, object] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        store = LeaseStore(settings)
        service = DhcpService(settings, store)
        notifier = _Notifier()
        udp = UdpDhcpServer(service, on_change=notifier.bump)
        probes = ProbeManager(settings, store)
        try:
            await udp.start()
        except OSError:
            store.close()
            raise
        _seed_endpoints(settings, store)
        state.update(
            settings=settings, store=store, service=service, udp=udp,
            notifier=notifier, probes=probes,
        )
        log.info(
            "DHCP lab listening on udp/%s, pool %s-%s, web on http://0.0.0.0:8080",
            udp.port,
            settings.pool_start,
            settings.pool_end,
        )
        try:
            yield
        finally:
            await probes.shutdown()
            udp.close()
            store.close()

    app = FastAPI(title="Isolated-lab DHCPv4", version="1.0", lifespan=lifespan)

    def deps():
        if "store" not in state:
            raise HTTPException(status_code=503, detail="server is starting")
        return state["settings"], state["store"], state["service"], state["notifier"]

    @app.get("/api/health")
    async def health():
        _settings, store, _service, _notifier = deps()
        udp_server: UdpDhcpServer = state["udp"]  # type: ignore[assignment]
        return {
            "ok": True,
            "udp_port": udp_server.port,
            "udp_received": udp_server.received,
            "udp_replied": udp_server.replied,
            "udp_dropped": udp_server.dropped,
            "pool_size": store.settings.pool_size,
            "db_path": store.db_path,
        }

    @app.get("/api/state")
    async def get_state():
        settings_obj, store, _service, notifier = deps()
        udp_server: UdpDhcpServer = state["udp"]  # type: ignore[assignment]
        return {
            "config": {
                "pool_start": str(settings_obj.pool_start),
                "pool_end": str(settings_obj.pool_end),
                "subnet_mask": str(settings_obj.subnet_mask),
                "router": str(settings_obj.router),
                "dns": [str(addr) for addr in settings_obj.dns_servers],
                "server_id": str(settings_obj.server_identifier),
                "broadcast": str(settings_obj.broadcast),
                "lease_time": settings_obj.lease_time,
                "offer_ttl": settings_obj.offer_ttl,
                "udp_port": udp_server.port,
                "relay_port": settings_obj.relay_port,
                "failure_injection": settings_obj.allow_failure_injection,
            },
            "pool": [str(ip) for ip in settings_obj.pool_ips()],
            "stats": store.stats(),
            "leases": store.list_leases(),
            "events": store.list_events(60),
            "sim_target": {
                "host": settings_obj.sim_target_host,
                "port": settings_obj.sim_target_port,
            },
            "probe": {
                "timeout": settings_obj.probe_timeout,
                "mac_oui": settings_obj.probe_mac_oui,
                "endpoints": store.list_endpoints(),
                "rounds": store.list_probe_rounds(10),
            },
            "version": notifier.version,
        }

    @app.get("/api/state/wait")
    async def wait_state(after: int = Query(default=0, ge=0)):
        _settings, _store, _service, notifier = deps()
        await notifier.wait(after)
        return {"version": notifier.version}

    @app.get("/api/leases")
    async def leases():
        _settings, store, _service, _notifier = deps()
        return {"leases": store.list_leases(), "stats": store.stats()}

    @app.get("/api/events")
    async def events(limit: int = Query(default=100, ge=1, le=500)):
        _settings, store, _service, _notifier = deps()
        return {"events": store.list_events(limit)}

    @app.post("/api/drill/inject-commit-failure")
    async def inject_commit_failure(count: int = Query(default=1, ge=1, le=10)):
        settings_obj, store, _service, _notifier = deps()
        if not settings_obj.allow_failure_injection:
            raise HTTPException(
                status_code=403,
                detail="failure injection disabled; start with "
                "DHCP_ALLOW_FAILURE_INJECTION=1 to enable this drill",
            )
        store.inject_next_commit_failure(count)
        return {"injected": count}

    @app.post("/api/simulate", response_model=SimResponse)
    async def simulate(body: SimRequest):
        settings_obj, store, _service, notifier = deps()
        udp_server: UdpDhcpServer = state["udp"]  # type: ignore[assignment]

        mac_bytes = bytes.fromhex(body.mac.replace(":", ""))
        requested = _parse_ip(body.requested_ip, "requested_ip")
        ciaddr = _parse_ip(body.ciaddr, "ciaddr") or ipaddress.IPv4Address("0.0.0.0")
        server_id = _parse_ip(body.server_id, "server_id")
        xid = body.xid or store.new_xid()

        options: dict[int, bytes] = {}
        if body.use_client_id:
            options[OPTION_CLIENT_ID] = b"\x01" + mac_bytes
        if body.hostname:
            options[OPTION_HOSTNAME] = body.hostname.encode("utf-8")
        if requested is not None:
            options[OPTION_REQUESTED_IP] = requested.packed
        if server_id is not None:
            options[OPTION_SERVER_ID] = server_id.packed

        message_type = {
            "DISCOVER": DHCPDISCOVER,
            "REQUEST": DHCPREQUEST,
            "RELEASE": DHCPRELEASE,
        }[body.kind]
        packet = build_packet(
            op=1,
            xid=xid,
            chaddr=mac_bytes,
            message_type=message_type,
            ciaddr=ciaddr,
            flags=0x8000,
            options=options,
        )

        if body.target == "loopback":
            host = settings_obj.sim_target_host
            port = (
                udp_server.port
                if settings_obj.sim_target_port == 0
                else settings_obj.sim_target_port
            )
        else:
            if not body.target_host or not body.target_port:
                raise HTTPException(
                    status_code=422,
                    detail="custom target requires target_host and target_port",
                )
            host, port = body.target_host, body.target_port

        outcome = None
        reply_bytes: bytes | None = None
        note = ""
        loop = asyncio.get_running_loop()

        class _Once(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.future: asyncio.Future = loop.create_future()

            def datagram_received(self, data: bytes, addr) -> None:
                if not self.future.done():
                    self.future.set_result((data, addr))

            def error_received(self, exc: Exception) -> None:
                if not self.future.done():
                    self.future.set_exception(exc)

        try:
            transport, proto = await loop.create_datagram_endpoint(
                _Once, remote_addr=(host, port)
            )
        except OSError as exc:
            raise HTTPException(
                status_code=502, detail=f"cannot open UDP socket to {host}:{port}: {exc}"
            ) from exc
        try:
            transport.sendto(packet)
            try:
                reply_bytes, _addr = await asyncio.wait_for(
                    proto.future, timeout=settings_obj.sim_timeout  # type: ignore[attr-defined]
                )
                try:
                    reply_packet = parse_packet(reply_bytes)
                    outcome = reply_packet.summary()
                except PacketError as exc:
                    outcome = {"error": str(exc), "hex": reply_bytes.hex()}
                note = "收到真实 UDP 响应"
            except asyncio.TimeoutError:
                note = (
                    f"{settings_obj.sim_timeout:g}s 内没有收到报文（服务器可能按策略静默）"
                )
        finally:
            transport.close()

        # Even a silent exchange may have changed state (RELEASE, NAK, expiry
        # purge), so always wake the UI.
        if body.target == "loopback":
            notifier.bump()
        await asyncio.sleep(0)
        return SimResponse(
            sent_hex=packet.hex(),
            target=f"{host}:{port}",
            reply=outcome,
            reply_hex=reply_bytes.hex() if reply_bytes else None,
            action=(outcome or {}).get("message_type_name") if outcome else None,
            note=note,
        )

    # -- directed rogue-DHCP probe ----------------------------------------

    def _get_probe_manager() -> ProbeManager:
        if "probes" not in state:
            raise HTTPException(status_code=503, detail="server is starting")
        return state["probes"]  # type: ignore[return-value]

    @app.get("/api/probe/endpoints")
    async def probe_list_endpoints():
        _settings, store, _service, _notifier = deps()
        return {"endpoints": store.list_endpoints()}

    @app.post("/api/probe/endpoints", status_code=201)
    async def probe_create_endpoint(body: EndpointBody):
        _settings, store, _service, _notifier = deps()
        try:
            endpoint = store.create_endpoint(
                name=body.name,
                host=body.host,
                port=body.port,
                trusted=body.trusted,
                expected_server_id=body.expected_server_id,
                note=body.note,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return endpoint

    @app.put("/api/probe/endpoints/{endpoint_id}")
    async def probe_update_endpoint(endpoint_id: int, body: EndpointBody):
        _settings, store, _service, _notifier = deps()
        try:
            return store.update_endpoint(
                endpoint_id,
                name=body.name,
                host=body.host,
                port=body.port,
                trusted=body.trusted,
                expected_server_id=body.expected_server_id,
                note=body.note,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="endpoint not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.delete("/api/probe/endpoints/{endpoint_id}", status_code=204)
    async def probe_delete_endpoint(endpoint_id: int):
        _settings, store, _service, _notifier = deps()
        try:
            store.delete_endpoint(endpoint_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="endpoint not found") from exc
        return JSONResponse(status_code=204, content=None)

    @app.post("/api/probe/rounds", status_code=201)
    async def probe_start_round(body: ProbeStartBody):
        _settings, store, _service, notifier = deps()
        manager = _get_probe_manager()
        endpoints: list[dict] = []
        peers: set[tuple[str, int]] = set()
        for endpoint_id in dict.fromkeys(body.endpoint_ids):  # de-duplicate, keep order
            endpoint = store.get_endpoint(endpoint_id)
            if endpoint is None:
                raise HTTPException(
                    status_code=404, detail=f"endpoint {endpoint_id} not registered"
                )
            peer = (str(endpoint["host"]), int(endpoint["port"]))
            if peer in peers:
                raise HTTPException(
                    status_code=422,
                    detail=f"duplicate endpoint peer {peer[0]}:{peer[1]} in one round; "
                    "a reply can only be attributed to one target",
                )
            peers.add(peer)
            endpoints.append(endpoint)
        detail = await manager.start_round(endpoints)
        notifier.bump()
        return detail

    @app.get("/api/probe/rounds")
    async def probe_list_rounds(limit: int = Query(default=20, ge=1, le=100)):
        _settings, store, _service, _notifier = deps()
        return {"rounds": store.list_probe_rounds(limit)}

    @app.get("/api/probe/rounds/{round_id}")
    async def probe_get_round(round_id: int):
        _settings, store, _service, _notifier = deps()
        detail = store.get_probe_round_detail(round_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="probe round not found")
        return detail

    @app.post("/api/probe/rounds/{round_id}/cancel")
    async def probe_cancel_round(round_id: int):
        _settings, store, _service, notifier = deps()
        manager = _get_probe_manager()
        try:
            detail = await manager.cancel_round(round_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="probe round not found") from exc
        notifier.bump()
        return detail

    static_dir = settings.static_dir
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def index():
        index_file = static_dir / "index.html"
        if not index_file.is_file():
            return JSONResponse(
                {"detail": "web assets missing", "path": str(index_file)},
                status_code=500,
            )
        return FileResponse(index_file)

    return app


app = create_app()
