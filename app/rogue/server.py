"""Rogue DHCPv4 responder used by the docker-compose drill.

This is *not* part of the lab DHCP service. It is a deliberately simple
unauthorised endpoint that answers DHCPDISCOVER with an OFFER pointing devices
at a strange gateway, so the web console's directed probe has a real rogue to
find. Configuration is environment-only:

ROGUE_UDP_HOST / ROGUE_UDP_PORT  bind address (default 0.0.0.0:6768)
ROGUE_SERVER_ID                  Server Identifier option 54 (default 198.51.100.2)
ROGUE_OFFER_IP                   yiaddr handed out (default 198.51.100.230)
ROGUE_ROUTER                     option 3, the "strange gateway" (default 198.51.100.1)
ROGUE_DNS                        option 6 (default equal to the router)
ROGUE_SUBNET_MASK                option 1 (default 255.255.255.0)
ROGUE_LEASE_TIME                 option 51 seconds (default 60)
ROGUE_DELAY_SECONDS              wait this long before answering. Values larger
                                 than the probe window demonstrate that late
                                 replies never leak into a later round.
ROGUE_REPLY_BAD_XID              set to "1" to answer with a wrong xid,
                                 demonstrating the identity guard.

Only DHCPDISCOVER is answered; no REQUEST handling exists, so this responder
can never confirm a lease.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct

from app.dhcp.packet import (
    BOOTREPLY,
    DHCPOFFER,
    OPTION_DNS,
    OPTION_LEASE_TIME,
    OPTION_MESSAGE_TYPE,
    OPTION_ROUTER,
    OPTION_SERVER_ID,
    OPTION_SUBNET_MASK,
    DhcpPacket,
    PacketError,
    build_packet,
    parse_packet,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s rogue-dhcp: %(message)s",
)
log = logging.getLogger("rogue")


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


class RogueProtocol(asyncio.DatagramProtocol):
    def __init__(self, config: dict[str, object]) -> None:
        self.config = config
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            packet = parse_packet(data)
        except PacketError as exc:
            log.info("ignoring malformed datagram from %s: %s", addr, exc)
            return
        if packet.message_type != 1:  # DHCPDISCOVER
            log.info(
                "ignoring non-DISCOVER (%s) from %s; rogue never confirms leases",
                packet.message_type, addr,
            )
            return
        delay = float(self.config["delay"])  # type: ignore[arg-type]
        if delay > 0:
            loop = asyncio.get_running_loop()
            loop.call_later(delay, self._answer, packet, addr)
            log.info(
                "DISCOVER xid=0x%08x from %s queued, answering in %.2fs",
                packet.xid, addr, delay,
            )
        else:
            self._answer(packet, addr)

    def _answer(self, request: DhcpPacket, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return
        cfg = self.config
        bad_xid = bool(cfg["bad_xid"])
        xid = (request.xid + 1) & 0xFFFFFFFF if bad_xid else request.xid
        options = {
            OPTION_MESSAGE_TYPE: bytes((DHCPOFFER,)),
            OPTION_SERVER_ID: ipaddress.IPv4Address(str(cfg["server_id"])).packed,
            OPTION_ROUTER: ipaddress.IPv4Address(str(cfg["router"])).packed,
            OPTION_DNS: ipaddress.IPv4Address(str(cfg["dns"])).packed,
            OPTION_SUBNET_MASK: ipaddress.IPv4Address(str(cfg["subnet_mask"])).packed,
            OPTION_LEASE_TIME: struct.pack("!I", int(cfg["lease_time"])),
        }
        reply = build_packet(
            op=BOOTREPLY,
            xid=xid,
            chaddr=request.chaddr,
            htype=request.htype,
            hlen=request.hlen,
            message_type=DHCPOFFER,
            yiaddr=ipaddress.IPv4Address(str(cfg["offer_ip"])),
            giaddr=request.giaddr,
            flags=request.flags,
            options=options,
        )
        self.transport.sendto(reply, addr)
        log.info(
            "OFFER xid=0x%08x%s -> %s: yiaddr=%s router=%s server-id=%s",
            xid, " (spoofed xid)" if bad_xid else "", addr,
            cfg["offer_ip"], cfg["router"], cfg["server_id"],
        )

    def error_received(self, exc: Exception) -> None:
        log.warning("UDP error: %s", exc)


def load_config() -> dict[str, object]:
    return {
        "host": _env("ROGUE_UDP_HOST", "0.0.0.0"),
        "port": int(_env("ROGUE_UDP_PORT", "6768")),
        "server_id": _env("ROGUE_SERVER_ID", "198.51.100.2"),
        "offer_ip": _env("ROGUE_OFFER_IP", "198.51.100.230"),
        "router": _env("ROGUE_ROUTER", "198.51.100.1"),
        "dns": _env("ROGUE_DNS", "198.51.100.1"),
        "subnet_mask": _env("ROGUE_SUBNET_MASK", "255.255.255.0"),
        "lease_time": int(_env("ROGUE_LEASE_TIME", "60")),
        "delay": float(_env("ROGUE_DELAY_SECONDS", "0")),
        "bad_xid": _env("ROGUE_REPLY_BAD_XID", "0") in ("1", "true", "yes", "on"),
    }


async def amain() -> None:
    config = load_config()
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: RogueProtocol(config),
        local_addr=(str(config["host"]), int(config["port"])),
    )
    log.info(
        "rogue DHCP listening on udp/%s; server-id=%s router=%s offer=%s delay=%.2fs",
        config["port"], config["server_id"], config["router"],
        config["offer_ip"], float(config["delay"]),  # type: ignore[arg-type]
    )
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
