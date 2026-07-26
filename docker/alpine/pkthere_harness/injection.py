"""Malformed and wrong-peer ICMP injection profile."""

from __future__ import annotations

import importlib

from .config import LOG_DIR, required, required_int
from .processes import wait_for


def attacker() -> None:
    scapy = importlib.import_module("scapy.all")
    icmp = scapy.ICMP
    ip = scapy.IP
    raw = scapy.Raw
    send = scapy.send

    wait_for(
        lambda: (LOG_DIR / "legitimate-flow-ready").exists(),
        "legitimate flow marker",
    )
    server = required("NODE_B_IP")
    expected_client = required("NODE_A_IP")
    attacker_ip = required("ATTACKER_IP")
    destination_id = required_int("SERVER_DESTINATION_ID")
    reply_id = required_int("CLIENT_REPLY_ID")

    for seq, payload in enumerate(
        (
            bytes([0x01]),
            bytes([0x80]),
            bytes([0xD0]),
            bytes([0x50]),
            bytes([0x90]),
        ),
        start=50,
    ):
        send(
            ip(src=attacker_ip, dst=server)
            / icmp(type=8, code=0, id=destination_id, seq=seq)
            / raw(load=payload),
            verbose=False,
        )

    send(
        ip(src=attacker_ip, dst=server)
        / icmp(type=8, code=0, id=destination_id - 1, seq=41)
        / raw(load=bytes([0x90]) + b"wrong-destination-id"),
        verbose=False,
    )
    send(
        ip(dst=server)
        / icmp(type=8, code=0, id=destination_id, seq=42)
        / raw(load=bytes([0x80, 0x9C, 0x40]) + b"wrong-source-ip"),
        verbose=False,
    )
    send(
        ip(src=attacker_ip, dst=expected_client)
        / icmp(type=0, code=0, id=reply_id, seq=60)
        / raw(load=bytes([0x28, 0x1E, 0x61, 0x27, 0x0F])),
        verbose=False,
    )
    (LOG_DIR / "attacker-finished").touch()
