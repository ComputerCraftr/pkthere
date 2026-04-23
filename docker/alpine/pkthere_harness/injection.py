"""Malformed and wrong-peer ICMP injection profile."""

from __future__ import annotations

from .config import LOG_DIR, required, required_int
from .processes import wait_for


def attacker() -> None:
    from scapy.all import ICMP, IP, Raw, send  # type: ignore[import-not-found]

    wait_for(
        lambda: (LOG_DIR / "legitimate-flow-ready").exists(),
        "legitimate flow marker",
    )
    server = required("NODE_B_IP")
    expected_client = required("NODE_A_IP")
    destination_id = required_int("SERVER_DESTINATION_ID")
    reply_id = required_int("CLIENT_REPLY_ID")

    for seq, payload in enumerate(
        (bytes([0x01]), bytes([0x80]), bytes([0xD0]), bytes([0x50])),
        start=50,
    ):
        send(
            IP(src=expected_client, dst=server)
            / ICMP(type=8, code=0, id=destination_id, seq=seq)
            / Raw(load=payload),
            verbose=False,
        )

    send(
        IP(src=expected_client, dst=server)
        / ICMP(type=8, code=0, id=destination_id - 1, seq=41)
        / Raw(load=bytes([0x90]) + b"wrong-destination-id"),
        verbose=False,
    )
    send(
        IP(dst=server)
        / ICMP(type=8, code=0, id=destination_id, seq=42)
        / Raw(load=bytes([0x80, 0x9C, 0x40]) + b"wrong-source-ip"),
        verbose=False,
    )
    send(
        IP(src=server, dst=expected_client)
        / ICMP(type=0, code=0, id=reply_id, seq=60)
        / Raw(load=bytes([0x28, 0x1E, 0x61, 0x27, 0x0F])),
        verbose=False,
    )
    (LOG_DIR / "attacker-finished").touch()
