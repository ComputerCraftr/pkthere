"""Container command dispatch."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from .injection import attacker
from .reality import reality
from .topology import (
    blackhole,
    driver,
    node_a,
    node_b,
    timeout_driver,
    timeout_node,
    udp_echo,
)


def main() -> None:
    commands: dict[str, Callable[[], None]] = {
        "attacker": attacker,
        "blackhole": blackhole,
        "driver": driver,
        "echo": udp_echo,
        "node-a": node_a,
        "node-b": node_b,
        "reality": reality,
        "timeout-driver": timeout_driver,
        "timeout-node": timeout_node,
    }
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=tuple(commands))
    args = parser.parse_args()
    commands[args.command]()
