"""Typed environment configuration shared by Alpine services."""

from __future__ import annotations

import os
from pathlib import Path

LOG_DIR = Path("/logs")
PKTHERE = "/usr/local/libexec/pkthere/pkthere"
TEST_APP = "/usr/local/libexec/pkthere/pkthere-priv"
SOCKET_REALITY_TEST = "/usr/local/libexec/pkthere/socket-reality-test"
ICMP_INTEGRATION_TEST = "/usr/local/libexec/pkthere/icmp-integration-test"
TOPOLOGY_VERIFIER = "/usr/local/libexec/pkthere/topology-verifier"
WORKER_MODES_TEST = "/usr/local/libexec/pkthere/worker-modes-test"
PKTHERE_TEST_SUPPORT_TEST = "/usr/local/libexec/pkthere/pkthere-test-support-test"


def required(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise RuntimeError(f"missing required environment variable {name}")
    return value


def required_int(name: str) -> int:
    return int(required(name))
