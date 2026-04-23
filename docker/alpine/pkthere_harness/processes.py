"""Bounded command and forwarder service lifecycle helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import os
import time

from .command_runner import (
    CommandRunner,
)
from .config import LOG_DIR, PKTHERE
from .timing import (
    EVENT_POLL_SECONDS,
    TOPOLOGY_EVENT_TIMEOUT_SECONDS,
)

RUNNER = CommandRunner()


def run(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
) -> None:
    RUNNER.run(
        command,
        timeout_seconds=timeout_seconds,
        env=env,
    )


def wait_for(
    predicate: Callable[[], bool],
    description: str,
    timeout: float = TOPOLOGY_EVENT_TIMEOUT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(min(EVENT_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
    raise TimeoutError(f"timed out waiting for {description}")


def exec_forwarder(name: str, arguments: Sequence[str]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    argv = [
        PKTHERE,
        *arguments,
        "--debug-fast-stats",
        "--debug-log",
        "packet-dump",
        "--debug-log",
        "drops",
        "--debug-log",
        "handles",
        "--debug-log",
        "handshake",
        "--user",
        "pkthere",
        "--group",
        "pkthere",
    ]
    stdout_fd = os.open(
        LOG_DIR / f"{name}.out", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666
    )
    stderr_fd = os.open(
        LOG_DIR / f"{name}.err", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666
    )
    try:
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    os.execve(PKTHERE, argv, os.environ.copy())
