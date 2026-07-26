"""Bounded command and forwarder service lifecycle helpers."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping, Sequence

from ci.pkthere_ci.command_runner import (
    CommandRunner,
)
from ci.pkthere_ci.test_discovery import (
    listed_rust_tests,
    require_exactly_one_listed_rust_test,
    require_nonempty_rust_tests,
)
from ci.pkthere_ci.timing import (
    EVENT_POLL_SECONDS,
    TOPOLOGY_EVENT_TIMEOUT_SECONDS,
)

from .config import LOG_DIR, PKTHERE

RUNNER = CommandRunner()
FORWARDER_DEBUG_LOGS = ("drops", "handles", "handshake")


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


def require_rust_test(
    executable: str,
    test_name: str,
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
) -> None:
    listing = rust_test_listing(
        executable,
        timeout_seconds=timeout_seconds,
        env=env,
    )
    try:
        require_exactly_one_listed_rust_test(listing, test_name)
    except RuntimeError as error:
        raise RuntimeError(
            f"staged Rust test executable {executable} does not contain "
            f"the required exact test {test_name}"
        ) from error


def require_rust_tests(
    executable: str,
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
) -> None:
    discovered = rust_test_inventory(
        executable,
        timeout_seconds=timeout_seconds,
        env=env,
    )
    require_nonempty_rust_tests(
        discovered,
        f"staged Rust test executable {executable}",
    )


def rust_test_inventory(
    executable: str,
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
) -> frozenset[str]:
    return listed_rust_tests(
        rust_test_listing(executable, timeout_seconds=timeout_seconds, env=env)
    )


def rust_test_listing(
    executable: str,
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
) -> str:
    result = RUNNER.run(
        [executable, "--list"],
        timeout_seconds=timeout_seconds,
        env=env,
        capture_output=True,
    )
    return result.stdout


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
        *(
            argument
            for category in FORWARDER_DEBUG_LOGS
            for argument in ("--debug-log", category)
        ),
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
