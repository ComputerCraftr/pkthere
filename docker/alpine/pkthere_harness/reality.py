"""Privileged local socket-reality profile."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
import shutil
import time

from .config import (
    ICMP_INTEGRATION_TEST,
    PKTHERE,
    PKTHERE_TEST_SUPPORT_TEST,
    SOCKET_REALITY_TEST,
    TEST_APP,
    WORKER_MODES_TEST,
)
from .processes import run
from .test_manifest import (
    RAW_SOCKET_REALITY_TEST,
    privileged_icmp_tests_for_platform,
)
from .timing import (
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
    DOCKER_SUITE_TIMEOUT_SECONDS,
)


def run_reality_test(
    label: str,
    command: Sequence[str],
    timeout_seconds: float,
    environment: Mapping[str, str],
) -> None:
    started = time.monotonic()
    print(f"=== Alpine reality start: {label} ===", flush=True)
    try:
        run(command, timeout_seconds=timeout_seconds, env=environment)
    except Exception:
        elapsed = time.monotonic() - started
        print(
            f"=== Alpine reality failed: {label} after {elapsed:.3f}s ===",
            flush=True,
        )
        raise
    elapsed = time.monotonic() - started
    print(f"=== Alpine reality passed: {label} in {elapsed:.3f}s ===", flush=True)


def reality() -> None:
    shutil.copy2(PKTHERE, TEST_APP)
    run(
        ["setcap", "cap_net_raw+ep", TEST_APP],
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
    )
    run(
        ["setcap", "cap_net_raw+ep", SOCKET_REALITY_TEST],
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
    )

    environment = os.environ.copy()
    environment["TEST_APP_BIN"] = TEST_APP
    run_reality_test(
        "native socket-reality suite",
        ["su-exec", "pkthere", SOCKET_REALITY_TEST, "--nocapture"],
        DOCKER_SUITE_TIMEOUT_SECONDS,
        environment,
    )
    run_reality_test(
        RAW_SOCKET_REALITY_TEST.test_name,
        [
            "su-exec",
            "pkthere",
            *RAW_SOCKET_REALITY_TEST.executable_arguments(SOCKET_REALITY_TEST),
        ],
        DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
        environment,
    )
    run_reality_test(
        "worker-mode suite",
        ["su-exec", "pkthere", WORKER_MODES_TEST, "--nocapture"],
        DOCKER_SUITE_TIMEOUT_SECONDS,
        environment,
    )
    run_reality_test(
        "non-privileged ICMP integration suite",
        ["su-exec", "pkthere", ICMP_INTEGRATION_TEST, "--nocapture"],
        DOCKER_SUITE_TIMEOUT_SECONDS,
        environment,
    )
    executables = {
        "icmp-integration-test": ICMP_INTEGRATION_TEST,
        "pkthere-test-support-test": PKTHERE_TEST_SUPPORT_TEST,
    }
    for selection in privileged_icmp_tests_for_platform("linux"):
        run_reality_test(
            selection.test_name,
            [
                "su-exec",
                "pkthere",
                *selection.executable_arguments(
                    executables[selection.staged_executable]
                ),
            ],
            DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
            environment,
        )
