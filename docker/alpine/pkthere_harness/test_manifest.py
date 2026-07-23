"""Authoritative native and privileged test selections for every platform runner."""

from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class CargoTestSelection:
    package: str
    target_flag: str
    target_name: str | None
    test_name: str
    staged_executable: str
    platforms: frozenset[str]
    ignored: bool

    def harness_arguments(self) -> tuple[str, ...]:
        arguments = [self.test_name, "--exact"]
        if self.ignored:
            arguments.append("--ignored")
        arguments.append("--nocapture")
        return tuple(arguments)

    def cargo_arguments(self) -> tuple[str, ...]:
        target = (
            (self.target_flag, self.target_name)
            if self.target_name is not None
            else (self.target_flag,)
        )
        return (
            "cargo",
            "test",
            "--locked",
            "-p",
            self.package,
            *target,
            "--",
            *self.harness_arguments(),
        )

    def executable_arguments(self, executable: str) -> tuple[str, ...]:
        return (executable, *self.harness_arguments())


PRIVILEGED_ICMP_TESTS = (
    CargoTestSelection(
        package="pkthere",
        target_flag="--test",
        target_name="icmp_integration",
        test_name=(
            "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node"
        ),
        staged_executable="icmp-integration-test",
        platforms=frozenset({"linux", "android"}),
        ignored=True,
    ),
    CargoTestSelection(
        package="pkthere",
        target_flag="--test",
        target_name="icmp_integration",
        test_name="raw_icmp_locked_flow_rejects_wrong_source_id",
        staged_executable="icmp-integration-test",
        platforms=frozenset({"linux", "android", "windows", "freebsd"}),
        ignored=True,
    ),
    CargoTestSelection(
        package="pkthere",
        target_flag="--test",
        target_name="icmp_integration",
        test_name="test_raw_icmp_independent_ids",
        staged_executable="icmp-integration-test",
        platforms=frozenset({"linux", "android", "windows", "freebsd"}),
        ignored=True,
    ),
    CargoTestSelection(
        package="pkthere-test-support",
        target_flag="--lib",
        target_name=None,
        test_name=(
            "icmp_wildcard_cases::raw_icmp_wildcard_upstream_locks_on_localhost"
        ),
        staged_executable="pkthere-test-support-test",
        platforms=frozenset({"linux", "android", "windows", "freebsd"}),
        ignored=True,
    ),
)

RAW_SOCKET_REALITY_TEST = CargoTestSelection(
    package="pkthere",
    target_flag="--test",
    target_name="socket_reality",
    test_name="raw_icmp_forwarder_packet_dump_matches_policy",
    staged_executable="socket-reality-test",
    platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
    ignored=True,
)

ALPINE_CONCURRENCY_TESTS = (
    CargoTestSelection(
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "net::managed_socket::receive_tests::"
            "multi_worker_receive_boundary_covers_zero_capacity_reuse_and_mixed_syscalls"
        ),
        staged_executable="pkthere-unit-test",
        platforms=frozenset({"linux"}),
        ignored=False,
    ),
    CargoTestSelection(
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "net::managed_socket::concurrency_tests::"
            "concurrent_destination_required_fallback_publishes_one_association_transition"
        ),
        staged_executable="pkthere-unit-test",
        platforms=frozenset({"linux"}),
        ignored=False,
    ),
    CargoTestSelection(
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "worker_support::client_lock::tests::"
            "shared_flow_concurrent_rollback_failure_blocks_competitors_"
            "and_requests_fatal_exit"
        ),
        staged_executable="pkthere-unit-test",
        platforms=frozenset({"linux"}),
        ignored=False,
    ),
)


def native_platform_name(sys_platform: str = sys.platform) -> str:
    if sys_platform.startswith("linux"):
        return "linux"
    if sys_platform in {"win32", "cygwin"}:
        return "windows"
    if sys_platform == "darwin":
        return "macos"
    if sys_platform.startswith("freebsd"):
        return "freebsd"
    return sys_platform


def privileged_icmp_tests_for_platform(
    platform: str,
) -> tuple[CargoTestSelection, ...]:
    normalized = platform.lower()
    return tuple(
        selection
        for selection in PRIVILEGED_ICMP_TESTS
        if normalized in selection.platforms
    )


def alpine_concurrency_tests_for_platform(
    platform: str,
) -> tuple[CargoTestSelection, ...]:
    normalized = platform.lower()
    return tuple(
        selection
        for selection in ALPINE_CONCURRENCY_TESTS
        if normalized in selection.platforms
    )
