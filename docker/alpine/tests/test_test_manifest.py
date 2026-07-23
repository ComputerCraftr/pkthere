from __future__ import annotations

import unittest

from docker.alpine.pkthere_harness.test_manifest import (
    ALPINE_CONCURRENCY_TESTS,
    PRIVILEGED_ICMP_TESTS,
    RAW_SOCKET_REALITY_TEST,
    alpine_concurrency_tests_for_platform,
    native_platform_name,
    privileged_icmp_tests_for_platform,
)


class TestManifestTests(unittest.TestCase):
    def test_privileged_manifest_is_unique_and_complete(self) -> None:
        expected = {
            "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node",
            "raw_icmp_locked_flow_rejects_wrong_source_id",
            "test_raw_icmp_independent_ids",
            "icmp_wildcard_cases::raw_icmp_wildcard_upstream_locks_on_localhost",
        }
        actual = {selection.test_name for selection in PRIVILEGED_ICMP_TESTS}
        self.assertEqual(actual, expected)
        self.assertEqual(len(PRIVILEGED_ICMP_TESTS), len(actual))

    def test_every_privileged_cargo_invocation_is_locked_exact_and_ignored(
        self,
    ) -> None:
        for selection in (*PRIVILEGED_ICMP_TESTS, RAW_SOCKET_REALITY_TEST):
            arguments = selection.cargo_arguments()
            self.assertIn("--locked", arguments)
            self.assertEqual(arguments[-3:], ("--exact", "--ignored", "--nocapture"))
            self.assertEqual(arguments.count(selection.test_name), 1)

    def test_alpine_concurrency_manifest_is_exact_nonignored_and_complete(self) -> None:
        expected_suffixes = {
            "multi_worker_receive_boundary_covers_zero_capacity_reuse_and_mixed_syscalls",
            "concurrent_destination_required_fallback_publishes_one_association_transition",
            (
                "shared_flow_concurrent_rollback_failure_blocks_competitors_"
                "and_requests_fatal_exit"
            ),
        }
        self.assertEqual(
            {
                selection.test_name.rsplit("::", maxsplit=1)[-1]
                for selection in ALPINE_CONCURRENCY_TESTS
            },
            expected_suffixes,
        )
        for selection in ALPINE_CONCURRENCY_TESTS:
            self.assertFalse(selection.ignored)
            self.assertEqual(
                selection.harness_arguments()[-2:],
                ("--exact", "--nocapture"),
            )
            self.assertEqual(selection.staged_executable, "pkthere-unit-test")
        self.assertEqual(
            alpine_concurrency_tests_for_platform("linux"),
            ALPINE_CONCURRENCY_TESTS,
        )
        self.assertEqual(alpine_concurrency_tests_for_platform("macos"), ())

    def test_staged_manifest_names_match_container_artifact_contract(self) -> None:
        self.assertEqual(
            {selection.staged_executable for selection in PRIVILEGED_ICMP_TESTS},
            {"icmp-integration-test", "pkthere-test-support-test"},
        )
        self.assertEqual(
            RAW_SOCKET_REALITY_TEST.staged_executable,
            "socket-reality-test",
        )

    def test_platform_ownership_excludes_unsupported_privileged_topologies(
        self,
    ) -> None:
        all_tests = {selection.test_name for selection in PRIVILEGED_ICMP_TESTS}
        linux = {
            selection.test_name
            for selection in privileged_icmp_tests_for_platform("linux")
        }
        windows = {
            selection.test_name
            for selection in privileged_icmp_tests_for_platform("windows")
        }
        multihop = "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node"
        self.assertEqual(linux, all_tests)
        self.assertNotIn(multihop, windows)
        self.assertEqual(windows, linux - {multihop})
        self.assertEqual(privileged_icmp_tests_for_platform("macos"), ())

    def test_native_platform_names_match_ci_runners(self) -> None:
        self.assertEqual(native_platform_name("linux"), "linux")
        self.assertEqual(native_platform_name("win32"), "windows")
        self.assertEqual(native_platform_name("darwin"), "macos")
        self.assertEqual(native_platform_name("freebsd14"), "freebsd")


if __name__ == "__main__":
    unittest.main()
