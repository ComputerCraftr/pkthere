"""Canonical test manifest tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ci.pkthere_ci.evidence_types import (
    PRIVILEGED_RAW_SOCKET_PLATFORMS,
    PRODUCTION_RAW_FORWARDING_PLATFORMS,
)
from ci.pkthere_ci.platform_selection import (
    NativePlatform,
    native_platform,
)
from ci.pkthere_ci.selection_arguments import CargoTestSelection
from ci.pkthere_ci.test_discovery import (
    listed_rust_tests,
    require_exactly_one_listed_rust_test,
    require_listed_rust_test,
    require_nonempty_rust_tests,
)
from ci.pkthere_ci.test_manifest import (
    ALL_RELEASE_TEST_SELECTIONS,
    ALPINE_CONCURRENCY_TESTS,
    CORE_AUTHORITY_TESTS,
    EVIDENCE_CONTRACTS,
    NATIVE_AUTHORITY_STRESS_TESTS,
    NEGATIVE_AUTHORITY_SMOKE_TESTS,
    PRIVILEGED_ICMP_TESTS,
    RAW_ICMP_TEST_ENVIRONMENT,
    RAW_SOCKET_REALITY_TEST,
    STRUCTURAL_AUTHORITY_TESTS,
    alpine_concurrency_tests_for_platform,
    authority_stress_tests_for_platform,
    privileged_icmp_tests_for_platform,
    validate_release_test_manifest,
)


class TestManifestTests(unittest.TestCase):
    def test_release_evidence_contracts_are_complete_and_unique(self) -> None:
        validate_release_test_manifest()
        self.assertEqual(
            {selection.evidence_id for selection in ALL_RELEASE_TEST_SELECTIONS},
            set(EVIDENCE_CONTRACTS),
        )
        for selection in ALL_RELEASE_TEST_SELECTIONS:
            self.assertTrue(selection.invariant_id)

    def test_core_authority_manifest_covers_required_invariant_classes(self) -> None:
        required_invariants = {
            "ATOMIC-PUB-001",
            "BARRIER-ICMP-001",
            "BARRIER-UDP-001",
            "FIFO-RESERVATION-001",
            "GROUP-PUBLICATION-001",
            "HOTPATH-ALLOC-001",
            "ICMP-OBS-BINDING-001",
            "IDLE-TRANSITION-CORE-001",
            "OBSERVATION-LIFECYCLE-001",
            "PAYLOAD-COPY-001",
            "RECEIVER-TRANSFER-001",
            "RECOVERY-SEND-CORE-001",
            "SEND-COMPLETION-CORE-001",
            "STALE-SEND-001",
            "STATS-FINALITY-001",
            "WAIT-REACQUIRE-001",
        }
        covered_invariants = {
            selection.invariant_id for selection in CORE_AUTHORITY_TESTS
        }
        self.assertLessEqual(required_invariants, covered_invariants)
        evidence_ids = [selection.evidence_id for selection in CORE_AUTHORITY_TESTS]
        test_names = [selection.test_name for selection in CORE_AUTHORITY_TESTS]
        self.assertEqual(len(evidence_ids), len(set(evidence_ids)))
        self.assertEqual(len(test_names), len(set(test_names)))
        self.assertEqual(
            {selection.staged_executable for selection in CORE_AUTHORITY_TESTS},
            {"pkthere-authority-audit-test"},
        )
        for selection in CORE_AUTHORITY_TESTS:
            self.assertEqual(selection.target_flag, "--bin")
            self.assertEqual(selection.target_name, "pkthere")
            self.assertFalse(selection.ignored)
            self.assertEqual(selection.evidence_class, "production-core")

    def test_negative_controls_are_exactly_allowlisted_and_not_positive_evidence(
        self,
    ) -> None:
        expected = {
            "atomic-publication-weakened-release",
            "lane-admission-weakened-store-scan",
            "send-completion-weakened-stranding",
            "stats-finality-weakened-order",
            "group-publication-weakened-split",
            "receiver-publication-weakened-split",
            "authority-order-negative-smoke",
            "authority-logging-reservation-negative-smoke",
        }
        self.assertEqual(
            {selection.evidence_id for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS},
            expected,
        )
        self.assertTrue(
            all(
                selection.evidence_class == "negative-control"
                and selection.staged_executable == "pkthere-authority-audit-test"
                and not selection.ignored
                for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS
            )
        )
        self.assertTrue(
            expected.isdisjoint(
                selection.evidence_id for selection in CORE_AUTHORITY_TESTS
            )
        )

    def test_evidence_binding_requires_the_exact_discovered_target_test(self) -> None:
        selection = RAW_SOCKET_REALITY_TEST
        executable = str(Path(tempfile.gettempdir()) / "socket-reality-test")
        binding = selection.bind_discovered_test(
            f"{selection.test_name}: test\n", executable
        )
        self.assertEqual(binding.evidence_id, selection.evidence_id)
        self.assertEqual(binding.invariant_id, selection.invariant_id)
        self.assertEqual(binding.test_name, selection.test_name)
        self.assertEqual(binding.executable, executable)
        for listing in (
            "",
            "renamed_test: test\n",
            f"{selection.test_name}: test\n{selection.test_name}: test\n",
        ):
            with self.assertRaisesRegex(RuntimeError, selection.test_name):
                selection.bind_discovered_test(listing, executable)

    def test_structural_authority_rows_execute_exact_policy_tests(self) -> None:
        self.assertEqual(
            {selection.evidence_id for selection in STRUCTURAL_AUTHORITY_TESTS},
            {
                "test-state-authority-policy",
                "interior-mutability-inventory-policy",
            },
        )
        for selection in STRUCTURAL_AUTHORITY_TESTS:
            self.assertEqual(selection.target_flag, "--test")
            self.assertEqual(selection.target_name, "policy")
            self.assertEqual(selection.evidence_class, "structural-policy")

    def test_unknown_or_misclassified_evidence_cannot_bind(self) -> None:
        original = RAW_SOCKET_REALITY_TEST
        executable = str(Path(tempfile.gettempdir()) / "socket-reality-test")
        unknown = CargoTestSelection(
            evidence_id="uncontracted",
            package=original.package,
            target_flag=original.target_flag,
            target_name=original.target_name,
            test_name=original.test_name,
            staged_executable=original.staged_executable,
            platforms=original.platforms,
            ignored=original.ignored,
            evidence_class=original.evidence_class,
        )
        with self.assertRaisesRegex(RuntimeError, "unknown release evidence ID"):
            unknown.bind_discovered_test(f"{unknown.test_name}: test\n", executable)
        wrong_class = CargoTestSelection(
            evidence_id=original.evidence_id,
            package=original.package,
            target_flag=original.target_flag,
            target_name=original.target_name,
            test_name=original.test_name,
            staged_executable=original.staged_executable,
            platforms=original.platforms,
            ignored=original.ignored,
            evidence_class="synthetic-boundary",
        )
        with self.assertRaisesRegex(RuntimeError, "evidence class mismatch"):
            wrong_class.bind_discovered_test(
                f"{wrong_class.test_name}: test\n", executable
            )

    def test_every_selection_has_a_release_evidence_class(self) -> None:
        allowed = {
            "negative-control",
            "production-core",
            "platform-reality",
            "structural-policy",
            "synthetic-boundary",
            "explanatory-model",
        }
        selections = ALL_RELEASE_TEST_SELECTIONS
        self.assertTrue(selections)
        for selection in selections:
            self.assertIn(selection.evidence_class, allowed)

    def test_low_level_receive_fixture_cannot_close_pipeline_rows(self) -> None:
        selection = next(
            selection
            for selection in ALPINE_CONCURRENCY_TESTS
            if selection.evidence_id == "alpine-receive-boundary"
        )
        self.assertEqual(selection.evidence_class, "synthetic-boundary")

    def test_raw_enablement_environment_has_one_manifest_authority(self) -> None:
        self.assertEqual(
            dict(RAW_ICMP_TEST_ENVIRONMENT),
            {"PKTHERE_ALLOW_RAW_ICMP": "1"},
        )

    def test_rust_test_discovery_fails_closed_for_zero_or_missing_selections(
        self,
    ) -> None:
        discovered = listed_rust_tests(
            "alpha::works: test\nignored chatter\nbeta::works: test\n"
        )
        self.assertEqual(discovered, {"alpha::works", "beta::works"})
        require_nonempty_rust_tests(discovered, "fixture executable")
        require_listed_rust_test(discovered, "alpha::works")
        with self.assertRaisesRegex(RuntimeError, "fixture executable"):
            require_nonempty_rust_tests(frozenset(), "fixture executable")
        with self.assertRaisesRegex(RuntimeError, "missing::test"):
            require_listed_rust_test(discovered, "missing::test")
        require_exactly_one_listed_rust_test("alpha::works: test\n", "alpha::works")
        for output in ("", "alpha::works: test\nalpha::works: test\n"):
            with self.assertRaisesRegex(RuntimeError, "alpha::works"):
                require_exactly_one_listed_rust_test(output, "alpha::works")

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
            "stress_multi_worker_distributed_udp_ipv4",
            "stress_multi_worker_distributed_icmp_ipv4",
            "multi_worker_receive_boundary_covers_zero_capacity_reuse_and_mixed_syscalls",
            "concurrent_destination_required_sends_return_stale_without_inline_transition",
            (
                "shared_flow_reader_blocks_until_all_managers_"
                "and_global_lock_are_published"
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
            if selection.staged_executable == "stress-test":
                self.assertTrue(selection.ignored)
                self.assertEqual(
                    selection.harness_arguments()[-3:],
                    ("--exact", "--ignored", "--nocapture"),
                )
            else:
                self.assertFalse(selection.ignored)
                self.assertEqual(selection.staged_executable, "pkthere-unit-test")
                self.assertEqual(
                    selection.harness_arguments()[-2:],
                    ("--exact", "--nocapture"),
                )
        stress_selections = {
            selection.evidence_id: selection.test_name
            for selection in ALPINE_CONCURRENCY_TESTS
            if selection.staged_executable == "stress-test"
        }
        self.assertEqual(
            stress_selections,
            {
                "alpine-multi-worker-udp-authority-stress": (
                    "stress_multi_worker_distributed_udp_ipv4"
                ),
                "alpine-multi-worker-icmp-authority-stress": (
                    "stress_multi_worker_distributed_icmp_ipv4"
                ),
            },
        )
        self.assertEqual(
            alpine_concurrency_tests_for_platform("linux"),
            ALPINE_CONCURRENCY_TESTS,
        )
        self.assertEqual(alpine_concurrency_tests_for_platform("macos"), ())

    def test_native_authority_stress_owns_non_linux_platforms(self) -> None:
        self.assertEqual(len(NATIVE_AUTHORITY_STRESS_TESTS), 1)
        selection = NATIVE_AUTHORITY_STRESS_TESTS[0]
        self.assertEqual(selection.test_name, "stress_test_ipv4")
        self.assertEqual(selection.platforms, {"macos", "windows", "freebsd"})
        linux_stress = tuple(
            selected
            for selected in ALPINE_CONCURRENCY_TESTS
            if selected.staged_executable == "stress-test"
        )
        self.assertEqual(authority_stress_tests_for_platform("linux"), linux_stress)
        for platform in selection.platforms:
            self.assertEqual(
                authority_stress_tests_for_platform(platform), (selection,)
            )

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
        self.assertEqual(
            PRIVILEGED_RAW_SOCKET_PLATFORMS,
            {"linux", "android", "macos", "windows", "freebsd"},
        )
        self.assertEqual(
            PRODUCTION_RAW_FORWARDING_PLATFORMS,
            {"linux", "android", "windows"},
        )
        all_tests = {selection.test_name for selection in PRIVILEGED_ICMP_TESTS}
        linux = {
            selection.test_name
            for selection in privileged_icmp_tests_for_platform("linux")
        }
        windows = {
            selection.test_name
            for selection in privileged_icmp_tests_for_platform("windows")
        }
        macos = {
            selection.test_name
            for selection in privileged_icmp_tests_for_platform("macos")
        }
        freebsd = {
            selection.test_name
            for selection in privileged_icmp_tests_for_platform("freebsd")
        }
        multihop = "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node"
        pure_raw = {
            "raw_icmp_locked_flow_rejects_wrong_source_id",
            "test_raw_icmp_independent_ids",
        }
        self.assertEqual(linux, all_tests)
        self.assertEqual(windows, linux - {multihop})
        self.assertEqual(freebsd, linux - {multihop, *pure_raw})
        self.assertEqual(macos, linux - {multihop, *pure_raw})
        self.assertEqual(
            RAW_SOCKET_REALITY_TEST.platforms,
            PRIVILEGED_RAW_SOCKET_PLATFORMS,
        )

    def test_native_platform_names_match_ci_runners(self) -> None:
        self.assertIs(native_platform("linux"), NativePlatform.LINUX)
        self.assertIs(native_platform("win32"), NativePlatform.WINDOWS)
        self.assertIs(native_platform("darwin"), NativePlatform.MACOS)
        self.assertIs(native_platform("freebsd14"), NativePlatform.FREEBSD)


if __name__ == "__main__":
    unittest.main()
