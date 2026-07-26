from __future__ import annotations

import io
import unittest
from collections.abc import Mapping, Sequence
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ci.pkthere_ci.command_runner import CommandResult
from ci.pkthere_ci.evidence_types import ArtifactIdentity
from ci.pkthere_ci.test_manifest import (
    RAW_ICMP_TEST_ENVIRONMENT,
    RAW_SOCKET_REALITY_TEST,
    UNPRIVILEGED_SOCKET_REALITY_TESTS,
    alpine_concurrency_tests_for_platform,
    privileged_icmp_tests_for_platform,
)
from ci.pkthere_ci.timing import (
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
    DOCKER_SUITE_TIMEOUT_SECONDS,
)
from docker.alpine.pkthere_harness import processes, reality
from docker.alpine.pkthere_harness.config import (
    PKTHERE,
    PKTHERE_AUTHORITY_AUDIT,
    SOCKET_REALITY_TEST,
)


class RealityCommandPolicyTests(unittest.TestCase):
    def test_suites_and_exact_tests_use_separate_bounded_deadlines(self) -> None:
        calls: list[tuple[tuple[str, ...], float]] = []
        environments: list[dict[str, str]] = []
        preflight_calls: list[tuple[str, float]] = []
        suite_inventory_calls: list[tuple[str, float]] = []

        def record_run(
            command: Sequence[str],
            *,
            timeout_seconds: float,
            env: Mapping[str, str] | None = None,
        ) -> None:
            calls.append((tuple(command), timeout_seconds))
            environments.append(dict(env or {}))

        def record_preflight(
            executable: str,
            *,
            timeout_seconds: float,
            env: Mapping[str, str] | None = None,
        ) -> str:
            del env
            preflight_calls.append((executable, timeout_seconds))
            selections = (
                *UNPRIVILEGED_SOCKET_REALITY_TESTS,
                RAW_SOCKET_REALITY_TEST,
                *alpine_concurrency_tests_for_platform("linux"),
                *privileged_icmp_tests_for_platform("linux"),
            )
            return "".join(f"{selection.test_name}: test\n" for selection in selections)

        def record_suite_inventory(
            executable: str,
            *,
            timeout_seconds: float,
            env: Mapping[str, str] | None = None,
        ) -> None:
            del env
            suite_inventory_calls.append((executable, timeout_seconds))

        def identity(path: str, *, privileged: bool = False) -> ArtifactIdentity:
            return ArtifactIdentity(
                path=Path(path),
                sha256="same-bytes",
                mode=0o755,
                uid=0,
                gid=0,
                privilege_metadata="cap_net_raw" if privileged else "",
            )

        identities = {
            PKTHERE: identity(PKTHERE),
            SOCKET_REALITY_TEST: identity(SOCKET_REALITY_TEST),
        }

        def record_identity(path: str) -> ArtifactIdentity:
            return identities[path]

        def prepare_copy(source: str, destination: str) -> ArtifactIdentity:
            del source
            return identity(destination, privileged=True)

        output = io.StringIO()
        with (
            patch.object(reality, "_artifact_identity", side_effect=record_identity),
            patch.object(reality, "_prepare_privileged_copy", side_effect=prepare_copy),
            patch.object(reality, "_destroy_privileged_copy"),
            patch.object(reality, "_record_privilege_evidence"),
            patch.object(reality, "run", side_effect=record_run),
            patch.object(reality, "audit_forwarder_lifecycle"),
            patch.object(
                reality,
                "require_rust_tests",
                side_effect=record_suite_inventory,
            ),
            patch.object(
                reality,
                "rust_test_listing",
                side_effect=record_preflight,
            ),
            redirect_stdout(output),
        ):
            reality.reality()

        self.assertEqual(len(suite_inventory_calls), 3)
        self.assertTrue(
            all(
                timeout == DOCKER_CONTROL_TIMEOUT_SECONDS
                for _, timeout in suite_inventory_calls
            )
        )
        test_calls = calls
        test_environments = environments
        unprivileged_count = len(UNPRIVILEGED_SOCKET_REALITY_TESTS)
        self.assertEqual(
            [timeout for _, timeout in test_calls[:unprivileged_count]],
            [DOCKER_SUITE_TIMEOUT_SECONDS] * unprivileged_count,
        )
        raw_index = unprivileged_count
        self.assertEqual(test_calls[raw_index][1], DOCKER_EXACT_TEST_TIMEOUT_SECONDS)
        privileged_tests = privileged_icmp_tests_for_platform("linux")
        privileged_end = raw_index + 1 + len(privileged_tests)
        self.assertEqual(
            [timeout for _, timeout in test_calls[raw_index:privileged_end]],
            [DOCKER_EXACT_TEST_TIMEOUT_SECONDS] * (1 + len(privileged_tests)),
        )
        self.assertEqual(
            [timeout for _, timeout in test_calls[privileged_end : privileged_end + 2]],
            [DOCKER_SUITE_TIMEOUT_SECONDS, DOCKER_SUITE_TIMEOUT_SECONDS],
        )
        concurrency_tests = alpine_concurrency_tests_for_platform("linux")
        concurrency_start = privileged_end + 2
        concurrency_end = concurrency_start + len(concurrency_tests)
        concurrency_environments = test_environments[concurrency_start:concurrency_end]
        self.assertEqual(
            [timeout for _, timeout in test_calls[concurrency_start:concurrency_end]],
            [
                (
                    DOCKER_SUITE_TIMEOUT_SECONDS
                    if selection.staged_executable == "stress-test"
                    else DOCKER_EXACT_TEST_TIMEOUT_SECONDS
                )
                for selection in concurrency_tests
            ],
        )
        for selection, environment in zip(
            concurrency_tests, concurrency_environments, strict=True
        ):
            if selection.staged_executable == "stress-test":
                self.assertEqual(
                    environment.get("TEST_APP_BIN"),
                    PKTHERE_AUTHORITY_AUDIT,
                )
        self.assertEqual(
            test_calls[concurrency_end][1],
            DOCKER_SUITE_TIMEOUT_SECONDS,
        )
        raw_variable, raw_value = next(iter(RAW_ICMP_TEST_ENVIRONMENT.items()))
        for environment in test_environments[:unprivileged_count]:
            self.assertNotIn(raw_variable, environment)
        for environment in test_environments[raw_index:privileged_end]:
            self.assertEqual(environment.get(raw_variable), raw_value)
        for environment in test_environments[privileged_end:]:
            self.assertNotIn(raw_variable, environment)
        for selection in (*concurrency_tests, *privileged_tests):
            self.assertIn(selection.evidence_id, output.getvalue())
        expected_exact_test_count = (
            unprivileged_count + 1 + len(concurrency_tests) + len(privileged_tests)
        )
        self.assertEqual(len(preflight_calls), expected_exact_test_count)
        self.assertTrue(
            all(
                timeout == DOCKER_CONTROL_TIMEOUT_SECONDS
                for _, timeout in preflight_calls
            )
        )

    def test_test_failure_remains_primary_when_stale_process_cleanup_fails(
        self,
    ) -> None:
        test_failure = RuntimeError("test failed")
        lifecycle_failure = RuntimeError("stale pkthere")
        with (
            patch.object(reality, "run", side_effect=test_failure),
            patch.object(
                reality,
                "audit_forwarder_lifecycle",
                side_effect=lifecycle_failure,
            ),
            self.assertRaisesRegex(RuntimeError, "test failed") as raised,
        ):
            reality.run_reality_test("failing test", ["test"], 1.0, {})
        self.assertIn(
            "secondary process lifecycle failure: stale pkthere",
            raised.exception.__notes__,
        )

    def test_exact_test_preflight_fails_closed_when_selection_is_missing(self) -> None:
        listed = CommandResult(
            argv=("tests", "--list"),
            returncode=0,
            stdout="present::test: test\n",
            stderr="",
            duration_seconds=0.01,
        )
        with patch.object(processes.RUNNER, "run", return_value=listed):
            processes.require_rust_test(
                "tests",
                "present::test",
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            )
            with self.assertRaisesRegex(RuntimeError, "missing::test"):
                processes.require_rust_test(
                    "tests",
                    "missing::test",
                    timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
                )

    def test_suite_preflight_fails_closed_when_executable_lists_zero_tests(
        self,
    ) -> None:
        listed = CommandResult(
            argv=("tests", "--list"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.01,
        )
        with (
            patch.object(processes.RUNNER, "run", return_value=listed),
            self.assertRaisesRegex(RuntimeError, "contains zero tests"),
        ):
            processes.require_rust_tests(
                "tests",
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            )


if __name__ == "__main__":
    unittest.main()
