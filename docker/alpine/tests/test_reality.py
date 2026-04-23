from __future__ import annotations

from collections.abc import Mapping, Sequence
import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from docker.alpine.pkthere_harness import reality
from docker.alpine.pkthere_harness.test_manifest import (
    privileged_icmp_tests_for_platform,
)
from docker.alpine.pkthere_harness.timing import (
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
    DOCKER_SUITE_TIMEOUT_SECONDS,
)


class RealityCommandPolicyTests(unittest.TestCase):
    def test_suites_and_exact_tests_use_separate_bounded_deadlines(self) -> None:
        calls: list[tuple[tuple[str, ...], float]] = []

        def record_run(
            command: Sequence[str],
            *,
            timeout_seconds: float,
            env: Mapping[str, str] | None = None,
        ) -> None:
            del env
            calls.append((tuple(command), timeout_seconds))

        output = io.StringIO()
        with (
            patch("docker.alpine.pkthere_harness.reality.shutil.copy2"),
            patch.object(reality, "run", side_effect=record_run),
            redirect_stdout(output),
        ):
            reality.reality()

        self.assertEqual(
            [timeout for _, timeout in calls[:2]],
            [DOCKER_CONTROL_TIMEOUT_SECONDS, DOCKER_CONTROL_TIMEOUT_SECONDS],
        )
        test_calls = calls[2:]
        self.assertEqual(
            [timeout for _, timeout in test_calls[:4]],
            [
                DOCKER_SUITE_TIMEOUT_SECONDS,
                DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
                DOCKER_SUITE_TIMEOUT_SECONDS,
                DOCKER_SUITE_TIMEOUT_SECONDS,
            ],
        )
        privileged_tests = privileged_icmp_tests_for_platform("linux")
        self.assertEqual(
            [timeout for _, timeout in test_calls[4:]],
            [DOCKER_EXACT_TEST_TIMEOUT_SECONDS] * len(privileged_tests),
        )
        for selection in privileged_tests:
            self.assertIn(selection.test_name, output.getvalue())


if __name__ == "__main__":
    unittest.main()
