from __future__ import annotations

import os
import sys
import time
import unittest

from docker.alpine.pkthere_harness.command_runner import (
    CommandRunner,
    CommandTimeoutError,
)

TEST_COMMAND_TIMEOUT_SECONDS = 0.1
TEST_COMMAND_BOUND_SECONDS = 2.0
TEST_PROCESS_POLL_SECONDS = 0.02
TEST_LONG_SLEEP_SECONDS = 30


class CommandRunnerTests(unittest.TestCase):
    def test_timeout_preserves_partial_output_and_returns_boundedly(self) -> None:
        runner = CommandRunner()
        with self.assertRaises(CommandTimeoutError) as raised:
            runner.run(
                [
                    sys.executable,
                    "-c",
                    "import time; print('before-timeout', flush=True); "
                    f"time.sleep({TEST_LONG_SLEEP_SECONDS})",
                ],
                timeout_seconds=TEST_COMMAND_TIMEOUT_SECONDS,
                capture_output=True,
            )
        self.assertIn("before-timeout", raised.exception.result.stdout)
        self.assertLess(
            raised.exception.result.duration_seconds, TEST_COMMAND_BOUND_SECONDS
        )

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX process-group regression")
    def test_timeout_terminates_descendants_that_retain_capture_pipes(self) -> None:
        script = (
            "import os,time; child=os.fork(); "
            "print(f'descendant={child}', flush=True) if child else None; "
            f"time.sleep({TEST_LONG_SLEEP_SECONDS})"
        )
        with self.assertRaises(CommandTimeoutError) as raised:
            CommandRunner().run(
                [sys.executable, "-c", script],
                timeout_seconds=TEST_COMMAND_TIMEOUT_SECONDS,
                capture_output=True,
            )

        descendant_line = next(
            line
            for line in raised.exception.result.stdout.splitlines()
            if line.startswith("descendant=")
        )
        descendant_pid = int(descendant_line.removeprefix("descendant="))
        deadline = time.monotonic() + TEST_COMMAND_BOUND_SECONDS
        while time.monotonic() < deadline:
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(TEST_PROCESS_POLL_SECONDS)
        else:
            self.fail(f"timed-out descendant {descendant_pid} remained alive")

    def test_nonzero_result_is_returned_when_check_is_disabled(self) -> None:
        result = CommandRunner().run(
            [sys.executable, "-c", "raise SystemExit(7)"],
            timeout_seconds=TEST_COMMAND_BOUND_SECONDS,
            check=False,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 7)


if __name__ == "__main__":
    unittest.main()
