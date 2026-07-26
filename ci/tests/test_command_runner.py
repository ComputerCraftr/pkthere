"""Bounded command-runner tests."""

from __future__ import annotations

import _thread
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ci.pkthere_ci.command_runner import (
    CommandResult,
    CommandRunner,
    CommandTimeoutError,
    console_output,
    exception_details,
    exception_exit_code,
    report_failure,
)

TEST_COMMAND_TIMEOUT_SECONDS = 0.1
TEST_COMMAND_BOUND_SECONDS = 2.0
TEST_INTERRUPT_DELAY_SECONDS = 0.2
TEST_PROCESS_POLL_SECONDS = 0.02
TEST_PROCESS_START_TIMEOUT_SECONDS = 1.0
TEST_LONG_SLEEP_SECONDS = 30


class CommandRunnerTests(unittest.TestCase):
    def test_console_output_hides_discovery_inventory(self) -> None:
        result = CommandResult(("cargo",), 0, "test a\ntest b\n", "", 0.1)

        stdout, stderr = console_output("Discover workspace tests", result)

        self.assertNotIn("test a", stdout)
        self.assertIn("retained in the CI log", stdout)
        self.assertEqual(stderr, "")

    def test_console_output_compacts_successful_test_case_lists(self) -> None:
        tests = "\n".join(f"test_case_{index} (...) ... ok" for index in range(20))
        result = CommandResult(
            ("python", "-m", "unittest"),
            0,
            "node output remains visible",
            f"{tests}\nRan 20 tests in 0.1s\n\nOK\n",
            0.1,
        )

        stdout, stderr = console_output("Run tests", result)

        self.assertEqual(stdout, "node output remains visible")
        self.assertNotIn("test_case_0", stderr)
        self.assertIn("Ran 20 tests", stderr)
        self.assertIn("OK", stderr)
        self.assertIn("successful output compacted", stderr)

    def test_console_output_extracts_failure_context_and_bounds_long_lines(
        self,
    ) -> None:
        noise = "\n".join(f"manifest row {index}" for index in range(300))
        long_failure = f"error: {'x' * 3_000}"
        result = CommandResult(
            ("cargo", "test"),
            101,
            f"{noise}\n{long_failure}\nnode diagnostic\n",
            "",
            0.1,
        )

        stdout, _ = console_output("Rust tests", result)

        self.assertNotIn("manifest row 0", stdout)
        self.assertIn("error:", stdout)
        self.assertIn("line truncated in console", stdout)
        self.assertIn("node diagnostic", stdout)
        self.assertIn("full failure output retained", stdout)

    def test_console_output_ignores_failure_words_inside_reality_json(self) -> None:
        evidence = "\n".join(
            f'socket-reality {{"sequence":{index},"message":"connection failed"}}'
            for index in range(100)
        )
        result = CommandResult(
            ("socket-reality",),
            101,
            f"{evidence}\nthread 'reality' panicked at test.rs:1\npolicy mismatch\n",
            "",
            0.1,
        )

        stdout, _ = console_output("Socket reality", result)

        self.assertNotIn('"sequence":0', stdout)
        self.assertIn("panicked at", stdout)
        self.assertIn("policy mismatch", stdout)

    def test_console_output_finds_structured_rust_failure_without_rendering_full_log(
        self,
    ) -> None:
        noise = "\n".join(f"cargo noise {index}" for index in range(100_000))
        marker = (
            'pkthere-test-failure {"schema":1,"event":"forwarder-wait",'
            '"expected":"handshake-reset-drop"}'
        )
        result = CommandResult(("cargo", "test"), 101, f"{noise}\n{marker}\n", "", 0.1)

        stdout, _ = console_output("Rust tests", result)

        self.assertNotIn("cargo noise 0", stdout)
        self.assertIn("handshake-reset-drop", stdout)

    def test_intentional_panics_cannot_hide_the_terminal_rust_failure(self) -> None:
        expected = (
            "test net::sock_mgr::grouped_clear_visibility ... FAILED\n"
            "\nfailures:\n    net::sock_mgr::grouped_clear_visibility\n"
            "test result: FAILED. 640 passed; 1 failed\n"
        )
        intentional = "\n".join(
            f"thread 'negative-{index}' panicked at negative.rs:{index}:1"
            for index in range(100)
        )
        result = CommandResult(
            ("cargo", "test"),
            101,
            f"{intentional}\n{expected}",
            "",
            0.1,
        )

        stdout, _ = console_output("Workspace tests", result)

        self.assertNotIn("negative-0", stdout)
        self.assertIn("grouped_clear_visibility", stdout)
        self.assertIn("test result: FAILED", stdout)

    def test_failure_report_is_annotated_and_added_to_step_summary(self) -> None:
        result = CommandResult(
            ("ruff", "check"),
            1,
            "I001 Import block is un-sorted\n  --> ci/example.py:3:1\n",
            "",
            0.1,
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            with (
                contextlib.redirect_stdout(output),
                patch.dict(
                    os.environ,
                    {"GITHUB_STEP_SUMMARY": str(summary)},
                ),
            ):
                report_failure("Check Python lint", result)
            summary_text = summary.read_text(encoding="utf-8")

        rendered = output.getvalue()
        self.assertIn("::error title=Check Python lint::I001", rendered)
        self.assertIn("Check Python lint FAILED", rendered)
        self.assertIn("I001 Import block is un-sorted", summary_text)

    def test_exception_detail_bounds_large_file_inventories(self) -> None:
        command = ("ruff", "check", *(f"source-{index}.py" for index in range(100)))
        details = exception_details(subprocess.CalledProcessError(1, command))

        self.assertEqual(len(details), 1)
        self.assertIn("92 more arguments", details[0])
        self.assertNotIn("source-99.py", details[0])

    def test_exception_group_exit_code_preserves_child_failure(self) -> None:
        error = ExceptionGroup(
            "native failures",
            [subprocess.CalledProcessError(101, ("cargo", "test"))],
        )

        self.assertEqual(exception_exit_code(error), 101)

    def test_timeout_preserves_partial_output_and_returns_boundedly(self) -> None:
        runner = CommandRunner()
        with self.assertRaises(CommandTimeoutError) as raised:
            runner.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import time; print('before-timeout', flush=True); "
                        f"time.sleep({TEST_LONG_SLEEP_SECONDS})"
                    ),
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
                timeout_seconds=TEST_PROCESS_START_TIMEOUT_SECONDS,
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

    def test_interruption_terminates_and_reaps_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            pid_path = Path(temporary_directory) / "child.pid"
            timer = threading.Timer(
                TEST_INTERRUPT_DELAY_SECONDS, _thread.interrupt_main
            )
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    CommandRunner().run(
                        [
                            sys.executable,
                            "-c",
                            (
                                "import os,time,pathlib; "
                                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
                                f"time.sleep({TEST_LONG_SLEEP_SECONDS})"
                            ),
                        ],
                        timeout_seconds=TEST_COMMAND_BOUND_SECONDS,
                        capture_output=True,
                    )
            finally:
                timer.cancel()
                timer.join()

            child_pid = int(pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + TEST_COMMAND_BOUND_SECONDS
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(TEST_PROCESS_POLL_SECONDS)
            else:
                self.fail(f"interrupted child {child_pid} remained alive")


if __name__ == "__main__":
    unittest.main()
