"""Authority process-policy tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest.mock import Mock, patch

from ci.pkthere_ci.ci_commands import AUTHORITY_PROFILE_NAME, release_stress_commands
from ci.pkthere_ci.command_runner import CommandResult, CommandRunner
from ci.pkthere_ci.platform_selection import NativePlatform, native_platform
from ci.pkthere_ci.provenance import workspace_source_identity
from ci.pkthere_ci.runner import TestRunner
from ci.pkthere_ci.test_manifest import (
    ALPINE_CONCURRENCY_TESTS,
    CORE_AUTHORITY_TESTS,
    NATIVE_AUTHORITY_STRESS_TESTS,
    NEGATIVE_AUTHORITY_SMOKE_TESTS,
)

ROOT = Path(__file__).resolve().parents[2]


def authority_result_for(
    app_executable: str, test_executable: str, stress_executable: str
) -> Callable[..., CommandResult]:
    def authority_result(command: tuple[str, ...], **_: object) -> CommandResult:
        command = tuple(command)
        if "--message-format=json-render-diagnostics" in command:
            if "--test" in command and command[command.index("--test") + 1] == "stress":
                target_name = "stress"
                executable = stress_executable
            else:
                target_name = "pkthere"
                executable = (
                    app_executable if command[1] == "build" else test_executable
                )
            stdout = (
                f'{{"reason":"compiler-artifact","target":{{"name":"{target_name}"}},'
                f'"executable":"{executable}"}}\n'
            )
        elif command == (test_executable, "--list"):
            stdout = "".join(
                f"{selection.test_name}: test\n"
                for selection in (
                    *CORE_AUTHORITY_TESTS,
                    *NEGATIVE_AUTHORITY_SMOKE_TESTS,
                )
            )
        elif command == (stress_executable, "--list", "--ignored"):
            stdout = "".join(
                f"{selection.test_name}: test\n"
                for selection in (
                    *ALPINE_CONCURRENCY_TESTS,
                    *NATIVE_AUTHORITY_STRESS_TESTS,
                )
                if selection.staged_executable == "stress-test"
            )
        else:
            stdout = "test result: ok\n"
        return CommandResult(
            argv=command,
            returncode=0,
            stdout=stdout,
            stderr="",
            duration_seconds=0.1,
        )

    return authority_result


class AuthorityProcessPolicyTests(unittest.TestCase):
    def test_authority_audit_uses_the_feature_and_an_isolated_target(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        with tempfile.TemporaryDirectory() as temporary:
            app_executable = str(Path(temporary) / "pkthere-authority-audit-app")
            test_executable = str(Path(temporary) / "pkthere-authority-audit-test")
            stress_executable = str(Path(temporary) / "stress-authority-audit-test")
            mocked_runner.run.side_effect = authority_result_for(
                app_executable, test_executable, stress_executable
            )
            runner = TestRunner(
                Path(temporary) / "runner.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.LINUX,
            )
            runner.authority_audit()

        calls = mocked_runner.run.call_args_list
        negative_commands = {
            selection.executable_arguments(test_executable)
            for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS
        }
        observed_commands = {tuple(call.args[0]) for call in calls}
        self.assertTrue(negative_commands.issubset(observed_commands))
        stress_selections = tuple(
            selection
            for selection in ALPINE_CONCURRENCY_TESTS
            if selection.staged_executable == "stress-test"
        )
        self.assertTrue(
            {
                selection.executable_arguments(stress_executable)
                for selection in stress_selections
            }.issubset(observed_commands)
        )
        for call in calls:
            if tuple(call.args[0]) in negative_commands:
                self.assertEqual(call.kwargs["env"]["RUSTFLAGS"], "--cfg loom")
            if tuple(call.args[0]) in {
                selection.executable_arguments(stress_executable)
                for selection in stress_selections
            }:
                self.assertNotIn("RUSTFLAGS", call.kwargs["env"])
                self.assertEqual(call.kwargs["env"]["TEST_APP_BIN"], app_executable)

        build_calls = [
            call
            for call in calls
            if "--message-format=json-render-diagnostics" in call.args[0]
        ]
        runtime_build = next(call for call in build_calls if call.args[0][1] == "build")
        model_build = next(
            call
            for call in build_calls
            if call.args[0][1] == "test"
            and "--bin" in call.args[0]
            and call.args[0][call.args[0].index("--bin") + 1] == "pkthere"
        )
        self.assertNotIn("RUSTFLAGS", runtime_build.kwargs["env"])
        self.assertEqual(
            Path(runtime_build.kwargs["env"]["CARGO_TARGET_DIR"]),
            ROOT
            / "target"
            / "authority-audit"
            / workspace_source_identity(ROOT)[:16]
            / "runtime",
        )
        self.assertEqual(model_build.kwargs["env"]["RUSTFLAGS"], "--cfg loom")
        self.assertEqual(
            Path(model_build.kwargs["env"]["CARGO_TARGET_DIR"]),
            ROOT
            / "target"
            / "authority-audit"
            / workspace_source_identity(ROOT)[:16]
            / "model",
        )

        arguments = mocked_runner.run.call_args
        command = arguments.args[0]
        environment = arguments.kwargs["env"]
        self.assertIn("authority-audit", command)
        self.assertEqual(
            command[command.index("--profile") + 1], AUTHORITY_PROFILE_NAME
        )
        self.assertEqual(
            command[command.index("--bin") + 1],
            "pkthere",
        )
        self.assertNotIn("--tests", command)
        self.assertEqual(environment["TEST_APP_BIN"], app_executable)
        self.assertEqual(environment["RUSTFLAGS"], "--cfg loom")
        skipped_tests = tuple(
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "--skip"
        )
        self.assertEqual(
            skipped_tests,
            tuple(selection.test_name for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS),
        )
        self.assertEqual(
            Path(environment["CARGO_TARGET_DIR"]),
            ROOT
            / "target"
            / "authority-audit"
            / workspace_source_identity(ROOT)[:16]
            / "model",
        )

    def test_authority_audit_accepts_an_external_target_directory(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "authority-target"
            app_executable = str(Path(temporary) / "pkthere-authority-audit-app")
            test_executable = str(Path(temporary) / "pkthere-authority-audit-test")
            stress_executable = str(Path(temporary) / "stress-authority-audit-test")
            mocked_runner.run.side_effect = authority_result_for(
                app_executable, test_executable, stress_executable
            )
            runner = TestRunner(
                Path(temporary) / "runner.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.LINUX,
            )
            with patch.dict(
                os.environ,
                {"PKTHERE_AUTHORITY_TARGET_DIR": str(target)},
            ):
                runner.authority_audit()

        self.assertEqual(
            {
                call.kwargs["env"]["CARGO_TARGET_DIR"]
                for call in mocked_runner.run.call_args_list
            },
            {
                str(target / workspace_source_identity(ROOT)[:16] / "runtime"),
                str(target / workspace_source_identity(ROOT)[:16] / "model"),
            },
        )

    def test_freebsd_authority_audit_runs_native_worker_pair_stress(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        with tempfile.TemporaryDirectory() as temporary:
            app_executable = str(Path(temporary) / "pkthere-authority-audit-app")
            test_executable = str(Path(temporary) / "pkthere-authority-audit-test")
            stress_executable = str(Path(temporary) / "stress-authority-audit-test")
            mocked_runner.run.side_effect = authority_result_for(
                app_executable, test_executable, stress_executable
            )
            runner = TestRunner(
                Path(temporary) / "runner.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.FREEBSD,
            )
            runner.authority_audit()

        selection = NATIVE_AUTHORITY_STRESS_TESTS[0]
        observed = {tuple(call.args[0]) for call in mocked_runner.run.call_args_list}
        self.assertIn(selection.executable_arguments(stress_executable), observed)

    def test_release_stress_build_and_execution_enable_authority_audit(self) -> None:
        commands = release_stress_commands()
        self.assertEqual(len(commands), 2)
        self.assertTrue(
            all(
                ("--features", "authority-audit")
                == command.arguments[
                    command.arguments.index("--features") : command.arguments.index(
                        "--features"
                    )
                    + 2
                ]
                for command in commands
            )
        )
        self.assertTrue(
            all(
                ("--profile", AUTHORITY_PROFILE_NAME)
                == command.arguments[
                    command.arguments.index("--profile") : command.arguments.index(
                        "--profile"
                    )
                    + 2
                ]
                for command in commands
            )
        )
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("cargo", "test"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "stress.log",
                runner=cast(CommandRunner, mocked_runner),
            )
            runner.release_stress()
        expected_name = native_platform().executable_name("pkthere")
        for invocation in mocked_runner.run.call_args_list:
            self.assertEqual(
                invocation.kwargs["env"]["TEST_APP_BIN"],
                str(ROOT / "target" / AUTHORITY_PROFILE_NAME / expected_name),
            )
