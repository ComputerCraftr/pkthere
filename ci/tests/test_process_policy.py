"""Canonical process and workflow ownership tests."""

from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from collections import Counter
from pathlib import Path
from typing import cast
from unittest.mock import Mock, patch

from ci.pkthere_ci.ci_commands import (
    QualityInventory,
    aarch64_musl_commands,
    alpine_build_commands,
    alpine_runtime_commands,
    miri_setup_commands,
    quality_bootstrap_commands,
    quality_commands,
    workspace_test_command,
)
from ci.pkthere_ci.ci_tool_versions import load_ci_tool_versions
from ci.pkthere_ci.command_runner import CommandResult, CommandRunner
from ci.pkthere_ci.platform_selection import (
    NativePlatform,
    native_platform,
)
from ci.pkthere_ci.runner import TestRunner
from ci.pkthere_ci.selection_arguments import ExecutionIsolation
from ci.pkthere_ci.test_manifest import UNPRIVILEGED_SOCKET_REALITY_TESTS

ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOTS = (ROOT / "ci", ROOT / "docker/alpine", ROOT / ".github/scripts")
IGNORED_SOURCE_DIRS = {
    ".artifacts",
    ".git",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "cross-artifacts",
    "docker-artifacts",
    "target",
}


def copy_artifact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


class ProcessBoundaryPolicyTests(unittest.TestCase):
    def test_alpine_runtime_artifacts_remain_in_docker_context(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".artifacts/*", dockerignore)
        self.assertIn("!.artifacts/alpine", dockerignore)
        self.assertIn("!.artifacts/alpine/**", dockerignore)
        self.assertNotIn(".artifacts", dockerignore)

        runtime_dockerfile = (ROOT / "docker/alpine/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "COPY .artifacts/alpine/ /usr/local/libexec/pkthere/",
            runtime_dockerfile,
        )
        self.assertNotIn("PKTHERE_ALLOW_RAW_ICMP", runtime_dockerfile)

    def test_python_tooling_covers_every_workspace_source(self) -> None:
        configuration = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            configuration["tool"]["mypy"]["files"],
            ["ci", "docker"],
        )

        configured_files = {
            path.resolve()
            for configured_root in configuration["tool"]["mypy"]["files"]
            for path in (ROOT / configured_root).rglob("*.py")
            if not IGNORED_SOURCE_DIRS.intersection(path.parts)
        }
        workspace_files = {
            path.resolve()
            for path in ROOT.rglob("*.py")
            if not IGNORED_SOURCE_DIRS.intersection(path.relative_to(ROOT).parts)
        }
        self.assertEqual(configured_files, workspace_files)

        inventory = QualityInventory(
            rust=("sample.rs",),
            python=("sample.py",),
            toml=("Cargo.toml",),
            shell=("sample.sh",),
        )
        planned = tuple(
            argument
            for command in quality_commands(ROOT, inventory)
            for argument in command.arguments
        )
        tools = load_ci_tool_versions(ROOT)
        self.assertIn(f"ruff=={tools.ruff}", planned)
        self.assertIn(f"mypy=={tools.mypy}", planned)
        self.assertIn("sample.py", planned)

    def test_ci_tool_versions_have_one_toml_authority(self) -> None:
        tools = load_ci_tool_versions(ROOT)
        inventory = QualityInventory(
            rust=("sample.rs",),
            python=("sample.py",),
            toml=("Cargo.toml",),
            shell=("sample.sh",),
        )
        quality = tuple(
            argument
            for command in quality_commands(ROOT, inventory)
            for argument in command.arguments
        )
        bootstrap = tuple(
            argument
            for command in quality_bootstrap_commands(ROOT)
            for argument in command.arguments
        )
        aarch64 = tuple(
            argument
            for command in aarch64_musl_commands(ROOT)
            for argument in command.arguments
        )
        miri = tuple(
            argument
            for command in miri_setup_commands(ROOT)
            for argument in command.arguments
        )
        alpine = tuple(
            argument
            for command in (*alpine_build_commands(), *alpine_runtime_commands())
            for argument in command.arguments
        )
        self.assertIn(f"pipx=={tools.pipx}", bootstrap)
        self.assertIn(tools.taplo_cli, bootstrap)
        self.assertIn(f"prettier@{tools.prettier}", quality)
        self.assertIn(f"yamllint=={tools.yamllint}", quality)
        self.assertIn(tools.shfmt_image, quality)
        self.assertIn(tools.actionlint_image, quality)
        self.assertIn(tools.cross_revision, aarch64)
        self.assertIn(f"+{tools.miri_toolchain}", miri)
        self.assertIn("docker.alpine.portable_build", aarch64)
        self.assertIn("docker.alpine.portable_build", alpine)
        self.assertIn("docker.alpine.ci", alpine)

        workflow = (ROOT / ".github/workflows/rust.yml").read_text(encoding="utf-8")
        for value in vars(tools).values():
            self.assertNotIn(value, workflow)

        synthetic = {
            "actionlint_image": "example/actionlint:9.8.7",
            "cross_revision": "0123456789abcdef",
            "mypy": "9.8.6",
            "miri_toolchain": "nightly-2099-01-01",
            "pipx": "9.8.5",
            "prettier": "9.8.4",
            "ruff": "9.8.3",
            "shfmt_image": "example/shfmt:9.8.2",
            "taplo_cli": "9.8.1",
            "yamllint": "9.8.0",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries = "\n".join(
                f'{name} = "{value}"' for name, value in synthetic.items()
            )
            (root / "pyproject.toml").write_text(
                f"[tool.pkthere.ci-tools]\n{entries}\n",
                encoding="utf-8",
            )
            synthetic_quality = tuple(
                argument
                for command in quality_commands(root, inventory)
                for argument in command.arguments
            )
            synthetic_bootstrap = tuple(
                argument
                for command in quality_bootstrap_commands(root)
                for argument in command.arguments
            )
            synthetic_aarch64 = tuple(
                argument
                for command in aarch64_musl_commands(root)
                for argument in command.arguments
            )
            synthetic_miri = tuple(
                argument
                for command in miri_setup_commands(root)
                for argument in command.arguments
            )
            synthetic_tools = load_ci_tool_versions(root)
        self.assertEqual(synthetic_tools.miri_toolchain, synthetic["miri_toolchain"])
        for name, value in synthetic.items():
            planned = (
                synthetic_aarch64
                if name == "cross_revision"
                else synthetic_miri
                if name == "miri_toolchain"
                else synthetic_bootstrap
                if name in {"pipx", "taplo_cli"}
                else synthetic_quality
            )
            self.assertTrue(any(value in argument for argument in planned), name)

    def test_python_sources_use_platform_temporary_directories(self) -> None:
        temporary_root = "/" + "tmp"
        private_temporary_root = "/private/" + "tmp"
        violations: list[str] = []
        for path in sorted(ROOT.rglob("*.py")):
            if IGNORED_SOURCE_DIRS.intersection(path.relative_to(ROOT).parts):
                continue
            syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(syntax):
                if not isinstance(node, ast.Constant) or not isinstance(
                    node.value, str
                ):
                    continue
                value = node.value
                if value in {
                    temporary_root,
                    private_temporary_root,
                } or value.startswith(
                    (temporary_root + "/", private_temporary_root + "/")
                ):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(violations, [])

    def test_subprocess_execution_is_centralized_and_runner_calls_are_bounded(
        self,
    ) -> None:
        violations: list[str] = []
        for root in PYTHON_ROOTS:
            for path in sorted(root.rglob("*.py")):
                relative = path.relative_to(ROOT).as_posix()
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    dotted = _dotted_name(node.func)
                    if (
                        dotted
                        in {
                            "subprocess.Popen",
                            "subprocess.call",
                            "subprocess.check_call",
                            "subprocess.check_output",
                            "subprocess.run",
                        }
                        and relative != "ci/pkthere_ci/command_runner.py"
                    ):
                        violations.append(f"{relative}: direct {dotted}")
                    if (
                        dotted is not None
                        and dotted.startswith("os.exec")
                        and relative != "docker/alpine/pkthere_harness/processes.py"
                    ):
                        violations.append(
                            f"{relative}: {dotted} outside service replacement"
                        )
                    if (
                        dotted is not None
                        and dotted.endswith(".run")
                        and not any(
                            keyword.arg == "timeout_seconds"
                            for keyword in node.keywords
                        )
                    ):
                        violations.append(
                            f"{relative}: command runner call lacks timeout_seconds"
                        )
        self.assertEqual(violations, [])

    def test_ci_launcher_propagates_command_failure_to_its_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = CommandRunner().run(
                [
                    sys.executable,
                    "-m",
                    "ci.pkthere_ci",
                    "not-a-valid-command",
                    "--log",
                    str(Path(temporary) / "runner.log"),
                ],
                timeout_seconds=5.0,
                cwd=ROOT,
                check=False,
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)

    def test_ci_module_does_not_swallow_runner_failure(self) -> None:
        from ci.pkthere_ci import __main__ as runner_module

        arguments = argparse.Namespace(
            command="quality",
            log=Path("quality.log"),
            cpu_policy="portable",
            target=None,
            app_bin=None,
            privileged_app_bin=None,
            result=None,
            evidence_dir=Path("evidence"),
        )
        with (
            patch.object(runner_module, "parse_args", return_value=arguments),
            patch.object(
                TestRunner,
                "quality",
                side_effect=subprocess.CalledProcessError(101, ("cargo", "test")),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            runner_module.main()

    def test_ci_runner_rejects_a_failed_selected_test_command(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("cargo", "test"),
            returncode=101,
            stdout="test selected_case ... FAILED\n",
            stderr="error: test failed\n",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "runner.log",
                runner=cast(CommandRunner, mocked_runner),
            )
            with self.assertRaisesRegex(
                subprocess.CalledProcessError,
                "returned non-zero exit status 101",
            ):
                runner._run("Injected selected-test failure", ("cargo", "test"))

    def test_native_suite_runs_every_test_target_and_docs_before_failing(self) -> None:
        command = workspace_test_command()
        self.assertIn("--no-fail-fast", command)
        mocked_runner = Mock(spec=CommandRunner)
        calls = 0

        def native_result(command: tuple[str, ...], **_: object) -> CommandResult:
            nonlocal calls
            calls += 1
            return CommandResult(
                argv=tuple(command),
                returncode=101 if calls == 1 else 0,
                stdout="test result: FAILED\n" if calls == 1 else "test result: ok\n",
                stderr="",
                duration_seconds=0.1,
            )

        mocked_runner.run.side_effect = native_result
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "native.log",
                runner=cast(CommandRunner, mocked_runner),
            )
            with self.assertRaisesRegex(ExceptionGroup, "native Rust test failures"):
                runner.native(discovered=frozenset({"already-discovered"}))

        self.assertEqual(calls, 2)
        first, second = mocked_runner.run.call_args_list
        self.assertIn("--no-fail-fast", first.args[0])
        self.assertIn("--doc", second.args[0])

    def test_artifact_profiles_execute_only_their_canonical_command_plans(
        self,
    ) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("placeholder",),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "artifact.log",
                runner=cast(CommandRunner, mocked_runner),
            )
            for method, commands in (
                (runner.aarch64_musl, aarch64_musl_commands(ROOT)),
                (runner.alpine_build, alpine_build_commands()),
                (runner.alpine_runtime, alpine_runtime_commands()),
            ):
                mocked_runner.reset_mock()
                method()
                self.assertEqual(
                    [tuple(call.args[0]) for call in mocked_runner.run.call_args_list],
                    [command.arguments for command in commands],
                )

    def test_ci_tool_output_profile_uses_the_toml_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "github-output"
            runner = TestRunner(root / "profile.log")
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                runner.ci_tool_outputs()
            published = dict(
                line.split("=", 1)
                for line in output.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(published, vars(load_ci_tool_versions(ROOT)))

    def test_native_platform_profile_owns_the_complete_fail_fast_lifecycle(
        self,
    ) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("cargo", "build"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "pkthere"
            app.write_bytes(b"test executable")
            reality = Path(temporary) / "socket-reality"
            reality.write_bytes(b"test reality executable")
            platform = native_platform()
            privileged = Path(temporary) / "pkthere-priv"
            runner = TestRunner(
                Path(temporary) / "platform.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=platform,
            )
            discovered = frozenset({"owned_test"})
            with (
                patch.object(
                    runner, "_discover_workspace_tests", return_value=discovered
                ),
                patch.object(
                    runner,
                    "_resolve_socket_reality_executable",
                    return_value=reality,
                ),
                patch.object(runner, "unprivileged_reality") as unprivileged,
                patch.object(runner, "native") as native,
                patch.object(runner, "authority_audit") as authority,
                patch.object(
                    runner, "_prepare_privileged_copy", side_effect=copy_artifact
                ),
                patch.object(runner, "raw_reality") as raw,
            ):
                runner.platform_ci(app_bin=app, privileged_app_bin=privileged)

        native.assert_called_once_with(test_app_bin=app, discovered=discovered)
        authority.assert_called_once_with()
        unprivileged.assert_called_once_with(test_app_bin=app, executable=reality)
        raw.assert_called_once_with(
            test_app_bin=privileged,
            test_executable=reality.with_name("socket-reality-priv"),
            discovered=discovered,
        )

    def test_windows_and_freebsd_use_the_same_privilege_isolated_order(self) -> None:
        for platform in (NativePlatform.WINDOWS, NativePlatform.FREEBSD):
            with self.subTest(platform=platform):
                mocked_runner = Mock(spec=CommandRunner)
                mocked_runner.run.return_value = CommandResult(
                    argv=("cargo", "build"),
                    returncode=0,
                    stdout="",
                    stderr="",
                    duration_seconds=0.1,
                )

                with tempfile.TemporaryDirectory() as temporary:
                    suffix = ".exe" if platform is NativePlatform.WINDOWS else ""
                    app = Path(temporary) / f"pkthere{suffix}"
                    privileged = Path(temporary) / f"pkthere-priv{suffix}"
                    reality = Path(temporary) / f"socket-reality{suffix}"
                    app.write_bytes(b"test executable")
                    reality.write_bytes(b"test reality executable")
                    runner = TestRunner(
                        Path(temporary) / "platform.log",
                        runner=cast(CommandRunner, mocked_runner),
                        platform=platform,
                    )
                    events: list[str] = []

                    def prepare_copy(
                        source: Path,
                        destination: Path,
                        event_log: list[str] = events,
                    ) -> None:
                        event_log.append("prepare")
                        copy_artifact(source, destination)

                    with (
                        patch.object(runner, "_configure_freebsd_privilege_drop"),
                        patch.object(
                            runner,
                            "_discover_workspace_tests",
                            return_value=frozenset({"owned_test"}),
                        ),
                        patch.object(
                            runner,
                            "_resolve_socket_reality_executable",
                            return_value=reality,
                        ),
                        patch.object(
                            runner,
                            "unprivileged_reality",
                            side_effect=lambda events=events, **_: events.append(
                                "unprivileged"
                            ),
                        ),
                        patch.object(
                            runner,
                            "raw_reality",
                            side_effect=lambda events=events, **_: events.append(
                                "raw-reality"
                            ),
                        ),
                        patch.object(
                            runner,
                            "native",
                            side_effect=lambda events=events, **_: events.append(
                                "native"
                            ),
                        ),
                        patch.object(
                            runner,
                            "authority_audit",
                            side_effect=lambda events=events: events.append(
                                "authority-audit"
                            ),
                        ),
                        patch.object(
                            runner,
                            "_prepare_privileged_copy",
                            side_effect=prepare_copy,
                        ),
                    ):
                        runner.platform_ci(
                            app_bin=app,
                            privileged_app_bin=privileged,
                        )

                self.assertEqual(
                    events,
                    [
                        "unprivileged",
                        "prepare",
                        "prepare",
                        "raw-reality",
                        "native",
                        "authority-audit",
                    ],
                )

    def test_windows_unprivileged_reality_uses_restricted_child_token(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("socket-reality.exe", "--list"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "platform.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.WINDOWS,
            )
            runner._run_unprivileged(
                "restricted reality",
                ("socket-reality.exe", "--list"),
                windows_restricted=True,
            )

        self.assertTrue(mocked_runner.run.call_args.kwargs["windows_restricted"])

    def test_windows_reality_manifest_restricts_only_direct_socket_probes(self) -> None:
        isolation = {
            selection.test_name: selection.execution_isolation
            for selection in UNPRIVILEGED_SOCKET_REALITY_TESTS
        }
        self.assertEqual(
            isolation["udp_lifecycle_reality_matches_policy"],
            ExecutionIsolation.NATIVE_BASE,
        )
        for direct_test in (
            "unprivileged_raw_privilege_boundary_is_enforced",
            "udp_reality_matches_policy",
            "icmp_dgram_reality_matches_policy",
        ):
            self.assertEqual(
                isolation[direct_test], ExecutionIsolation.WINDOWS_RESTRICTED
            )

    def test_platform_ci_runs_every_phase_before_reporting_failures(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("cargo", "build"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "pkthere"
            privileged = Path(temporary) / "pkthere-priv"
            app.write_bytes(b"test executable")
            reality = Path(temporary) / "socket-reality"
            reality.write_bytes(b"test reality executable")
            runner = TestRunner(
                Path(temporary) / "platform.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.FREEBSD,
            )
            events: list[str] = []

            def fail_raw(**_: object) -> None:
                events.append("raw-reality")
                raise subprocess.CalledProcessError(101, ("raw-reality",))

            with (
                patch.object(runner, "_configure_freebsd_privilege_drop"),
                patch.object(
                    runner,
                    "_discover_workspace_tests",
                    return_value=frozenset({"owned_test"}),
                ),
                patch.object(
                    runner,
                    "_resolve_socket_reality_executable",
                    return_value=reality,
                ),
                patch.object(
                    runner,
                    "unprivileged_reality",
                    side_effect=lambda **_: events.append("unprivileged"),
                ),
                patch.object(
                    runner, "_prepare_privileged_copy", side_effect=copy_artifact
                ),
                patch.object(runner, "raw_reality", side_effect=fail_raw),
                patch.object(
                    runner,
                    "native",
                    side_effect=lambda **_: events.append("native"),
                ),
                patch.object(
                    runner,
                    "authority_audit",
                    side_effect=lambda: events.append("authority-audit"),
                ),
                self.assertRaisesRegex(
                    ExceptionGroup,
                    "native platform CI failures",
                ),
            ):
                runner.platform_ci(
                    app_bin=app,
                    privileged_app_bin=privileged,
                )

        self.assertEqual(
            events,
            ["unprivileged", "raw-reality", "native", "authority-audit"],
        )

    def test_freebsd_capability_failure_does_not_mask_unprivileged_suites(
        self,
    ) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("cargo", "build"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "pkthere"
            privileged = Path(temporary) / "pkthere-priv"
            app.write_bytes(b"test executable")
            reality = Path(temporary) / "socket-reality"
            reality.write_bytes(b"test reality executable")
            runner = TestRunner(
                Path(temporary) / "platform.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.FREEBSD,
            )
            events: list[str] = []
            with (
                patch.object(runner, "_configure_freebsd_privilege_drop"),
                patch.object(
                    runner,
                    "_discover_workspace_tests",
                    return_value=frozenset({"owned_test"}),
                ),
                patch.object(
                    runner,
                    "_resolve_socket_reality_executable",
                    return_value=reality,
                ),
                patch.object(
                    runner,
                    "unprivileged_reality",
                    side_effect=lambda **_: events.append("unprivileged"),
                ),
                patch.object(
                    runner,
                    "_prepare_privileged_copy",
                    side_effect=subprocess.CalledProcessError(1, ("grant",)),
                ),
                patch.object(runner, "raw_reality") as raw,
                patch.object(
                    runner,
                    "native",
                    side_effect=lambda **_: events.append("native"),
                ),
                patch.object(
                    runner,
                    "authority_audit",
                    side_effect=lambda: events.append("authority-audit"),
                ),
                self.assertRaisesRegex(
                    ExceptionGroup,
                    "native platform CI failures",
                ),
            ):
                runner.platform_ci(
                    app_bin=app,
                    privileged_app_bin=privileged,
                )

        self.assertEqual(events, ["unprivileged", "native", "authority-audit"])
        raw.assert_not_called()

    def test_vm_platform_result_is_verified_by_the_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "platform-result.json"
            runner = TestRunner(Path(temporary) / "platform.log")
            failure = subprocess.CalledProcessError(101, ("cargo", "test"))
            with patch.object(runner, "platform_ci", side_effect=failure):
                runner.platform_ci_vm(result)

            with self.assertRaisesRegex(RuntimeError, "CalledProcessError"):
                runner.verify_platform_ci_result(result)

            nested = ExceptionGroup(
                "native failures",
                [RuntimeError("authority stress owner missing for freebsd")],
            )
            with patch.object(runner, "platform_ci", side_effect=nested):
                runner.platform_ci_vm(result)
            with self.assertRaisesRegex(
                RuntimeError, "authority stress owner missing for freebsd"
            ):
                runner.verify_platform_ci_result(result)

            with patch.object(runner, "platform_ci"):
                runner.platform_ci_vm(result)

            runner.verify_platform_ci_result(result)

    def test_freebsd_platform_defaults_are_outside_the_synced_workspace(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        mocked_runner.run.return_value = CommandResult(
            argv=("cargo", "build"),
            returncode=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "platform.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.FREEBSD,
            )
            target = Path(runner.platform_environment["CARGO_TARGET_DIR"])
            app = target / "debug" / "pkthere"
            reality = Path(temporary) / "socket-reality"
            reality.write_bytes(b"test reality executable")
            with (
                patch.object(runner, "_configure_freebsd_privilege_drop"),
                patch.object(runner, "_run") as run,
                patch.object(
                    runner,
                    "_discover_workspace_tests",
                    return_value=frozenset({"owned_test"}),
                ),
                patch.object(
                    runner,
                    "_resolve_socket_reality_executable",
                    return_value=reality,
                ),
                patch.object(runner, "unprivileged_reality"),
                patch.object(runner, "native"),
                patch.object(runner, "authority_audit"),
                patch.object(
                    runner, "_prepare_privileged_copy", side_effect=copy_artifact
                ),
                patch.object(runner, "_destroy_privileged_copy"),
                patch.object(runner, "raw_reality"),
            ):
                run.side_effect = [
                    CommandResult(
                        argv=("cargo", "build"),
                        returncode=0,
                        stdout="",
                        stderr="",
                        duration_seconds=0.1,
                    )
                ]
                app.parent.mkdir(parents=True, exist_ok=True)
                app.write_bytes(b"test executable")
                runner.platform_ci()

        self.assertFalse(target.is_relative_to(ROOT))

    def test_freebsd_privilege_drop_identity_is_typed_and_non_root(self) -> None:
        mocked_runner = Mock(spec=CommandRunner)
        with tempfile.TemporaryDirectory() as temporary:
            runner = TestRunner(
                Path(temporary) / "platform.log",
                runner=cast(CommandRunner, mocked_runner),
                platform=NativePlatform.FREEBSD,
            )
            for identity in ("", "not-a-uid", "0"):
                with self.subTest(identity=identity):
                    mocked_runner.run.return_value = CommandResult(
                        argv=("id", "-u", "pkthere-ci"),
                        returncode=0,
                        stdout=f"{identity}\n",
                        stderr="",
                        duration_seconds=0.1,
                    )
                    with self.assertRaises(RuntimeError):
                        runner._configure_freebsd_privilege_drop()

            mocked_runner.run.return_value = CommandResult(
                argv=("id", "-u", "pkthere-ci"),
                returncode=0,
                stdout="1001\n",
                stderr="",
                duration_seconds=0.1,
            )
            runner._configure_freebsd_privilege_drop()

        self.assertEqual(runner.platform_environment["SUDO_UID"], "1001")

    def test_workflow_delegates_command_plans_without_reconstructing_them(self) -> None:
        workflow = (ROOT / ".github/workflows/rust.yml").read_text(encoding="utf-8")
        for profile in (
            "aarch64-musl",
            "alpine-build",
            "alpine-runtime",
            "ci-tool-outputs",
            "quality",
            "bootstrap-quality-tools",
            "msrv",
            "platform-ci",
            "release-stress",
        ):
            self.assertEqual(
                len(
                    re.findall(
                        rf"-m ci\.pkthere_ci {re.escape(profile)}(?=\s|$)",
                        workflow,
                    )
                ),
                1,
            )
        for duplicate in (
            "git ls-files",
            ".github/scripts/grant_raw_capability.sh",
            "run: cargo check --locked",
            "run: cargo clippy --locked",
            "run: cargo fmt",
            "run: cargo test --locked",
            "python3 -m docker.alpine",
            "cargo miri setup",
            "cargo install cross",
            "sudo apt-get",
        ):
            self.assertNotIn(duplicate, workflow)

    def test_literal_ci_command_definitions_are_not_duplicated(self) -> None:
        executables = {
            "bash",
            "cargo",
            "docker",
            "npx",
            "pipx",
            "python",
            "python3",
            "rustfmt",
            "shellcheck",
            "taplo",
        }
        definitions: Counter[tuple[str, ...]] = Counter()
        for root in PYTHON_ROOTS:
            for path in root.rglob("*.py"):
                if "tests" in path.parts:
                    continue
                syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(syntax):
                    if (
                        not isinstance(node, (ast.List, ast.Tuple))
                        or len(node.elts) < 3
                    ):
                        continue
                    if not all(
                        isinstance(element, ast.Constant)
                        and isinstance(element.value, str)
                        for element in node.elts
                    ):
                        continue
                    command = tuple(
                        cast(ast.Constant, element).value for element in node.elts
                    )
                    if command[0] in executables:
                        definitions[cast(tuple[str, ...], command)] += 1
        duplicates = {
            command: count for command, count in definitions.items() if count > 1
        }
        self.assertEqual(duplicates, {})

    def test_ordinary_icmp_integration_keeps_default_parallelism(self) -> None:
        source = (ROOT / "docker/alpine/pkthere_harness/reality.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"--test-threads=1"', source)

    def test_privileged_test_names_have_one_authoritative_manifest(self) -> None:
        manifest = ROOT / "ci/pkthere_ci/test_manifest.py"
        names = (
            "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node",
            "raw_icmp_locked_flow_rejects_wrong_source_id",
            "test_raw_icmp_independent_ids",
            "raw_icmp_wildcard_upstream_locks_on_localhost",
            "raw_icmp_forwarder_packet_dump_matches_policy",
        )
        governed = (
            ROOT / ".github/scripts",
            ROOT / "ci/pkthere_ci",
        )
        violations: list[str] = []
        for name in names:
            owners: list[str] = []
            for root in governed:
                for path in root.rglob("*.py"):
                    if name in path.read_text(encoding="utf-8"):
                        owners.append(path.relative_to(ROOT).as_posix())
            if owners != [manifest.relative_to(ROOT).as_posix()]:
                violations.append(f"{name}: {owners}")
        self.assertEqual(violations, [])


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


if __name__ == "__main__":
    unittest.main()
