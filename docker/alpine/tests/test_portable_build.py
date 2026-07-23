from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from docker.alpine.pkthere_harness.command_runner import CommandRunner
from docker.alpine import portable_build
from docker.alpine.portable_build import (
    AARCH64_TARGET,
    NATIVE_CONTAINER_MARKER,
    STAGED_EXECUTABLE_NAMES,
    X86_TARGET,
    _select_aarch64_backend,
    build_aarch64,
    build_x86_64,
    sanitize_environment,
    verify_static_elf,
)


class PortableEnvironmentTests(unittest.TestCase):
    def test_sanitizer_removes_host_and_target_build_overrides_without_values(
        self,
    ) -> None:
        secret = "do-not-print-this-value"
        injected = {
            "RUSTFLAGS": "-Ctarget-cpu=" + "native",
            "CARGO_ENCODED_RUSTFLAGS": secret,
            "CARGO_BUILD_RUSTDOCFLAGS": secret,
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": secret,
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER": secret,
            "CC_aarch64_unknown_linux_musl": secret,
            "AR_AARCH64_UNKNOWN_LINUX_MUSL": secret,
            "CFLAGS_x86_64_unknown_linux_musl": secret,
            "RETAINED_BUILD_CONTEXT": "expected",
        }
        environment, removed = sanitize_environment(injected)
        self.assertEqual(environment, {"RETAINED_BUILD_CONTEXT": "expected"})
        self.assertNotIn("RETAINED_BUILD_CONTEXT", removed)
        self.assertEqual(
            set(removed), set(injected).difference({"RETAINED_BUILD_CONTEXT"})
        )


class PortableArtifactInventoryTests(unittest.TestCase):
    def test_aarch64_uses_shared_complete_alpine_artifact_pipeline(self) -> None:
        expected_artifacts = {
            "pkthere",
            "socket-reality-test",
            "icmp-integration-test",
            "worker-modes-test",
            "pkthere-test-support-test",
            "pkthere-unit-test",
            "topology-verifier",
        }
        self.assertEqual(set(STAGED_EXECUTABLE_NAMES.values()), expected_artifacts)

        runner = Mock(spec=CommandRunner)
        executables = {
            name: Path(f"/artifacts/{name}") for name in STAGED_EXECUTABLE_NAMES
        }
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(portable_build, "_require_tools"),
            patch.object(portable_build, "_recorded_command"),
            patch.object(portable_build, "_record_toolchain"),
            patch.object(
                portable_build,
                "_build_alpine_executables",
                return_value=executables,
            ) as build_executables,
            patch.object(
                portable_build, "_stage_alpine_executables"
            ) as stage_executables,
        ):
            temporary = Path(temporary_directory)
            output = temporary / "alpine"
            build_aarch64(
                temporary / "evidence",
                output,
                runner=runner,
                source_environment={},
                backend="cross",
            )

        build_executables.assert_called_once()
        self.assertEqual(
            build_executables.call_args.args[:2], (AARCH64_TARGET, ("cross",))
        )
        stage_executables.assert_called_once()
        self.assertEqual(stage_executables.call_args.args, (executables, output))
        self.assertEqual(
            stage_executables.call_args.kwargs["expected_machine"], "AArch64"
        )

    def test_x86_64_uses_the_same_complete_alpine_artifact_pipeline(self) -> None:
        runner = Mock(spec=CommandRunner)
        executables = {
            name: Path(f"/artifacts/{name}") for name in STAGED_EXECUTABLE_NAMES
        }
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(portable_build, "_require_tools"),
            patch.object(portable_build, "_record_toolchain"),
            patch.object(
                portable_build,
                "_build_alpine_executables",
                return_value=executables,
            ) as build_executables,
            patch.object(
                portable_build, "_stage_alpine_executables"
            ) as stage_executables,
        ):
            temporary = Path(temporary_directory)
            output = temporary / "alpine"
            build_x86_64(
                temporary / "evidence",
                output,
                runner=runner,
                source_environment={},
            )

        build_executables.assert_called_once()
        self.assertEqual(build_executables.call_args.args[:2], (X86_TARGET, ("cargo",)))
        stage_executables.assert_called_once()
        self.assertEqual(stage_executables.call_args.args, (executables, output))
        self.assertEqual(
            stage_executables.call_args.kwargs["expected_machine"],
            "Advanced Micro Devices X86-64",
        )

    def test_auto_backend_uses_native_container_on_aarch64_docker(self) -> None:
        runner = Mock(spec=CommandRunner)
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                portable_build,
                "_docker_server_architecture",
                return_value="arm64",
            ),
        ):
            selected = _select_aarch64_backend(
                "auto",
                Path(temporary_directory),
                runner=runner,
                environment={},
            )

        self.assertEqual(selected, "native-container")

    def test_auto_backend_keeps_cross_on_non_aarch64_docker(self) -> None:
        runner = Mock(spec=CommandRunner)
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                portable_build,
                "_docker_server_architecture",
                return_value="amd64",
            ),
        ):
            selected = _select_aarch64_backend(
                "auto",
                Path(temporary_directory),
                runner=runner,
                environment={},
            )

        self.assertEqual(selected, "cross")

    def test_native_container_inner_build_does_not_require_docker_socket(self) -> None:
        runner = Mock(spec=CommandRunner)
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                portable_build,
                "_build_aarch64_in_native_container",
            ) as native_build,
            patch.object(
                portable_build,
                "_docker_server_architecture",
            ) as docker_architecture,
        ):
            temporary = Path(temporary_directory)
            build_aarch64(
                temporary / "evidence",
                temporary / "alpine",
                runner=runner,
                source_environment={NATIVE_CONTAINER_MARKER: "1"},
                backend="native-container",
            )

        native_build.assert_called_once()
        docker_architecture.assert_not_called()

    def test_explicit_native_container_rejects_non_aarch64_docker(self) -> None:
        runner = Mock(spec=CommandRunner)
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(
                portable_build,
                "_docker_server_architecture",
                return_value="amd64",
            ),
            self.assertRaisesRegex(RuntimeError, "AArch64 Docker server"),
        ):
            _select_aarch64_backend(
                "native-container",
                Path(temporary_directory),
                runner=runner,
                environment={},
            )


class StaticElfVerifierTests(unittest.TestCase):
    def test_accepts_ordinary_static_executable(self) -> None:
        self.assertIsNone(self._run_verifier())

    def test_accepts_static_pie_relocation_metadata(self) -> None:
        error = self._run_verifier(
            machine="AArch64",
            file_description="ELF 64-bit LSB pie executable, static-pie linked",
            program_headers="LOAD 0x000000",
            dynamic_entries="(RELA) 0x1234\n(RELACOUNT) 3",
        )
        self.assertIsNone(error)

    def test_rejects_wrong_machine(self) -> None:
        error = self._run_verifier(machine="Advanced Micro Devices X86-64")
        self.assertIsNotNone(error)
        self.assertIn("expected ELF machine", error or "")

    def test_rejects_program_interpreter(self) -> None:
        error = self._run_verifier(program_headers="INTERP 0x000000")
        self.assertIsNotNone(error)
        self.assertIn("PT_INTERP", error or "")

    def test_rejects_needed_shared_library(self) -> None:
        error = self._run_verifier(dynamic_entries="(NEEDED) Shared library: [libc.so]")
        self.assertIsNotNone(error)
        self.assertIn("DT_NEEDED", error or "")

    def test_rejects_dynamically_linked_file_classification(self) -> None:
        error = self._run_verifier(
            file_description="ELF 64-bit LSB executable, dynamically linked"
        )
        self.assertIsNotNone(error)
        self.assertIn("static or static PIE", error or "")

    def _run_verifier(
        self,
        *,
        machine: str = "AArch64",
        file_description: str = "ELF 64-bit LSB executable, statically linked",
        program_headers: str = "LOAD 0x000000",
        dynamic_entries: str = "There is no dynamic section in this file.",
    ) -> str | None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            binary = temporary / "pkthere"
            binary.write_bytes(b"fixture")
            tools = temporary / "tools"
            tools.mkdir()
            self._write_tool(
                tools / "file",
                '#!/usr/bin/env bash\nprintf \'%s: %s\\n\' "$1" "$FAKE_FILE_DESCRIPTION"\n',
            )
            self._write_tool(
                tools / "readelf",
                "#!/usr/bin/env bash\n"
                'case "$1" in\n'
                "  -hW) printf '  Machine: %s\\n' \"$FAKE_MACHINE\" ;;\n"
                "  -lW) printf '%s\\n' \"$FAKE_PROGRAM_HEADERS\" ;;\n"
                "  -dW) printf '%s\\n' \"$FAKE_DYNAMIC_ENTRIES\" ;;\n"
                "  *) exit 64 ;;\n"
                "esac\n",
            )
            environment = {
                "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
                "FAKE_MACHINE": machine,
                "FAKE_FILE_DESCRIPTION": file_description,
                "FAKE_PROGRAM_HEADERS": program_headers,
                "FAKE_DYNAMIC_ENTRIES": dynamic_entries,
            }
            try:
                verify_static_elf(
                    binary,
                    "AArch64",
                    temporary / "evidence",
                    runner=CommandRunner(),
                    environment=environment,
                )
            except RuntimeError as error:
                return str(error)
            return None

    @staticmethod
    def _write_tool(path: Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
