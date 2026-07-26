"""Portable artifact plan tests."""

from __future__ import annotations

import os
import platform
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ci.pkthere_ci.command_runner import CommandRunner
from ci.pkthere_ci.source_cache import (
    commit_source_aware_target_cache,
    prepare_source_aware_target_cache,
)
from docker.alpine import portable_build
from docker.alpine.portable_build import (
    AARCH64_TARGET,
    NATIVE_CONTAINER_MARKER,
    STAGED_EXECUTABLE_NAMES,
    X86_TARGET,
    _build_alpine_executables,
    _replace_directory,
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
    def test_artifact_pipeline_preserves_the_incremental_cargo_target_cache(
        self,
    ) -> None:
        runner = Mock(spec=CommandRunner)
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(portable_build, "_recorded_command") as recorded_command,
            patch.object(
                portable_build,
                "cargo_executables",
                side_effect=lambda _arguments, names, **_kwargs: {
                    name: Path(f"/target/{name}") for name in names
                },
            ),
            patch.object(
                shutil,
                "copy2",
                side_effect=lambda _source, destination: Path(destination).touch(),
            ),
        ):
            temporary = Path(temporary_directory)
            evidence_directory = temporary / "evidence"
            executables = _build_alpine_executables(
                AARCH64_TARGET,
                ("cross",),
                evidence_directory,
                runner=runner,
                environment={"PATH": "/usr/bin"},
            )

        self.assertEqual(set(executables), set(STAGED_EXECUTABLE_NAMES))
        recorded_command.assert_not_called()

    def test_source_cache_refreshes_changed_inputs_without_cargo_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "workspace"
            target = temporary / "target"
            source = root / "src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
            (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")

            state_path, inputs, _first = prepare_source_aware_target_cache(root, target)
            first_mtime = source.stat().st_mtime_ns
            commit_source_aware_target_cache(state_path, inputs)

            state_path, inputs, unchanged = prepare_source_aware_target_cache(
                root, target
            )
            self.assertEqual(source.stat().st_mtime_ns, first_mtime)
            self.assertEqual(unchanged["changed_input_count"], 0)
            commit_source_aware_target_cache(state_path, inputs)

            source.write_text("pub fn value() -> u8 { 2 }\n", encoding="utf-8")
            os.utime(source, ns=(1, 1))
            state_path, inputs, changed = prepare_source_aware_target_cache(
                root, target
            )

            self.assertGreater(source.stat().st_mtime_ns, first_mtime)
            self.assertEqual(changed["changed_input_count"], 1)
            self.assertFalse(changed["cold_cache"])
            self.assertFalse(
                any(path.name == ".cargo-clean" for path in target.iterdir())
            )
            commit_source_aware_target_cache(state_path, inputs)

    def test_source_cache_deletion_invalidates_workspace_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "workspace"
            target = temporary / "target"
            source = root / "src/lib.rs"
            manifest = root / "Cargo.toml"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn value() {}\n", encoding="utf-8")
            manifest.write_text("[workspace]\n", encoding="utf-8")

            state_path, inputs, _ = prepare_source_aware_target_cache(root, target)
            commit_source_aware_target_cache(state_path, inputs)
            prior_manifest_mtime = manifest.stat().st_mtime_ns
            source.unlink()

            _, _, refresh = prepare_source_aware_target_cache(root, target)

            self.assertEqual(refresh["removed_input_count"], 1)
            self.assertGreater(manifest.stat().st_mtime_ns, prior_manifest_mtime)

    def test_builder_identity_change_rebuilds_workspace_without_cargo_clean(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "workspace"
            target = temporary / "target"
            source = root / "src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn value() {}\n", encoding="utf-8")
            (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            old_identity = {"target": "host", "builder": "glibc-2.39"}
            new_identity = {"target": "host", "builder": "glibc-2.36"}

            state_path, inputs, _ = prepare_source_aware_target_cache(
                root,
                target,
                old_identity,
            )
            commit_source_aware_target_cache(state_path, inputs, old_identity)
            prior_mtime = source.stat().st_mtime_ns

            _, _, refresh = prepare_source_aware_target_cache(
                root,
                target,
                new_identity,
            )

            self.assertTrue(refresh["cache_identity_changed"])
            self.assertGreater(source.stat().st_mtime_ns, prior_mtime)
            self.assertEqual(refresh["touched_input_count"], 2)
            self.assertFalse(
                any(path.name == ".cargo-clean" for path in target.iterdir())
            )

    def test_artifact_publication_replaces_a_complete_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            source = temporary / "source"
            destination = temporary / "published"
            source.mkdir()
            destination.mkdir()
            (source / "new").write_text("new", encoding="utf-8")
            (destination / "old").write_text("old", encoding="utf-8")

            _replace_directory(source, destination)

            self.assertEqual(
                sorted(path.name for path in destination.iterdir()),
                ["new"],
            )
            self.assertFalse(
                any(
                    path.name.startswith(".published.staging-")
                    or path.name.startswith(".published.backup-")
                    for path in temporary.iterdir()
                )
            )

    def test_aarch64_uses_shared_complete_alpine_artifact_pipeline(self) -> None:
        expected_artifacts = {
            "pkthere",
            "pkthere-authority-audit",
            "socket-reality-test",
            "icmp-integration-test",
            "worker-modes-test",
            "pkthere-test-support-test",
            "pkthere-unit-test",
            "stress-test",
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

    def test_x86_64_native_container_uses_explicit_amd64_platform(self) -> None:
        runner = Mock(spec=CommandRunner)
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(portable_build, "_run_native_container") as native_build,
        ):
            temporary = Path(temporary_directory)
            build_x86_64(
                temporary / "evidence",
                temporary / "alpine",
                runner=runner,
                source_environment={},
                backend="native-container",
            )

        self.assertEqual(native_build.call_args.args[:2], ("x86_64", "linux/amd64"))

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

    def test_native_container_uses_explicit_target_to_isolate_target_flags(
        self,
    ) -> None:
        runner = Mock(spec=CommandRunner)
        executables = {
            name: Path(f"/artifacts/{name}") for name in STAGED_EXECUTABLE_NAMES
        }
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            patch.object(platform, "system", return_value="Linux"),
            patch.object(platform, "machine", return_value="aarch64"),
            patch.object(portable_build, "_require_tools"),
            patch.object(portable_build, "_record_toolchain"),
            patch.object(
                portable_build,
                "_build_alpine_executables",
                return_value=executables,
            ) as build_executables,
            patch.object(portable_build, "_stage_alpine_executables"),
        ):
            temporary = Path(temporary_directory)
            portable_build._build_aarch64_in_native_container(
                temporary / "evidence",
                temporary / "alpine",
                runner=runner,
                environment={},
            )

        self.assertEqual(
            build_executables.call_args.args[:2],
            (AARCH64_TARGET, ("cargo",)),
        )
        native_environment = build_executables.call_args.kwargs["environment"]
        self.assertIn("-C target-feature=+crt-static", native_environment["RUSTFLAGS"])
        self.assertIn("-C target-cpu=generic", native_environment["RUSTFLAGS"])
        self.assertIn(
            "-C link-arg=-Wno-unused-command-line-argument",
            native_environment["RUSTFLAGS"],
        )
        self.assertNotIn("-static-pie", native_environment["RUSTFLAGS"])

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
