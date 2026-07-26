"""Canonical cross-platform native and privileged CI runner."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from ci.pkthere_ci.cargo import (
    cargo_executables,
    resolve_test_executable,
)
from ci.pkthere_ci.ci_commands import (
    AUTHORITY_PROFILE_NAME,
    CommandSpec,
    QualityInventory,
    aarch64_musl_commands,
    alpine_build_commands,
    alpine_runtime_commands,
    authority_build_arguments,
    authority_stress_build_arguments,
    authority_test_command,
    miri_setup_commands,
    msrv_commands,
    quality_bootstrap_commands,
    quality_commands,
    release_stress_commands,
    workspace_test_command,
)
from ci.pkthere_ci.ci_tool_versions import load_ci_tool_versions
from ci.pkthere_ci.command_runner import (
    CommandResult,
    CommandRunner,
    CommandTimeoutError,
    console_output,
    exception_details,
    report_failure,
)
from ci.pkthere_ci.evidence_types import ArtifactIdentity
from ci.pkthere_ci.macos_profile import (
    SUPPORTED_TARGETS,
    deterministic_bundle_manifest,
    parse_dwarfdump_uuids,
    parse_rustc_host,
    profiling_environment,
    profiling_paths,
    resolve_dwarf_payload,
    sha256_file,
)
from ci.pkthere_ci.miri_manifest import MIRI_BOUNDARY_TESTS
from ci.pkthere_ci.platform_selection import (
    NativePlatform,
    native_platform,
)
from ci.pkthere_ci.provenance import (
    candidate_file_paths,
    record_source_provenance,
    workspace_source_identity,
)
from ci.pkthere_ci.selection_arguments import ExecutionIsolation
from ci.pkthere_ci.test_discovery import (
    listed_rust_tests,
    require_exactly_one_listed_rust_test,
    require_listed_rust_test,
    require_nonempty_rust_tests,
)
from ci.pkthere_ci.test_manifest import (
    CORE_AUTHORITY_TESTS,
    NEGATIVE_AUTHORITY_SMOKE_TESTS,
    PRIVILEGED_ICMP_TESTS,
    RAW_ICMP_TEST_ENVIRONMENT,
    RAW_SOCKET_REALITY_TEST,
    UNPRIVILEGED_SOCKET_REALITY_TESTS,
    authority_stress_tests_for_platform,
    privileged_icmp_tests_for_platform,
)
from ci.pkthere_ci.timing import (
    ARTIFACT_BUILD_TIMEOUT_SECONDS,
    DOCKER_CONTROL_TIMEOUT_SECONDS,
)

ROOT = Path(__file__).resolve().parents[2]
CI_PHASE_FAILURES = (
    ExceptionGroup,
    OSError,
    RuntimeError,
    subprocess.SubprocessError,
)
PLATFORM_RESULT_SCHEMA = 2


class TestRunner:
    def __init__(
        self,
        log_file: Path,
        runner: CommandRunner | None = None,
        platform: NativePlatform | None = None,
    ) -> None:
        self.log_file = log_file
        self.runner = runner or CommandRunner()
        self.platform = native_platform() if platform is None else platform
        self.platform_environment = self._platform_environment()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.log_file.write_text("", encoding="utf-8")

    def _platform_environment(self) -> dict[str, str]:
        if self.platform is not NativePlatform.FREEBSD:
            return {}
        temporary = Path(tempfile.gettempdir())
        return {
            "CARGO_TARGET_DIR": os.environ.get(
                "CARGO_TARGET_DIR",
                str(temporary / "pkthere-target"),
            ),
            "PKTHERE_AUTHORITY_TARGET_DIR": os.environ.get(
                "PKTHERE_AUTHORITY_TARGET_DIR",
                str(temporary / "pkthere-authority-target"),
            ),
        }

    def quality(self) -> None:
        inventory = QualityInventory(
            rust=self._candidate_files("Rust", ("*.rs",)),
            python=self._candidate_files("Python", ("*.py", "*.pyi")),
            toml=self._candidate_files("TOML", ("*.toml",)),
            shell=self._candidate_files(
                "shell", ("*.sh", "*.bash", "*.dash", "*.ksh", "*.zsh")
            ),
        )
        for command in quality_commands(ROOT, inventory):
            self._run(
                command.label,
                command.arguments,
                timeout_seconds=command.timeout_seconds,
            )

    def quality_bootstrap(self) -> None:
        for command in quality_bootstrap_commands(ROOT):
            self._run(
                command.label,
                command.arguments,
                timeout_seconds=command.timeout_seconds,
            )

    def msrv(self) -> None:
        for command in msrv_commands():
            self._run(
                command.label,
                command.arguments,
                timeout_seconds=command.timeout_seconds,
            )

    def release_stress(self) -> None:
        executable_name = self.platform.executable_name("pkthere")
        test_app_bin = ROOT / "target" / AUTHORITY_PROFILE_NAME / executable_name
        for command in release_stress_commands():
            self._run(
                command.label,
                command.arguments,
                timeout_seconds=command.timeout_seconds,
                environment_overrides={"TEST_APP_BIN": str(test_app_bin)},
            )

    def ci_tool_outputs(self) -> None:
        output_name = os.environ.get("GITHUB_OUTPUT")
        if output_name is None:
            raise RuntimeError("ci-tool-outputs requires GITHUB_OUTPUT")
        tools = load_ci_tool_versions(ROOT)
        with Path(output_name).open("a", encoding="utf-8") as output:
            output.writelines(
                f"{name}={value}\n" for name, value in vars(tools).items()
            )
        self.log_file.write_text(
            "Published non-secret CI tool versions to GITHUB_OUTPUT\n",
            encoding="utf-8",
        )

    def aarch64_musl(self) -> None:
        self._run_commands(aarch64_musl_commands(ROOT))

    def alpine_build(self) -> None:
        self._run_commands(alpine_build_commands())

    def alpine_runtime(self) -> None:
        self._run_commands(alpine_runtime_commands())

    def _run_commands(self, commands: tuple[CommandSpec, ...]) -> None:
        for command in commands:
            self._run(
                command.label,
                command.arguments,
                timeout_seconds=command.timeout_seconds,
            )

    def native(
        self,
        *,
        test_app_bin: Path | None = None,
        discovered: frozenset[str] | None = None,
    ) -> frozenset[str]:
        discovered = discovered or self._discover_workspace_tests()
        environment_overrides = (
            {"TEST_APP_BIN": str(test_app_bin)} if test_app_bin is not None else None
        )
        failures: list[Exception] = []
        try:
            self._run(
                "Workspace unit and integration tests",
                workspace_test_command(),
                environment_overrides=environment_overrides,
            )
        except subprocess.CalledProcessError as error:
            failures.append(error)
        try:
            self._run(
                "Workspace documentation tests",
                (
                    "cargo",
                    "test",
                    "--locked",
                    "--workspace",
                    "--doc",
                    "--",
                    "--nocapture",
                ),
                environment_overrides=environment_overrides,
            )
        except subprocess.CalledProcessError as error:
            failures.append(error)
        if failures:
            raise ExceptionGroup("native Rust test failures", failures)
        return discovered

    def platform_ci(
        self,
        *,
        app_bin: Path | None = None,
        privileged_app_bin: Path | None = None,
    ) -> None:
        if self.platform is NativePlatform.FREEBSD:
            self._configure_freebsd_privilege_drop()
        target_dir = Path(
            self.platform_environment.get(
                "CARGO_TARGET_DIR",
                os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")),
            )
        )
        app_bin = app_bin or (
            target_dir / "debug" / self.platform.executable_name("pkthere")
        )
        privileged_app_bin = privileged_app_bin or (
            app_bin.with_name(f"{app_bin.stem}-priv{app_bin.suffix}")
        )
        self._run(
            "Build native packet forwarder",
            ("cargo", "build", "--locked", "-p", "pkthere", "--bin", "pkthere"),
        )
        app_bin = _workspace_path(app_bin)
        privileged_app_bin = _workspace_path(privileged_app_bin)
        if not app_bin.is_file():
            raise RuntimeError(f"native Cargo build omitted {app_bin}")
        discovered = self._discover_workspace_tests()
        reality_executable = self._resolve_socket_reality_executable()
        app_identity = self._artifact_identity(app_bin)
        reality_identity = self._artifact_identity(reality_executable)
        self._record_artifact_identity("base-application", app_identity)
        self._record_artifact_identity("base-socket-reality", reality_identity)

        self.unprivileged_reality(
            test_app_bin=app_bin,
            executable=reality_executable,
        )

        if privileged_app_bin == app_bin:
            raise RuntimeError(
                "privileged application path must differ from the base path"
            )
        privileged_test_bin = reality_executable.with_name(
            f"{reality_executable.stem}-priv{reality_executable.suffix}"
        )
        if privileged_test_bin == reality_executable:
            raise RuntimeError("privileged test path must differ from the base path")

        failures: list[Exception] = []
        try:
            self._prepare_privileged_copy(app_bin, privileged_app_bin)
            self._prepare_privileged_copy(reality_executable, privileged_test_bin)
            self._record_artifact_identity(
                "privileged-application",
                self._artifact_identity(privileged_app_bin),
            )
            self._record_artifact_identity(
                "privileged-socket-reality",
                self._artifact_identity(privileged_test_bin),
            )
            self.raw_reality(
                test_app_bin=privileged_app_bin,
                test_executable=privileged_test_bin,
                discovered=discovered,
            )
        except CI_PHASE_FAILURES as error:
            failures.append(error)
        finally:
            for privileged in (privileged_test_bin, privileged_app_bin):
                try:
                    self._destroy_privileged_copy(privileged)
                except CI_PHASE_FAILURES as error:
                    failures.append(error)

        self._assert_artifact_unchanged(app_identity)
        self._assert_artifact_unchanged(reality_identity)
        try:
            self.native(test_app_bin=app_bin, discovered=discovered)
        except CI_PHASE_FAILURES as error:
            failures.append(error)
        try:
            self.authority_audit()
        except CI_PHASE_FAILURES as error:
            failures.append(error)
        if failures:
            raise ExceptionGroup("native platform CI failures", failures)

    def platform_ci_vm(
        self,
        result_file: Path,
        *,
        app_bin: Path | None = None,
        privileged_app_bin: Path | None = None,
    ) -> None:
        """Preserve expected VM suite failures for host-side verification."""
        try:
            self.platform_ci(
                app_bin=app_bin,
                privileged_app_bin=privileged_app_bin,
            )
        except CI_PHASE_FAILURES as error:
            payload = {
                "schema": PLATFORM_RESULT_SCHEMA,
                "success": False,
                "failure_type": type(error).__name__,
                "message": str(error)[:1024],
                "failures": exception_details(error),
            }
        else:
            payload = {
                "schema": PLATFORM_RESULT_SCHEMA,
                "success": True,
                "failure_type": None,
                "message": "",
                "failures": [],
            }
        result_file = _workspace_path(result_file)
        result_file.parent.mkdir(parents=True, exist_ok=True)
        result_file.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    @staticmethod
    def verify_platform_ci_result(result_file: Path) -> None:
        result_file = _workspace_path(result_file)
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"platform CI result is missing or invalid: {result_file}"
            ) from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != PLATFORM_RESULT_SCHEMA
        ):
            raise RuntimeError("platform CI result has an unsupported schema")
        if payload.get("success") is True:
            return
        failure_type = payload.get("failure_type")
        message = payload.get("message")
        failures = payload.get("failures")
        if (
            not isinstance(failure_type, str)
            or not isinstance(message, str)
            or not isinstance(failures, list)
            or not all(isinstance(failure, str) for failure in failures)
        ):
            raise TypeError("platform CI failure result is malformed")
        detail = " | ".join(failures) if failures else message
        raise RuntimeError(f"FreeBSD platform CI failed ({failure_type}): {detail}")

    def _configure_freebsd_privilege_drop(self) -> None:
        identity = self._run(
            "Resolve FreeBSD unprivileged CI identity",
            ("id", "-u", "pkthere-ci"),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        ).stdout.strip()
        try:
            uid = int(identity)
        except ValueError as error:
            raise RuntimeError(
                "FreeBSD CI identity did not resolve to a UID"
            ) from error
        if uid <= 0:
            raise RuntimeError("FreeBSD CI identity must be non-root")
        self.platform_environment["SUDO_UID"] = str(uid)

    def authority_audit(self) -> None:
        base_environment = os.environ.copy()
        base_environment.update(self.platform_environment)
        target_root = Path(
            os.environ.get(
                "PKTHERE_AUTHORITY_TARGET_DIR",
                self.platform_environment.get(
                    "PKTHERE_AUTHORITY_TARGET_DIR",
                    str(ROOT / "target" / "authority-audit"),
                ),
            )
        )
        target_root = target_root / workspace_source_identity(ROOT)[:16]
        base_environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
        base_environment.pop("RUSTFLAGS", None)
        runtime_environment = base_environment.copy()
        runtime_environment["CARGO_TARGET_DIR"] = str(target_root / "runtime")
        app_executables = cargo_executables(
            authority_build_arguments(tests=False),
            {"pkthere"},
            root=ROOT,
            runner=self.runner,
            environment=runtime_environment,
        )
        runtime_environment["TEST_APP_BIN"] = str(app_executables["pkthere"])
        stress_selections = tuple(
            selection
            for selection in authority_stress_tests_for_platform(self.platform.value)
            if selection.staged_executable == "stress-test"
        )
        if not stress_selections:
            raise RuntimeError(
                f"authority audit has no multithread stress owners for {self.platform.value}"
            )
        stress_executable = cargo_executables(
            authority_stress_build_arguments(),
            {"stress"},
            root=ROOT,
            runner=self.runner,
            environment=runtime_environment,
        )["stress"]
        stress_listing = self._run(
            "Discover optimized multithread authority stress evidence",
            (str(stress_executable), "--list", "--ignored"),
            environment=runtime_environment,
        )
        stress_bindings = tuple(
            selection.bind_discovered_test(
                stress_listing.stdout, str(stress_executable)
            )
            for selection in stress_selections
        )
        self._record_bindings("optimized authority stress", stress_bindings)
        for selection in stress_selections:
            self._run(
                f"Optimized authority stress: {selection.evidence_id}",
                selection.executable_arguments(str(stress_executable)),
                environment=runtime_environment,
            )
        model_environment = base_environment.copy()
        model_environment["CARGO_TARGET_DIR"] = str(target_root / "model")
        model_environment["RUSTFLAGS"] = "--cfg loom"
        model_environment["TEST_APP_BIN"] = str(app_executables["pkthere"])
        test_executables = cargo_executables(
            authority_build_arguments(tests=True),
            {"pkthere"},
            root=ROOT,
            runner=self.runner,
            environment=model_environment,
        )
        executable = test_executables["pkthere"]
        listing = self._run(
            "Discover production authority-audit evidence",
            (str(executable), "--list"),
            environment=model_environment,
        )
        bindings = tuple(
            selection.bind_discovered_test(listing.stdout, str(executable))
            for selection in CORE_AUTHORITY_TESTS
        )
        self._record_bindings("production authority evidence", bindings)
        negative_bindings = tuple(
            selection.bind_discovered_test(listing.stdout, str(executable))
            for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS
        )
        self._record_bindings("negative authority controls", negative_bindings)
        for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS:
            self._run(
                f"Negative-control smoke: {selection.evidence_id}",
                selection.executable_arguments(str(executable)),
                environment=model_environment,
            )
        self._run(
            "Production authority-audit tests",
            authority_test_command(
                skipped_tests=tuple(
                    selection.test_name for selection in NEGATIVE_AUTHORITY_SMOKE_TESTS
                )
            ),
            environment=model_environment,
        )

    def miri_boundaries(self) -> None:
        self._run_commands(miri_setup_commands(ROOT))
        miri_toolchain = load_ci_tool_versions(ROOT).miri_toolchain
        for selection in MIRI_BOUNDARY_TESTS:
            listing = self._run(
                f"Discover exact Miri owner: {selection.label}",
                selection.miri_listing_arguments(miri_toolchain),
            )
            require_exactly_one_listed_rust_test(listing.stdout, selection.test_name)
            self._run(
                f"Miri: {selection.label}",
                selection.miri_arguments(miri_toolchain),
            )

    def macos_profile(
        self,
        *,
        cpu_policy: str,
        target: str | None,
        evidence_root: Path,
    ) -> None:
        if self.platform is not NativePlatform.MACOS:
            raise RuntimeError("macOS profiling artifacts require a macOS host")
        rustc_verbose = self._run(
            "Resolve Rust host target",
            ("rustc", "-vV"),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        host_target = parse_rustc_host(rustc_verbose.stdout)
        selected_target = target or host_target
        if selected_target not in SUPPORTED_TARGETS:
            raise RuntimeError(f"unsupported macOS profiling target: {selected_target}")
        if cpu_policy == "native" and selected_target != host_target:
            raise RuntimeError(
                "native CPU profiling requires the target to equal the Rust host"
            )

        paths = profiling_paths(
            ROOT,
            evidence_root.resolve(),
            selected_target,
            cpu_policy,
        )
        paths.evidence_dir.mkdir(parents=True, exist_ok=True)
        environment, removed, flags = profiling_environment(
            os.environ.copy(),
            cpu_policy=cpu_policy,
            target_dir=paths.target_dir,
        )
        sanitized = "".join(
            f"macOS profiling build: cleared {name}\n" for name in removed
        )
        (paths.evidence_dir / "sanitized-environment.txt").write_text(
            sanitized,
            encoding="utf-8",
        )
        sys.stdout.write(sanitized)

        rustc = self._run(
            "Record profiling rustc",
            ("rustc", "--version", "--verbose"),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            environment=environment,
        )
        cargo = self._run(
            "Record profiling Cargo",
            ("cargo", "--version", "--verbose"),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            environment=environment,
        )
        source_evidence = record_source_provenance(
            ROOT,
            paths.evidence_dir,
            runner=self.runner,
            environment=environment,
        )
        self._run(
            "Build macOS Time Profiler artifact",
            (
                "cargo",
                "build",
                "--locked",
                "--profile",
                "profiling",
                "-p",
                "pkthere",
                "--bin",
                "pkthere",
                "--target",
                selected_target,
            ),
            environment=environment,
        )

        required = (paths.binary, paths.dsym, paths.dwarf_directory)
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise RuntimeError(
                f"macOS profiling build omitted required artifacts: {missing}"
            )
        try:
            dwarf_payload = resolve_dwarf_payload(paths)
        except ValueError as error:
            raise RuntimeError(str(error)) from error
        binary_uuid = self._run(
            "Read Mach-O UUID",
            ("dwarfdump", "--uuid", str(paths.binary)),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            environment=environment,
        )
        dsym_uuid = self._run(
            "Read dSYM UUID",
            ("dwarfdump", "--uuid", str(paths.dsym)),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            environment=environment,
        )
        binary_uuids = parse_dwarfdump_uuids(binary_uuid.stdout)
        dsym_uuids = parse_dwarfdump_uuids(dsym_uuid.stdout)
        if not binary_uuids or binary_uuids != dsym_uuids:
            raise RuntimeError("Mach-O and dSYM UUID sets are missing or do not match")
        self._run(
            "Verify dSYM debug information",
            ("dwarfdump", "--verify", str(paths.dsym)),
            timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
            environment=environment,
        )

        bundle_manifest, bundle_manifest_sha256 = deterministic_bundle_manifest(
            paths.dsym
        )
        (paths.evidence_dir / "dsym-bundle-manifest.json").write_text(
            bundle_manifest,
            encoding="utf-8",
        )
        evidence = {
            **source_evidence,
            "binary": str(paths.binary),
            "binary_sha256": sha256_file(paths.binary),
            "cargo_version": cargo.stdout.strip(),
            "cpu_policy": cpu_policy,
            "dsym": str(paths.dsym),
            "dsym_bundle_manifest_sha256": bundle_manifest_sha256,
            "dsym_dwarf_payload": str(dwarf_payload),
            "dsym_dwarf_payload_sha256": sha256_file(dwarf_payload),
            "dsym_uuids": sorted(dsym_uuids),
            "encoded_rustflags": list(flags),
            "encoded_rustflags_escaped": "\\u001f".join(flags),
            "mach_o_uuids": sorted(binary_uuids),
            "rustc_version": rustc.stdout.strip(),
            "target_dir": str(paths.target_dir),
            "target_triple": selected_target,
        }
        (paths.evidence_dir / "profile-evidence.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def raw_reality(
        self,
        *,
        test_app_bin: Path | None = None,
        test_executable: Path | None = None,
        discovered: frozenset[str] | None = None,
    ) -> None:
        configured_app = test_app_bin or (
            Path(os.environ["TEST_APP_BIN"]) if "TEST_APP_BIN" in os.environ else None
        )
        if configured_app is None:
            raise RuntimeError("TEST_APP_BIN must name the prepared test binary")
        discovered = discovered or self._discover_workspace_tests()
        platform = self.platform.value
        if platform not in RAW_SOCKET_REALITY_TEST.platforms:
            raise RuntimeError(
                f"no privileged RAW socket reality owner for platform: {platform}"
            )
        executable = test_executable
        if executable is None:
            raise RuntimeError(
                "privileged socket reality requires an isolated prepared test artifact"
            )
        listed = self._run(
            "Discover privileged RAW socket reality test",
            (str(executable), "--list"),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        RAW_SOCKET_REALITY_TEST.bind_discovered_test(listed.stdout, str(executable))
        raw_environment = {
            **RAW_ICMP_TEST_ENVIRONMENT,
            "TEST_APP_BIN": str(configured_app),
        }
        failures: list[Exception] = []
        try:
            self._run(
                "Privileged RAW socket reality",
                RAW_SOCKET_REALITY_TEST.executable_arguments(str(executable)),
                environment_overrides=raw_environment,
            )
        except subprocess.CalledProcessError as error:
            failures.append(error)
        for selection in privileged_icmp_tests_for_platform(platform):
            require_listed_rust_test(discovered, selection.test_name)
            listing = self._run(
                f"List exact privileged target ({platform}): {selection.test_name}",
                selection.cargo_listing_arguments(),
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            )
            selection.bind_discovered_test(listing.stdout, "cargo")
            try:
                self._run(
                    f"Privileged ICMP test ({platform}): {selection.test_name}",
                    selection.cargo_arguments(),
                    environment_overrides=raw_environment,
                )
            except subprocess.CalledProcessError as error:
                failures.append(error)
        if failures:
            raise ExceptionGroup("privileged RAW test failures", failures)

    def standalone_raw_reality(self) -> None:
        configured = os.environ.get("TEST_APP_BIN")
        if configured is None:
            raise RuntimeError("TEST_APP_BIN must name the immutable base application")
        base_app = _workspace_path(Path(configured))
        base_test = resolve_test_executable(
            RAW_SOCKET_REALITY_TEST.package,
            RAW_SOCKET_REALITY_TEST.target_name or "socket_reality",
            root=ROOT,
            runner=self.runner,
            environment={**os.environ, **self.platform_environment},
        )
        privileged_app = base_app.with_name(f"{base_app.stem}-priv{base_app.suffix}")
        privileged_test = base_test.with_name(
            f"{base_test.stem}-priv{base_test.suffix}"
        )
        try:
            self._prepare_privileged_copy(base_app, privileged_app)
            self._prepare_privileged_copy(base_test, privileged_test)
            self.raw_reality(
                test_app_bin=privileged_app,
                test_executable=privileged_test,
            )
        finally:
            self._destroy_privileged_copy(privileged_test)
            self._destroy_privileged_copy(privileged_app)

    def unprivileged_reality(
        self,
        *,
        test_app_bin: Path,
        executable: Path,
    ) -> None:
        listing = self._run_unprivileged(
            "Discover unprivileged socket reality tests",
            (str(executable), "--list"),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        environment = {"TEST_APP_BIN": str(test_app_bin)}
        for selection in UNPRIVILEGED_SOCKET_REALITY_TESTS:
            if self.platform.value not in selection.platforms:
                continue
            selection.bind_discovered_test(listing.stdout, str(executable))
            self._run_unprivileged(
                f"Unprivileged socket reality: {selection.evidence_id}",
                selection.executable_arguments(str(executable)),
                environment_overrides=environment,
                windows_restricted=(
                    selection.execution_isolation
                    is ExecutionIsolation.WINDOWS_RESTRICTED
                ),
            )

    def _run_unprivileged(
        self,
        label: str,
        command: tuple[str, ...],
        *,
        timeout_seconds: float = ARTIFACT_BUILD_TIMEOUT_SECONDS,
        environment_overrides: Mapping[str, str] | None = None,
        windows_restricted: bool = False,
    ) -> CommandResult:
        if self.platform is NativePlatform.FREEBSD:
            command = ("su", "-m", "pkthere-ci", "-c", shlex.join(command))
        elif os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            raise RuntimeError(
                "unprivileged reality cannot run under a root process without a platform adapter"
            )
        return self._run(
            label,
            command,
            timeout_seconds=timeout_seconds,
            environment_overrides=environment_overrides,
            windows_restricted=(
                self.platform is NativePlatform.WINDOWS and windows_restricted
            ),
        )

    def _resolve_socket_reality_executable(self) -> Path:
        return resolve_test_executable(
            "pkthere",
            "socket_reality",
            root=ROOT,
            runner=self.runner,
            environment={**os.environ, **self.platform_environment},
        )

    def _artifact_identity(self, path: Path) -> ArtifactIdentity:
        path = _workspace_path(path)
        getxattr = getattr(os, "getxattr", None)
        try:
            capability = (
                getxattr(path, "security.capability").hex()
                if getxattr is not None
                else "none"
            )
        except OSError:
            capability = "none"
        return ArtifactIdentity.inspect(
            path,
            f"mode={path.stat().st_mode:o};linux-capability={capability}",
        )

    def _record_artifact_identity(self, label: str, identity: ArtifactIdentity) -> None:
        with self.log_file.open("a", encoding="utf-8") as stream:
            stream.write(
                "\n"
                + json.dumps(
                    {"artifact": label, **identity.evidence_payload()},
                    sort_keys=True,
                )
                + "\n"
            )

    def _assert_artifact_unchanged(self, expected: ArtifactIdentity) -> None:
        observed = self._artifact_identity(expected.path)
        if observed != expected:
            raise RuntimeError(
                f"base artifact changed during privileged phase: {expected.path}"
            )

    def _prepare_privileged_copy(self, source: Path, destination: Path) -> None:
        if source == destination:
            raise RuntimeError("privileged artifact must use a distinct path")
        if destination.exists():
            self._destroy_privileged_copy(destination)
        if self.platform.requires_raw_capability_grant:
            self._grant_raw_capability(source, destination)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def _destroy_privileged_copy(self, path: Path) -> None:
        if not path.exists():
            return
        if self.platform.requires_raw_capability_grant:
            self._run(
                "Destroy privileged artifact",
                (
                    "bash",
                    str(ROOT / ".github/scripts/revoke_raw_capability.sh"),
                    str(path),
                ),
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            )
        else:
            path.unlink()

    def _grant_raw_capability(self, source: Path, destination: Path) -> None:
        if source == destination:
            raise RuntimeError("RAW privilege grant cannot mutate a base artifact")
        self._run(
            "Grant RAW capability",
            (
                "bash",
                str(ROOT / ".github/scripts/grant_raw_capability.sh"),
                str(source),
                str(destination),
            ),
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )

    def _candidate_files(
        self, label: str, patterns: tuple[str, ...]
    ) -> tuple[str, ...]:
        files = candidate_file_paths(
            ROOT,
            patterns,
            runner=self.runner,
            environment={**os.environ, **self.platform_environment},
        )
        if not files:
            raise RuntimeError(f"candidate {label} inventory is empty")
        return files

    def _discover_workspace_tests(self) -> frozenset[str]:
        listed = self._run(
            "Discover workspace test inventory",
            workspace_test_command(list_only=True),
            # A cold `cargo test -- --list` still resolves, downloads, and
            # compiles the complete workspace before it can print inventory.
            timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
        )
        discovered = listed_rust_tests(listed.stdout)
        require_nonempty_rust_tests(discovered, "workspace test discovery")
        for selection in (*PRIVILEGED_ICMP_TESTS, RAW_SOCKET_REALITY_TEST):
            require_listed_rust_test(discovered, selection.test_name)
        print(f"Discovered {len(discovered)} unique workspace tests", flush=True)
        return discovered

    def _run(
        self,
        label: str,
        command: tuple[str, ...],
        *,
        timeout_seconds: float = ARTIFACT_BUILD_TIMEOUT_SECONDS,
        environment_overrides: Mapping[str, str] | None = None,
        environment: Mapping[str, str] | None = None,
        windows_restricted: bool = False,
    ) -> CommandResult:
        if environment is not None and environment_overrides is not None:
            raise ValueError(
                "use either a complete environment or environment overrides"
            )
        command_environment = (
            os.environ.copy() if environment is None else dict(environment)
        )
        command_environment.update(self.platform_environment)
        if environment_overrides is not None:
            command_environment.update(environment_overrides)
        print(f"::group::{label}", flush=True)
        try:
            completed = self.runner.run(
                command,
                timeout_seconds=timeout_seconds,
                cwd=ROOT,
                env=command_environment,
                check=False,
                capture_output=True,
                windows_restricted=windows_restricted,
            )
        except CommandTimeoutError as error:
            self._record(label, error.result)
            print("::endgroup::", flush=True)
            report_failure(label, error.result)
            raise
        except BaseException:
            print("::endgroup::", flush=True)
            raise
        self._record(label, completed)
        print("::endgroup::", flush=True)
        if completed.returncode != 0:
            report_failure(label, completed)
            raise subprocess.CalledProcessError(
                completed.returncode,
                completed.argv,
                output=completed.stdout,
                stderr=completed.stderr,
            )
        return completed

    def _record(self, label: str, completed: CommandResult) -> None:
        rendered = (
            f"\n=== {label} ===\n"
            f"command: {' '.join(completed.argv)}\n"
            f"exit: {completed.returncode}\n"
            f"duration_seconds: {completed.duration_seconds:.3f}\n"
            f"--- stdout ---\n{completed.stdout}"
            f"--- stderr ---\n{completed.stderr}"
        )
        with self.log_file.open("a", encoding="utf-8") as stream:
            stream.write(rendered)
        if completed.returncode != 0:
            return
        console_stdout, console_stderr = console_output(label, completed)
        sys.stdout.write(console_stdout)
        sys.stderr.write(console_stderr)
        sys.stdout.flush()
        sys.stderr.flush()

    def _record_bindings(self, label: str, bindings: tuple[object, ...]) -> None:
        lines = [f"\n=== {label} bindings ===\n"]
        for binding in bindings:
            lines.append(f"{binding!r}\n")
        with self.log_file.open("a", encoding="utf-8") as stream:
            stream.writelines(lines)
        print(f"Bound {len(bindings)} {label} row(s); details retained in the CI log")


def _workspace_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path
