"""Authoritative portable artifact build, staging, and ELF verification."""

from __future__ import annotations

import argparse
import errno
import importlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Literal, cast

from ci.pkthere_ci.build_environment import (
    sanitize_environment,
)
from ci.pkthere_ci.cargo import cargo_executables
from ci.pkthere_ci.command_runner import CommandResult, CommandRunner
from ci.pkthere_ci.provenance import record_source_provenance, sha256_file
from ci.pkthere_ci.source_cache import (
    commit_source_aware_target_cache,
    prepare_source_aware_target_cache,
    target_cache_identity,
)
from ci.pkthere_ci.test_manifest import (
    ALPINE_CONCURRENCY_TESTS,
    PRIVILEGED_ICMP_TESTS,
    RAW_SOCKET_REALITY_TEST,
)
from ci.pkthere_ci.timing import (
    ARTIFACT_BUILD_TIMEOUT_SECONDS,
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    VERIFIER_TIMEOUT_SECONDS,
)

__all__ = ("sanitize_environment",)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STAGE = ROOT / ".artifacts/alpine"
X86_TARGET = "x86_64-unknown-linux-musl"
AARCH64_TARGET = "aarch64-unknown-linux-musl"
AARCH64_NATIVE_PLATFORM = "linux/arm64"
X86_NATIVE_PLATFORM = "linux/amd64"
X86_TARGET_DIR = ROOT / "target/portable-x86_64-musl"
AARCH64_CROSS_TARGET_DIR = ROOT / "target/cross-aarch64-musl"
AARCH64_NATIVE_TARGET_DIR = ROOT / "target/portable-aarch64-native-musl"
CROSS_IMAGE = (
    "ghcr.io/cross-rs/aarch64-unknown-linux-musl@"
    "sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83"
)
NATIVE_CONTAINER_DOCKERFILE = ROOT / "docker/alpine/portable_builder.Dockerfile"
NATIVE_CONTAINER_MARKER = "PKTHERE_PORTABLE_NATIVE_CONTAINER"
NATIVE_CONTAINER_RUSTFLAGS = (
    "-C linker=clang "
    "-C link-arg=-fuse-ld=lld "
    "-C link-arg=-Wno-unused-command-line-argument "
    "-C target-feature=+crt-static "
    "-C target-cpu=generic"
)
Aarch64Backend = Literal["auto", "cross", "native-container"]
X86Backend = Literal["host", "native-container"]
STAGED_EXECUTABLE_NAMES = {
    "pkthere": "pkthere",
    "pkthere_authority_audit": "pkthere-authority-audit",
    "socket_reality": "socket-reality-test",
    "icmp_integration": "icmp-integration-test",
    "worker_modes": "worker-modes-test",
    "pkthere_test_support": "pkthere-test-support-test",
    "pkthere_unit_test": "pkthere-unit-test",
    "stress": "stress-test",
    "topology-verifier": "topology-verifier",
}


def verify_static_elf(
    binary: Path,
    expected_machine: str,
    evidence_prefix: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    evidence_prefix.parent.mkdir(parents=True, exist_ok=True)
    file_result = _recorded_command(
        ["file", str(binary)],
        evidence_prefix.with_name(f"{evidence_prefix.name}-file"),
        runner=runner,
        environment=environment,
        timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
    )
    header = _recorded_command(
        ["readelf", "-hW", str(binary)],
        evidence_prefix.with_name(f"{evidence_prefix.name}-elf-header"),
        runner=runner,
        environment=environment,
        timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
    )
    program_headers = _recorded_command(
        ["readelf", "-lW", str(binary)],
        evidence_prefix.with_name(f"{evidence_prefix.name}-program-headers"),
        runner=runner,
        environment=environment,
        timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
    )
    dynamic = _recorded_command(
        ["readelf", "-dW", str(binary)],
        evidence_prefix.with_name(f"{evidence_prefix.name}-dynamic"),
        runner=runner,
        environment=environment,
        timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
    )

    machine_match = re.search(r"^\s*Machine:\s*(.+?)\s*$", header.stdout, re.MULTILINE)
    actual_machine = machine_match.group(1) if machine_match is not None else None
    if actual_machine != expected_machine:
        raise RuntimeError(
            f"expected ELF machine {expected_machine!r}, found {actual_machine!r}"
        )
    if re.search(r"(?:^|\s)INTERP(?:\s|$)", program_headers.stdout):
        raise RuntimeError("portable musl artifact contains a PT_INTERP entry")
    if "(NEEDED)" in dynamic.stdout:
        raise RuntimeError("portable musl artifact contains a DT_NEEDED dependency")
    if not re.search(r"statically linked|static-pie linked", file_result.stdout):
        raise RuntimeError(
            "file did not identify the portable musl artifact as static or static PIE"
        )


def build_x86_64(
    evidence_dir: Path,
    output: Path,
    *,
    runner: CommandRunner,
    source_environment: Mapping[str, str],
    backend: X86Backend = "host",
) -> None:
    environment = _portable_environment(source_environment, evidence_dir)
    inside_native_container = environment.get(NATIVE_CONTAINER_MARKER) == "1"
    if backend == "native-container" and not inside_native_container:
        _run_native_container(
            "x86_64",
            X86_NATIVE_PLATFORM,
            evidence_dir,
            output,
            runner=runner,
            environment=environment,
        )
        return
    toolchain: tuple[tuple[str, ...], ...]
    if inside_native_container and backend == "native-container":
        environment["RUSTFLAGS"] = NATIVE_CONTAINER_RUSTFLAGS
        environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"] = "clang"
        _require_tools(("cargo", "rustc", "clang", "file", "readelf"), environment)
        toolchain = (
            ("rustc", "-vV"),
            ("cargo", "-V"),
            ("clang", "--version"),
        )
    else:
        _require_tools(("cargo", "rustc", "musl-gcc", "file", "readelf"), environment)
        toolchain = (
            ("rustc", "-vV"),
            ("cargo", "-V"),
            ("musl-gcc", "--version"),
        )
    _record_toolchain(
        toolchain,
        evidence_dir,
        runner=runner,
        environment=environment,
    )
    executables = _build_alpine_executables_with_cache(
        X86_TARGET,
        ("cargo",),
        evidence_dir,
        runner=runner,
        environment=environment,
        target_dir=X86_TARGET_DIR,
    )
    _stage_alpine_executables(
        executables,
        output,
        expected_machine="Advanced Micro Devices X86-64",
        evidence_name="x86_64-musl",
        evidence_dir=evidence_dir,
        runner=runner,
        environment=environment,
    )


def _build_alpine_executables(
    target: str | None,
    cargo_command: Sequence[str],
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
    target_dir: Path | None = None,
    container_target_dir: Path | None = None,
) -> dict[str, Path]:
    common = ["--locked", "--release"]
    if target is not None:
        common[1:1] = ["--target", target]
    if target_dir is not None:
        common.extend(("--target-dir", str(target_dir)))
    executables: dict[str, Path] = {}
    production = cargo_executables(
        ["build", *common, "-p", "pkthere", "--bin", "pkthere"],
        {"pkthere"},
        root=ROOT,
        runner=runner,
        environment=environment,
        cargo_command=cargo_command,
        evidence_prefix=evidence_dir / "cargo-build-pkthere",
        container_target_dir=container_target_dir,
    )
    preserved_dir = evidence_dir / "staged-executables"
    preserved_dir.mkdir(parents=True, exist_ok=True)
    preserved_production = preserved_dir / "pkthere-production"
    shutil.copy2(production["pkthere"], preserved_production)
    executables["pkthere"] = preserved_production
    pkthere_unit_test = cargo_executables(
        [
            "test",
            *common,
            "-p",
            "pkthere",
            "--bin",
            "pkthere",
            "--no-run",
        ],
        {"pkthere"},
        root=ROOT,
        runner=runner,
        environment=environment,
        cargo_command=cargo_command,
        evidence_prefix=evidence_dir / "cargo-test-pkthere-unit",
        container_target_dir=container_target_dir,
    )
    executables["pkthere_unit_test"] = pkthere_unit_test["pkthere"]
    executables.update(
        cargo_executables(
            [
                "test",
                *common,
                "-p",
                "pkthere",
                "--test",
                "socket_reality",
                "--test",
                "icmp_integration",
                "--test",
                "worker_modes",
                "--no-run",
            ],
            {"socket_reality", "icmp_integration", "worker_modes"},
            root=ROOT,
            runner=runner,
            environment=environment,
            cargo_command=cargo_command,
            evidence_prefix=evidence_dir / "cargo-test-integration-artifacts",
            container_target_dir=container_target_dir,
        )
    )
    audited_app = cargo_executables(
        [
            "build",
            *common,
            "--features",
            "authority-audit",
            "-p",
            "pkthere",
            "--bin",
            "pkthere",
        ],
        {"pkthere"},
        root=ROOT,
        runner=runner,
        environment=environment,
        cargo_command=cargo_command,
        evidence_prefix=evidence_dir / "cargo-build-pkthere-authority-audit",
        container_target_dir=container_target_dir,
    )
    preserved_audited_app = preserved_dir / "pkthere-authority-audit"
    shutil.copy2(audited_app["pkthere"], preserved_audited_app)
    executables["pkthere_authority_audit"] = preserved_audited_app
    executables.update(
        cargo_executables(
            [
                "test",
                *common,
                "--features",
                "authority-audit",
                "-p",
                "pkthere",
                "--test",
                "stress",
                "--no-run",
            ],
            {"stress"},
            root=ROOT,
            runner=runner,
            environment=environment,
            cargo_command=cargo_command,
            evidence_prefix=evidence_dir / "cargo-test-authority-stress",
            container_target_dir=container_target_dir,
        )
    )
    executables.update(
        cargo_executables(
            [
                "test",
                *common,
                "-p",
                "pkthere-test-support",
                "--lib",
                "--no-run",
            ],
            {"pkthere_test_support"},
            root=ROOT,
            runner=runner,
            environment=environment,
            cargo_command=cargo_command,
            evidence_prefix=evidence_dir / "cargo-test-support-unit",
            container_target_dir=container_target_dir,
        )
    )
    executables.update(
        cargo_executables(
            [
                "build",
                *common,
                "-p",
                "pkthere-test-support",
                "--bin",
                "topology-verifier",
            ],
            {"topology-verifier"},
            root=ROOT,
            runner=runner,
            environment=environment,
            cargo_command=cargo_command,
            evidence_prefix=evidence_dir / "cargo-build-topology-verifier",
            container_target_dir=container_target_dir,
        )
    )
    return executables


def _build_alpine_executables_with_cache(
    target: str | None,
    cargo_command: Sequence[str],
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
    target_dir: Path,
    container_target_dir: Path | None = None,
) -> dict[str, Path]:
    with _exclusive_file_lock(
        target_dir / ".pkthere-source-cache.lock",
        timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
    ):
        cache_identity = target_cache_identity(target, cargo_command, environment)
        state_path, current_inputs, refresh = prepare_source_aware_target_cache(
            ROOT,
            target_dir,
            cache_identity,
        )
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "source-cache-refresh.json").write_text(
            json.dumps(refresh, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        executables = _build_alpine_executables(
            target,
            cargo_command,
            evidence_dir,
            runner=runner,
            environment=environment,
            target_dir=target_dir,
            container_target_dir=container_target_dir,
        )
        commit_source_aware_target_cache(
            state_path,
            current_inputs,
            cache_identity,
        )
        return executables


def _stage_alpine_executables(
    executables: Mapping[str, Path],
    output: Path,
    *,
    expected_machine: str,
    evidence_name: str,
    evidence_dir: Path,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    for name, destination_name in STAGED_EXECUTABLE_NAMES.items():
        source = executables[name]
        if not source.is_absolute():
            source = ROOT / source
        destination = output / destination_name
        shutil.copy2(source, destination)
        destination.chmod(0o755)
        verify_static_elf(
            destination,
            expected_machine,
            evidence_dir / f"{evidence_name}-{destination_name}",
            runner=runner,
            environment=environment,
        )


def build_aarch64(
    evidence_dir: Path,
    output: Path,
    *,
    runner: CommandRunner,
    source_environment: Mapping[str, str],
    backend: Aarch64Backend = "cross",
) -> None:
    environment = _portable_environment(source_environment, evidence_dir)
    inside_native_container = environment.get(NATIVE_CONTAINER_MARKER) == "1"
    selected_backend = (
        "native-container"
        if inside_native_container and backend == "native-container"
        else _select_aarch64_backend(
            backend,
            evidence_dir,
            runner=runner,
            environment=environment,
        )
    )
    if selected_backend == "native-container":
        if inside_native_container:
            _build_aarch64_in_native_container(
                evidence_dir,
                output,
                runner=runner,
                environment=environment,
            )
        else:
            _run_native_container(
                "aarch64",
                AARCH64_NATIVE_PLATFORM,
                evidence_dir,
                output,
                runner=runner,
                environment=environment,
            )
        return

    _build_aarch64_with_cross(
        evidence_dir,
        output,
        runner=runner,
        environment=environment,
    )


def _select_aarch64_backend(
    requested: Aarch64Backend,
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> Literal["cross", "native-container"]:
    if requested == "cross":
        return "cross"

    architecture = _docker_server_architecture(
        evidence_dir,
        runner=runner,
        environment=environment,
    )
    native = architecture in {"aarch64", "arm64"}
    if requested == "native-container" and not native:
        raise RuntimeError(
            "native-container AArch64 builds require an AArch64 Docker server; "
            f"found {architecture!r}"
        )
    return "native-container" if native else "cross"


def _docker_server_architecture(
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> str:
    _require_tools(("docker",), environment)
    result = _recorded_command(
        ["docker", "version", "--format", "{{.Server.Arch}}"],
        evidence_dir / "docker-server-architecture",
        runner=runner,
        environment=environment,
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
    )
    architecture = result.stdout.strip().lower()
    if not architecture:
        raise RuntimeError("Docker did not report its server architecture")
    return architecture


def _build_aarch64_with_cross(
    evidence_dir: Path,
    output: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    _require_tools(
        ("cargo", "cross", "docker", "file", "readelf", "rustc"), environment
    )
    _recorded_command(
        ["docker", "pull", CROSS_IMAGE],
        evidence_dir / "cross-image-pull",
        runner=runner,
        environment=environment,
        timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
    )
    _record_toolchain(
        (
            ("rustc", "-vV"),
            ("cargo", "-V"),
            ("cross", "--version"),
            ("docker", "version"),
            (
                "docker",
                "image",
                "inspect",
                CROSS_IMAGE,
                "--format",
                "{{json .RepoDigests}}",
            ),
        ),
        evidence_dir,
        runner=runner,
        environment=environment,
    )
    executables = _build_alpine_executables_with_cache(
        AARCH64_TARGET,
        ("cross",),
        evidence_dir,
        runner=runner,
        environment=environment,
        target_dir=AARCH64_CROSS_TARGET_DIR,
        container_target_dir=AARCH64_CROSS_TARGET_DIR,
    )
    _stage_alpine_executables(
        executables,
        output,
        expected_machine="AArch64",
        evidence_name="aarch64-musl",
        evidence_dir=evidence_dir,
        runner=runner,
        environment=environment,
    )


def _run_native_container(
    architecture: str,
    platform_name: str,
    evidence_dir: Path,
    output: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=f"pkthere-{architecture}-native-"
    ) as temporary:
        export_root = Path(temporary)
        _recorded_command(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                platform_name,
                "--build-arg",
                f"PORTABLE_ARCHITECTURE={architecture}",
                "--file",
                str(NATIVE_CONTAINER_DOCKERFILE.relative_to(ROOT)),
                "--target",
                "export",
                "--output",
                f"type=local,dest={export_root}",
                ".",
            ],
            evidence_dir / "native-container-build",
            runner=runner,
            environment=environment,
            timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
        )
        exported_artifacts = export_root / "alpine"
        exported_evidence = export_root / "evidence"
        if not exported_artifacts.is_dir() or not exported_evidence.is_dir():
            raise RuntimeError(
                f"native {architecture} container did not export Alpine artifacts and evidence"
            )
        _replace_directory(exported_artifacts, output)
        shutil.copytree(exported_evidence, evidence_dir, dirs_exist_ok=True)


def _build_aarch64_in_native_container(
    evidence_dir: Path,
    output: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    machine = platform.machine().lower()
    if platform.system() != "Linux" or machine not in {"aarch64", "arm64"}:
        raise RuntimeError(
            "native-container inner build requires AArch64 Linux; "
            f"found {platform.system()} {machine}"
        )
    native_environment = dict(environment)
    native_environment["RUSTFLAGS"] = NATIVE_CONTAINER_RUSTFLAGS
    _require_tools(
        ("cargo", "clang", "file", "readelf", "rustc"),
        native_environment,
    )
    _record_toolchain(
        (
            ("rustc", "-vV"),
            ("cargo", "-V"),
            ("clang", "--version"),
        ),
        evidence_dir,
        runner=runner,
        environment=native_environment,
    )
    executables = _build_alpine_executables_with_cache(
        AARCH64_TARGET,
        ("cargo",),
        evidence_dir,
        runner=runner,
        environment=native_environment,
        target_dir=AARCH64_NATIVE_TARGET_DIR,
    )
    _stage_alpine_executables(
        executables,
        output,
        expected_machine="AArch64",
        evidence_name="aarch64-native-musl",
        evidence_dir=evidence_dir,
        runner=runner,
        environment=native_environment,
    )


def _replace_directory(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    token = f"{os.getpid()}-{uuid.uuid4().hex}"
    staging = destination.parent / f".{destination.name}.staging-{token}"
    backup = destination.parent / f".{destination.name}.backup-{token}"
    lock_path = destination.parent / f".{destination.name}.publish.lock"
    shutil.copytree(source, staging)
    try:
        with _exclusive_file_lock(lock_path):
            if destination.exists():
                os.replace(destination, backup)
            try:
                os.replace(staging, destination)
            except BaseException:
                if backup.exists() and not destination.exists():
                    os.replace(backup, destination)
                raise
            if backup.exists():
                shutil.rmtree(backup)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup.exists():
            shutil.rmtree(backup)


@contextmanager
def _exclusive_file_lock(
    path: Path,
    timeout_seconds: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
) -> Generator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    with path.open("a+b") as lock_file:
        if os.name == "nt":
            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
        while True:
            try:
                _set_file_lock(lock_file, acquire=True)
                break
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"timed out publishing portable artifacts through {path}"
                    ) from error
                time.sleep(0.05)
        try:
            yield
        finally:
            _set_file_lock(lock_file, acquire=False)


def _set_file_lock(lock_file: BinaryIO, *, acquire: bool) -> None:
    if os.name == "nt":
        module = importlib.import_module("msvcrt")
        locking = cast(
            Callable[[int, int, int], None],
            module.locking,
        )
        mode_name = "LK_NBLCK" if acquire else "LK_UNLCK"
        mode = cast(int, getattr(module, mode_name))
        lock_file.seek(0)
        locking(lock_file.fileno(), mode, 1)
        return

    module = importlib.import_module("fcntl")
    flock = cast(Callable[[int, int], None], module.flock)
    exclusive = cast(int, module.LOCK_EX)
    nonblocking = cast(int, module.LOCK_NB)
    unlock = cast(int, module.LOCK_UN)
    flock(lock_file.fileno(), exclusive | nonblocking if acquire else unlock)


def _portable_environment(
    source: Mapping[str, str], evidence_dir: Path
) -> dict[str, str]:
    environment, removed = sanitize_environment(source)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    rendered = "".join(f"portable build: cleared {name}\n" for name in removed)
    (evidence_dir / "sanitized-environment.txt").write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return environment


def _require_tools(tools: Sequence[str], environment: Mapping[str, str]) -> None:
    path = environment.get("PATH")
    for tool in tools:
        if shutil.which(tool, path=path) is None:
            raise RuntimeError(f"portable build requires {tool!r} in PATH")


def _record_toolchain(
    commands: Sequence[Sequence[str]],
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    output: list[str] = []
    for index, command in enumerate(commands):
        result = _recorded_command(
            command,
            evidence_dir / f"toolchain-{index}",
            runner=runner,
            environment=environment,
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        output.extend((result.stdout, result.stderr))
    (evidence_dir / "toolchain.txt").write_text("".join(output), encoding="utf-8")


def _recorded_command(
    command: Sequence[str],
    evidence_prefix: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> CommandResult:
    completed = runner.run(
        command,
        timeout_seconds=timeout_seconds,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
    )
    evidence_prefix.parent.mkdir(parents=True, exist_ok=True)
    evidence_prefix.with_suffix(".out").write_text(completed.stdout, encoding="utf-8")
    evidence_prefix.with_suffix(".err").write_text(completed.stderr, encoding="utf-8")
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            completed.argv,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="architecture", required=True)
    x86 = subparsers.add_parser("x86_64")
    x86.add_argument("--evidence-dir", type=Path, required=True)
    x86.add_argument("--output", type=Path, default=DEFAULT_STAGE)
    x86.add_argument("--require-clean-source", action="store_true")
    x86.add_argument(
        "--backend",
        choices=("host", "native-container"),
        default="host",
    )
    arm = subparsers.add_parser("aarch64")
    arm.add_argument("--evidence-dir", type=Path, required=True)
    arm.add_argument("--output", type=Path, default=DEFAULT_STAGE)
    arm.add_argument("--require-clean-source", action="store_true")
    arm.add_argument(
        "--backend",
        choices=("auto", "cross", "native-container"),
        default="auto",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    runner = CommandRunner()
    evidence_dir = args.evidence_dir.resolve()
    output = args.output.resolve()
    source_evidence: dict[str, object] = {}
    if os.environ.get(NATIVE_CONTAINER_MARKER) != "1":
        source_evidence = record_source_provenance(
            ROOT,
            evidence_dir,
            runner=runner,
            environment=os.environ,
        )
        if args.require_clean_source and source_evidence["dirty_worktree"]:
            raise RuntimeError(
                "release artifact build requires a clean source tree; "
                "dirty worktrees are development evidence only"
            )
    if args.architecture == "x86_64":
        build_x86_64(
            evidence_dir,
            output,
            runner=runner,
            source_environment=os.environ,
            backend=args.backend,
        )
        target = X86_TARGET
        builder = args.backend
    else:
        build_aarch64(
            evidence_dir,
            output,
            runner=runner,
            source_environment=os.environ,
            backend=args.backend,
        )
        target = AARCH64_TARGET
        builder = args.backend
    if source_evidence:
        selections = (
            *PRIVILEGED_ICMP_TESTS,
            RAW_SOCKET_REALITY_TEST,
            *ALPINE_CONCURRENCY_TESTS,
        )
        artifact_evidence = {
            path.name: sha256_file(path)
            for path in sorted(output.iterdir())
            if path.is_file()
        }
        manifest = {
            **source_evidence,
            "artifact_sha256": artifact_evidence,
            "builder_identity": builder,
            "evidence_ids": [selection.evidence_id for selection in selections],
            "selected_test_count": len(selections),
            "target_triple": target,
        }
        (evidence_dir / "portable-artifact-evidence.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
