"""Authoritative portable artifact build, staging, and ELF verification."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import fnmatch
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Literal

from docker.alpine.pkthere_harness.cargo import cargo_executables
from docker.alpine.pkthere_harness.command_runner import CommandResult, CommandRunner
from docker.alpine.pkthere_harness.timing import (
    ARTIFACT_BUILD_TIMEOUT_SECONDS,
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    VERIFIER_TIMEOUT_SECONDS,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STAGE = ROOT / ".artifacts/alpine"
X86_TARGET = "x86_64-unknown-linux-musl"
AARCH64_TARGET = "aarch64-unknown-linux-musl"
AARCH64_NATIVE_PLATFORM = "linux/arm64"
CROSS_IMAGE = (
    "ghcr.io/cross-rs/aarch64-unknown-linux-musl@"
    "sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83"
)
NATIVE_CONTAINER_DOCKERFILE = ROOT / "docker/alpine/portable_builder.Dockerfile"
NATIVE_CONTAINER_MARKER = "PKTHERE_PORTABLE_NATIVE_CONTAINER"
NATIVE_CONTAINER_RUSTFLAGS = (
    "-C linker=clang "
    "-C link-arg=-fuse-ld=lld "
    "-C target-feature=+crt-static "
    "-C relocation-model=pic "
    "-C link-arg=-static-pie "
    "-C link-arg=-Wl,--eh-frame-hdr "
    "-C target-cpu=generic"
)
Aarch64Backend = Literal["auto", "cross", "native-container"]
STAGED_EXECUTABLE_NAMES = {
    "pkthere": "pkthere",
    "socket_reality": "socket-reality-test",
    "icmp_integration": "icmp-integration-test",
    "worker_modes": "worker-modes-test",
    "pkthere_test_support": "pkthere-test-support-test",
    "pkthere_unit_test": "pkthere-unit-test",
    "topology-verifier": "topology-verifier",
}
_EXACT_BUILD_VARIABLES = frozenset(
    {
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_RUSTDOCFLAGS",
        "CARGO_BUILD_TARGET",
        "CC",
        "CXX",
        "AR",
        "CFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "HOST_CC",
        "HOST_CXX",
        "HOST_AR",
        "HOST_CFLAGS",
        "HOST_CXXFLAGS",
        "HOST_LDFLAGS",
        "TARGET_CC",
        "TARGET_CXX",
        "TARGET_AR",
        "TARGET_CFLAGS",
        "TARGET_CXXFLAGS",
        "TARGET_LDFLAGS",
    }
)
_BUILD_VARIABLE_PATTERNS = (
    "CARGO_TARGET_*_RUSTFLAGS",
    "CARGO_TARGET_*_RUSTDOCFLAGS",
    "CARGO_TARGET_*_LINKER",
    "CARGO_TARGET_*_RUNNER",
    "CC_*",
    "CXX_*",
    "AR_*",
    "CFLAGS_*",
    "CXXFLAGS_*",
    "LDFLAGS_*",
)


def sanitize_environment(
    source: Mapping[str, str],
) -> tuple[dict[str, str], tuple[str, ...]]:
    environment = dict(source)
    removed = tuple(
        sorted(
            name
            for name in environment
            if name in _EXACT_BUILD_VARIABLES
            or any(
                fnmatch.fnmatchcase(name, pattern)
                for pattern in _BUILD_VARIABLE_PATTERNS
            )
        )
    )
    for name in removed:
        del environment[name]
    return environment, removed


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
) -> None:
    environment = _portable_environment(source_environment, evidence_dir)
    _require_tools(("cargo", "rustc", "musl-gcc", "file", "readelf"), environment)
    _record_toolchain(
        (
            ("rustc", "-vV"),
            ("cargo", "-V"),
            ("musl-gcc", "--version"),
        ),
        evidence_dir,
        runner=runner,
        environment=environment,
    )
    executables = _build_alpine_executables(
        X86_TARGET,
        ("cargo",),
        evidence_dir,
        runner=runner,
        environment=environment,
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
    executables.update(
        cargo_executables(
            ["build", *common, "-p", "pkthere", "--bin", "pkthere"],
            {"pkthere"},
            root=ROOT,
            runner=runner,
            environment=environment,
            cargo_command=cargo_command,
            evidence_prefix=evidence_dir / "cargo-build-pkthere",
            container_target_dir=container_target_dir,
        )
    )
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
            _run_aarch64_native_container(
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
    cross_target_dir = ROOT / "target/cross-aarch64-musl"
    executables = _build_alpine_executables(
        AARCH64_TARGET,
        ("cross",),
        evidence_dir,
        runner=runner,
        environment=environment,
        target_dir=cross_target_dir,
        container_target_dir=cross_target_dir,
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


def _run_aarch64_native_container(
    evidence_dir: Path,
    output: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> None:
    with tempfile.TemporaryDirectory(prefix="pkthere-aarch64-native-") as temporary:
        export_root = Path(temporary)
        _recorded_command(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                AARCH64_NATIVE_PLATFORM,
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
                "native AArch64 container did not export Alpine artifacts and evidence"
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
    executables = _build_alpine_executables(
        None,
        ("cargo",),
        evidence_dir,
        runner=runner,
        environment=native_environment,
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
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination)


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
    arm = subparsers.add_parser("aarch64")
    arm.add_argument("--evidence-dir", type=Path, required=True)
    arm.add_argument("--output", type=Path, default=DEFAULT_STAGE)
    arm.add_argument(
        "--backend",
        choices=("auto", "cross", "native-container"),
        default="auto",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    runner = CommandRunner()
    if args.architecture == "x86_64":
        build_x86_64(
            args.evidence_dir.resolve(),
            args.output.resolve(),
            runner=runner,
            source_environment=os.environ,
        )
    else:
        build_aarch64(
            args.evidence_dir.resolve(),
            args.output.resolve(),
            runner=runner,
            source_environment=os.environ,
            backend=args.backend,
        )


if __name__ == "__main__":
    main()
