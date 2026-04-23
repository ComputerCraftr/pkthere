"""Authoritative portable artifact build, staging, and ELF verification."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import fnmatch
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

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
CROSS_IMAGE = (
    "ghcr.io/cross-rs/aarch64-unknown-linux-musl@"
    "sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83"
)

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
    common = ["--locked", "--target", X86_TARGET, "--release"]
    executables: dict[str, Path] = {}
    executables.update(
        cargo_executables(
            ["build", *common, "-p", "pkthere", "--bin", "pkthere"],
            {"pkthere"},
            root=ROOT,
            runner=runner,
            environment=environment,
        )
    )
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
        )
    )

    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    destination_names = {
        "pkthere": "pkthere",
        "socket_reality": "socket-reality-test",
        "icmp_integration": "icmp-integration-test",
        "worker_modes": "worker-modes-test",
        "pkthere_test_support": "pkthere-test-support-test",
        "topology-verifier": "topology-verifier",
    }
    for name, destination_name in destination_names.items():
        source = executables[name]
        if not source.is_absolute():
            source = ROOT / source
        destination = output / destination_name
        shutil.copy2(source, destination)
        destination.chmod(0o755)
        verify_static_elf(
            destination,
            "Advanced Micro Devices X86-64",
            evidence_dir / f"x86_64-musl-{destination_name}",
            runner=runner,
            environment=environment,
        )


def build_aarch64(
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    source_environment: Mapping[str, str],
) -> None:
    environment = _portable_environment(source_environment, evidence_dir)
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
    _recorded_command(
        [
            "cross",
            "build",
            "--locked",
            "--release",
            "--target",
            AARCH64_TARGET,
            "-p",
            "pkthere",
            "--bin",
            "pkthere",
        ],
        evidence_dir / "cross-build",
        runner=runner,
        environment=environment,
        timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
    )
    verify_static_elf(
        ROOT / "target" / AARCH64_TARGET / "release/pkthere",
        "AArch64",
        evidence_dir / "aarch64-musl-pkthere",
        runner=runner,
        environment=environment,
    )


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
            runner=runner,
            source_environment=os.environ,
        )


if __name__ == "__main__":
    main()
