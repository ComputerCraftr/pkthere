"""Canonical command plans for all repository CI profiles."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .ci_tool_versions import load_ci_tool_versions
from .timing import ARTIFACT_BUILD_TIMEOUT_SECONDS

WORKSPACE_TARGETS = ("--workspace", "--lib", "--bins", "--tests")
WORKSPACE_CHECK_COMMAND = (
    "cargo",
    "check",
    "--locked",
    "--workspace",
    "--all-targets",
)
AUTHORITY_PROFILE_NAME = "release-debug"
AUTHORITY_PROFILE = ("--profile", AUTHORITY_PROFILE_NAME, "-p", "pkthere")
AUTHORITY_FEATURE = ("--features", "authority-audit")
QUALITY_VENV_DIRECTORY = ".artifacts/quality-tools"


@dataclass(frozen=True)
class CommandSpec:
    label: str
    arguments: tuple[str, ...]
    timeout_seconds: float = ARTIFACT_BUILD_TIMEOUT_SECONDS


@dataclass(frozen=True)
class QualityInventory:
    rust: tuple[str, ...]
    python: tuple[str, ...]
    toml: tuple[str, ...]
    shell: tuple[str, ...]


def workspace_test_command(*, list_only: bool = False) -> tuple[str, ...]:
    test_arguments = ("--list",) if list_only else ("--nocapture",)
    return (
        "cargo",
        "test",
        "--locked",
        "--no-fail-fast",
        *WORKSPACE_TARGETS,
        "--",
        *test_arguments,
    )


def msrv_commands() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            "Check locked workspace at MSRV",
            WORKSPACE_CHECK_COMMAND,
        ),
        CommandSpec("Test locked workspace at MSRV", workspace_test_command()),
    )


def miri_setup_commands(root: Path) -> tuple[CommandSpec, ...]:
    toolchain = load_ci_tool_versions(root).miri_toolchain
    return (
        CommandSpec(
            "Prepare Miri",
            ("cargo", f"+{toolchain}", "miri", "setup"),
        ),
    )


def aarch64_musl_commands(root: Path) -> tuple[CommandSpec, ...]:
    tools = load_ci_tool_versions(root)
    return (
        CommandSpec(
            "Install pinned cross",
            (
                "cargo",
                "install",
                "cross",
                "--git",
                "https://github.com/cross-rs/cross",
                "--rev",
                tools.cross_revision,
                "--locked",
            ),
        ),
        CommandSpec(
            "Build and inspect AArch64 musl artifact",
            (
                sys.executable,
                "-m",
                "docker.alpine.portable_build",
                "aarch64",
                "--backend",
                "cross",
                "--require-clean-source",
                "--evidence-dir",
                "cross-artifacts",
                "--output",
                "cross-artifacts/alpine",
            ),
        ),
    )


def alpine_build_commands() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            "Refresh package metadata for musl tools",
            ("sudo", "apt-get", "update"),
        ),
        CommandSpec(
            "Install musl linker",
            ("sudo", "apt-get", "install", "--yes", "musl-tools"),
        ),
        CommandSpec(
            "Build exact Alpine executables",
            (
                sys.executable,
                "-m",
                "docker.alpine.portable_build",
                "x86_64",
                "--require-clean-source",
                "--evidence-dir",
                "docker-artifacts",
            ),
        ),
    )


def alpine_runtime_commands() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            "Run privileged Alpine profiles",
            (
                sys.executable,
                "-m",
                "docker.alpine.ci",
                "all",
                "--artifact-dir",
                "docker-artifacts",
            ),
        ),
    )


def authority_build_arguments(*, tests: bool) -> tuple[str, ...]:
    operation = "test" if tests else "build"
    target = ("--bin", "pkthere", "--no-run") if tests else ("--bin", "pkthere")
    return (
        operation,
        "--locked",
        *AUTHORITY_PROFILE,
        *AUTHORITY_FEATURE,
        *target,
    )


def authority_stress_build_arguments() -> tuple[str, ...]:
    return (
        "test",
        "--locked",
        *AUTHORITY_PROFILE,
        *AUTHORITY_FEATURE,
        "--test",
        "stress",
        "--no-run",
    )


def authority_test_command(*, skipped_tests: tuple[str, ...] = ()) -> tuple[str, ...]:
    skip_arguments = tuple(
        argument for test_name in skipped_tests for argument in ("--skip", test_name)
    )
    return (
        "cargo",
        "test",
        "--locked",
        *AUTHORITY_PROFILE,
        *AUTHORITY_FEATURE,
        "--bin",
        "pkthere",
        "--",
        "--nocapture",
        *skip_arguments,
    )


def release_stress_commands() -> tuple[CommandSpec, ...]:
    prefix = (
        "cargo",
        "test",
        "--locked",
        *AUTHORITY_PROFILE,
        *AUTHORITY_FEATURE,
        "--test",
        "stress",
    )
    return (
        CommandSpec("Build release authority stress target", (*prefix, "--no-run")),
        CommandSpec(
            "Execute release authority stress owner",
            (
                *prefix,
                "stress_test_ipv4",
                "--",
                "--exact",
                "--ignored",
                "--nocapture",
            ),
        ),
    )


def quality_commands(
    root: Path, inventory: QualityInventory
) -> tuple[CommandSpec, ...]:
    tools = load_ci_tool_versions(root)
    pipx = (_quality_venv_python(root), "-m", "pipx", "run")
    strict = (
        "-D",
        "warnings",
        "-D",
        "clippy::unwrap_used",
        "-D",
        "clippy::expect_used",
        "-D",
        "clippy::panic",
        "-D",
        "clippy::unreachable",
        "-D",
        "clippy::todo",
        "-D",
        "clippy::unimplemented",
    )
    commands = [
        CommandSpec(
            "Check Rust formatting", ("cargo", "fmt", "--all", "--", "--check")
        ),
        CommandSpec(
            "Check tracked Rust formatting inventory",
            ("rustfmt", "--check", "--edition", "2024", *inventory.rust),
        ),
        CommandSpec(
            "Check Rust workspace",
            WORKSPACE_CHECK_COMMAND,
        ),
        CommandSpec(
            "Check Rust lints",
            (
                "cargo",
                "clippy",
                "--locked",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ),
        ),
    ]
    for package, target in (
        ("pkthere", ("--bin", "pkthere")),
        ("pkthere-socket-policy", ("--lib",)),
        ("pkthere-wire", ("--lib",)),
    ):
        commands.append(
            CommandSpec(
                f"Deny production panic surfaces in {package}",
                (
                    "cargo",
                    "clippy",
                    "--locked",
                    "-p",
                    package,
                    *target,
                    "--all-features",
                    "--",
                    *strict,
                ),
            )
        )
    commands.extend(
        (
            CommandSpec(
                "Check Python formatting",
                (
                    *pipx,
                    f"ruff=={tools.ruff}",
                    "format",
                    "--check",
                    *inventory.python,
                ),
            ),
            CommandSpec(
                "Check Python lint",
                (
                    *pipx,
                    f"ruff=={tools.ruff}",
                    "check",
                    *inventory.python,
                ),
            ),
            CommandSpec(
                "Check Python types",
                (*pipx, f"mypy=={tools.mypy}", "--strict"),
            ),
            CommandSpec(
                "Check TOML formatting",
                ("taplo", "fmt", "--check", *inventory.toml),
            ),
            CommandSpec("Validate TOML", ("taplo", "check", *inventory.toml)),
            CommandSpec(
                "Check YAML formatting",
                (
                    "npx",
                    "--yes",
                    f"prettier@{tools.prettier}",
                    "--check",
                    "**/*.{yml,yaml}",
                ),
            ),
            CommandSpec("Check shell scripts", ("shellcheck", "-x", *inventory.shell)),
            CommandSpec(
                "Check shell formatting",
                (
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{root}:/work",
                    "-w",
                    "/work",
                    tools.shfmt_image,
                    "-d",
                    "-ci",
                    *inventory.shell,
                ),
            ),
            CommandSpec(
                "Enforce repository-wide source layout",
                (
                    "cargo",
                    "test",
                    "--locked",
                    "--test",
                    "policy",
                    "source_layout_policy_engine_is_self_consistent",
                    "--",
                    "--exact",
                    "--nocapture",
                ),
            ),
            CommandSpec(
                "Check workflow YAML style",
                (
                    *pipx,
                    f"yamllint=={tools.yamllint}",
                    "-d",
                    "{extends: default, rules: {line-length: disable, truthy: disable, document-start: disable}}",
                    ".github/workflows",
                ),
            ),
            CommandSpec(
                "Validate GitHub Actions semantics",
                (
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{root}:/repo",
                    "-w",
                    "/repo",
                    tools.actionlint_image,
                    "-color",
                ),
            ),
            CommandSpec(
                "Run Alpine harness unit tests",
                (
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "ci/tests",
                    "docker/alpine/tests",
                    "-v",
                ),
            ),
            CommandSpec(
                "Compile benchmarks without running them",
                ("cargo", "bench", "--locked", "--workspace", "--no-run"),
            ),
        )
    )
    return tuple(commands)


def quality_bootstrap_commands(root: Path) -> tuple[CommandSpec, ...]:
    tools = load_ci_tool_versions(root)
    quality_python = _quality_venv_python(root)
    return (
        CommandSpec(
            "Create isolated Python quality environment",
            (
                sys.executable,
                "-m",
                "venv",
                str(root / QUALITY_VENV_DIRECTORY),
            ),
        ),
        CommandSpec(
            "Install pinned Python check runner",
            (
                quality_python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                f"pipx=={tools.pipx}",
            ),
        ),
        CommandSpec(
            "Install pinned TOML formatter and validator",
            (
                "cargo",
                "install",
                "taplo-cli",
                "--version",
                tools.taplo_cli,
                "--locked",
            ),
        ),
    )


def _quality_venv_python(root: Path) -> str:
    executable = "python.exe" if sys.platform == "win32" else "python"
    directory = "Scripts" if sys.platform == "win32" else "bin"
    return str(root / QUALITY_VENV_DIRECTORY / directory / executable)
