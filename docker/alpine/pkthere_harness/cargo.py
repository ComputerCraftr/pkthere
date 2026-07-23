"""Cargo JSON artifact discovery shared by CI and portable artifact staging."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
from pathlib import Path
import re
import sys

from .command_runner import CommandRunner
from .timing import ARTIFACT_BUILD_TIMEOUT_SECONDS

_RUSTUP_TOOLCHAIN_STATUS = re.compile(
    r"\s*(?:stable|beta|nightly)(?:-[A-Za-z0-9_.-]+)?\s+"
    r"(?:installed|unchanged|updated)\s+-\s+.+"
)


def cargo_executables(
    arguments: Sequence[str],
    target_names: set[str],
    *,
    root: Path,
    runner: CommandRunner,
    environment: Mapping[str, str] | None = None,
    cargo_command: Sequence[str] = ("cargo",),
    evidence_prefix: Path | None = None,
    container_target_dir: Path | None = None,
) -> dict[str, Path]:
    if "--locked" not in arguments:
        raise ValueError("portable and CI Cargo invocations must use --locked")
    if not cargo_command:
        raise ValueError("Cargo command must not be empty")
    command = [
        *cargo_command,
        *arguments,
        "--message-format=json-render-diagnostics",
    ]
    completed = runner.run(
        command,
        timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
    )
    if evidence_prefix is not None:
        evidence_prefix.parent.mkdir(parents=True, exist_ok=True)
        evidence_prefix.with_suffix(".out").write_text(
            completed.stdout, encoding="utf-8"
        )
        evidence_prefix.with_suffix(".err").write_text(
            completed.stderr, encoding="utf-8"
        )
    sys.stderr.write(completed.stderr)
    if "Falling back to `cargo` on the host." in (completed.stdout + completed.stderr):
        raise RuntimeError(
            "Cross refused container execution and attempted host Cargo; "
            f"command was {' '.join(command)}"
        )
    try:
        messages = cargo_messages(
            completed.stdout,
            allow_rustup_status=Path(cargo_command[0]).name == "cross",
        )
    except ValueError as error:
        raise RuntimeError(
            f"{' '.join(command)} emitted invalid Cargo JSON: {error}"
        ) from error
    if completed.returncode != 0:
        for diagnostic in rendered_diagnostics(messages):
            sys.stderr.write(diagnostic)
        raise RuntimeError(
            f"{' '.join(command)} exited with status {completed.returncode}"
        )

    found: dict[str, Path] = {}
    for message in messages:
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        executable = message.get("executable")
        if not isinstance(target, dict) or not isinstance(executable, str):
            continue
        name = target.get("name")
        if isinstance(name, str) and name in target_names:
            executable_path = Path(executable)
            if container_target_dir is not None:
                try:
                    relative = executable_path.relative_to("/target")
                except ValueError:
                    pass
                else:
                    executable_path = container_target_dir / relative
            found[name] = executable_path

    missing = target_names.difference(found)
    if missing:
        raise RuntimeError(f"Cargo omitted requested executables: {sorted(missing)}")
    return found


def resolve_test_executable(
    package: str,
    test_name: str,
    *,
    root: Path,
    runner: CommandRunner,
) -> Path:
    executables = cargo_executables(
        [
            "test",
            "--locked",
            "-p",
            package,
            "--test",
            test_name,
            "--no-run",
        ],
        {test_name},
        root=root,
        runner=runner,
    )
    return executables[test_name]


def cargo_messages(
    output: str,
    *,
    allow_rustup_status: bool = False,
) -> list[dict[str, object]]:
    messages: list[dict[str, object]] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        if allow_rustup_status and _RUSTUP_TOOLCHAIN_STATUS.fullmatch(line):
            continue
        try:
            value: object = json.loads(line)
        except json.JSONDecodeError as error:
            preview = line if len(line) <= 200 else f"{line[:197]}..."
            raise ValueError(f"line {line_number} was not JSON: {preview!r}") from error
        if not isinstance(value, dict):
            raise ValueError(
                f"line {line_number} was a JSON value that was not an object"
            )
        messages.append({str(key): item for key, item in value.items()})
    return messages


def rendered_diagnostics(messages: Iterable[dict[str, object]]) -> Iterable[str]:
    for message in messages:
        compiler_message = message.get("message")
        if not isinstance(compiler_message, dict):
            continue
        rendered = compiler_message.get("rendered")
        if isinstance(rendered, str):
            yield rendered
