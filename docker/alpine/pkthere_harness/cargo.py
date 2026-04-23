"""Cargo JSON artifact discovery shared by CI and portable artifact staging."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
from pathlib import Path
import sys

from .command_runner import CommandRunner
from .timing import ARTIFACT_BUILD_TIMEOUT_SECONDS


def cargo_executables(
    arguments: Sequence[str],
    target_names: set[str],
    *,
    root: Path,
    runner: CommandRunner,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Path]:
    if "--locked" not in arguments:
        raise ValueError("portable and CI Cargo invocations must use --locked")
    command = ["cargo", *arguments, "--message-format=json-render-diagnostics"]
    completed = runner.run(
        command,
        timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
    )
    messages = cargo_messages(completed.stdout)
    sys.stderr.write(completed.stderr)
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
            found[name] = Path(executable)

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


def cargo_messages(output: str) -> list[dict[str, object]]:
    messages: list[dict[str, object]] = []
    for line in output.splitlines():
        value: object = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("Cargo emitted a JSON value that was not an object")
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
