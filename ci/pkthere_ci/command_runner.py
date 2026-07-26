"""Bounded subprocess execution for repository CI tooling."""

from __future__ import annotations

import html
import os
import re
import signal
import subprocess
import sys
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .timing import COMMAND_TERMINATION_GRACE_SECONDS

WINDOWS_PROCESS_HOST = os.name == "nt"
MAX_CONSOLE_OUTPUT_CHARACTERS = 12_000
MAX_FAILURE_CONTEXT_LINES = 160
MAX_FAILURE_MARKERS = 40
_SUCCESS_SUMMARY_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:All checks passed!|Discovered |Finished |OK(?:$| )|Ran |Success:|running |test result:)[^\r\n]*"
)
_TEST_DETAIL_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:test (?!result:)|test_)[^\r\n]* \.\.\. [^\r\n]*$"
)
_PRIMARY_FAILURE_MARKER_PATTERN = re.compile(
    r"(?im)^(?:"
    r"[ \t]*(?:##\[error\]|error(?::|\[)|failures:|runtimeerror:|"
    r"test result:[ \t]*failed|traceback \(most recent call last\)|"
    r"pkthere-test-failure\b|[A-Z][0-9]{3}\b)[^\r\n]*"
    r"|[^\r\n]+:[0-9]+(?::[0-9]+)?:[ \t]*(?:error|fatal)\b[^\r\n]*"
    r"|[^\r\n]*[ \t]\.\.\.[ \t]+failed[ \t]*"
    r")$"
)
_SECONDARY_FAILURE_MARKER_PATTERN = re.compile(
    r"(?im)^[^\r\n]*(?:panicked at|assertion `|calledprocesserror)[^\r\n]*$"
)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandTimeoutError(RuntimeError):
    def __init__(self, result: CommandResult, timeout_seconds: float) -> None:
        self.result = result
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"command exceeded {timeout_seconds:.3f}s: {' '.join(result.argv)}\n"
            f"partial stdout:\n{result.stdout}\npartial stderr:\n{result.stderr}"
        )


class CommandRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        capture_output: bool = False,
        windows_restricted: bool = False,
    ) -> CommandResult:
        if windows_restricted:
            from .windows_restricted import run_restricted_windows

            return run_restricted_windows(
                command,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                env=env,
                check=check,
                capture_output=capture_output,
            )
        argv = tuple(command)
        started = time.monotonic()
        creation_flags = (
            int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            if WINDOWS_PROCESS_HOST
            else 0
        )
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            start_new_session=not WINDOWS_PROCESS_HOST,
            creationflags=creation_flags,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as timeout:
            partial_stdout = _text(timeout.stdout)
            partial_stderr = _text(timeout.stderr)
            timeout_stdout, timeout_stderr = self._stop_and_reap(process)
            partial_stdout = _merge_output(partial_stdout, _text(timeout_stdout))
            partial_stderr = _merge_output(partial_stderr, _text(timeout_stderr))
            returncode = process.poll()
            result = CommandResult(
                argv=argv,
                returncode=returncode if returncode is not None else -1,
                stdout=partial_stdout,
                stderr=partial_stderr,
                duration_seconds=time.monotonic() - started,
            )
            raise CommandTimeoutError(result, timeout_seconds) from timeout
        except BaseException:
            self._stop_and_reap(process)
            raise

        result = CommandResult(
            argv=argv,
            returncode=process.returncode,
            stdout=_text(stdout),
            stderr=_text(stderr),
            duration_seconds=time.monotonic() - started,
        )
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.argv,
                output=result.stdout,
                stderr=result.stderr,
            )
        return result

    def _stop_and_reap(
        self, process: subprocess.Popen[str]
    ) -> tuple[str | bytes | None, str | bytes | None]:
        self._terminate_process_tree(process)
        try:
            return process.communicate(timeout=COMMAND_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            self._kill_process_tree(process)
            try:
                return process.communicate(timeout=COMMAND_TERMINATION_GRACE_SECONDS)
            except subprocess.TimeoutExpired as forced_timeout:
                return forced_timeout.stdout, forced_timeout.stderr

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
        if WINDOWS_PROCESS_HOST:
            process.kill()
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return

    @staticmethod
    def _kill_process_tree(process: subprocess.Popen[str]) -> None:
        if WINDOWS_PROCESS_HOST:
            process.kill()
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return


def console_output(label: str, completed: CommandResult) -> tuple[str, str]:
    if completed.returncode == 0:
        if label.startswith("Discover "):
            return ("[discovery output retained in the CI log]\n", "")
        return (
            _bounded_success_output(completed.stdout),
            _bounded_success_output(completed.stderr),
        )
    return (
        _failure_excerpt(completed.stdout),
        _failure_excerpt(completed.stderr),
    )


def exception_details(error: BaseException) -> list[str]:
    if isinstance(error, BaseExceptionGroup):
        details = [
            detail
            for nested in error.exceptions
            for detail in exception_details(nested)
        ]
        return details or [f"{type(error).__name__}: {error}"]
    if isinstance(error, subprocess.CalledProcessError):
        command = _bounded_command(tuple(str(argument) for argument in error.cmd))
        return [f"CalledProcessError exit={error.returncode} command={command}"]
    if isinstance(error, CommandTimeoutError):
        command = _bounded_command(error.result.argv)
        return [
            f"CommandTimeoutError deadline={error.timeout_seconds:.3f}s command={command}"
        ]
    return [f"{type(error).__name__}: {error}"]


def exception_exit_code(error: BaseException) -> int:
    if isinstance(error, BaseExceptionGroup):
        codes = [exception_exit_code(nested) for nested in error.exceptions]
        return max(codes, default=1)
    if isinstance(error, subprocess.CalledProcessError):
        return error.returncode if error.returncode > 0 else 1
    if isinstance(error, CommandTimeoutError):
        return 124
    return 1


def _bounded_success_output(output: str) -> str:
    test_detail_count = sum(
        1 for _ in zip(_TEST_DETAIL_PATTERN.finditer(output), range(5), strict=False)
    )
    if len(output) <= MAX_CONSOLE_OUTPUT_CHARACTERS and test_detail_count < 5:
        return output
    summaries = deque(
        (match.group(0).strip() for match in _SUCCESS_SUMMARY_PATTERN.finditer(output)),
        maxlen=20,
    )
    rendered = "\n".join(summaries)
    suffix = "\n[successful output compacted; full output retained in the CI log]\n"
    return f"{rendered}\n{suffix}" if rendered else suffix


def _failure_excerpt(output: str) -> str:
    if not output:
        return output
    matches = list(
        zip(
            _PRIMARY_FAILURE_MARKER_PATTERN.finditer(output),
            range(MAX_FAILURE_MARKERS),
            strict=False,
        )
    )
    if not matches:
        matches = list(
            zip(
                _SECONDARY_FAILURE_MARKER_PATTERN.finditer(output),
                range(MAX_FAILURE_MARKERS),
                strict=False,
            )
        )
    ranges = [
        _line_context_range(output, match.start(), match.end(), before=6, after=8)
        for match, _ in matches
    ]
    if not ranges:
        ranges = [(_tail_start(output, 40), len(output))]
    rendered_lines: list[str] = []
    for start, end in _merge_ranges(ranges):
        for line in output[start:end].splitlines():
            rendered_lines.append(_bounded_console_line(line))
            if len(rendered_lines) == MAX_FAILURE_CONTEXT_LINES:
                break
        if len(rendered_lines) == MAX_FAILURE_CONTEXT_LINES:
            break
    rendered = "\n".join(rendered_lines)
    return f"{rendered}\n[full failure output retained in the CI log]\n"


def _line_context_range(
    output: str,
    match_start: int,
    match_end: int,
    *,
    before: int,
    after: int,
) -> tuple[int, int]:
    start = match_start
    for _ in range(before + 1):
        previous = output.rfind("\n", 0, max(0, start - 1))
        if previous < 0:
            start = 0
            break
        start = previous + 1
    end = match_end
    for _ in range(after + 1):
        following = output.find("\n", end)
        if following < 0:
            end = len(output)
            break
        end = following + 1
    return start, end


def _tail_start(output: str, lines: int) -> int:
    start = len(output)
    for _ in range(lines):
        previous = output.rfind("\n", 0, max(0, start - 1))
        if previous < 0:
            return 0
        start = previous + 1
    return start


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _bounded_console_line(line: str) -> str:
    if len(line) <= 2_000:
        return line
    return f"{line[:2_000]}… [line truncated in console]"


def failure_headline(completed: CommandResult) -> str:
    for pattern in (
        _PRIMARY_FAILURE_MARKER_PATTERN,
        _SECONDARY_FAILURE_MARKER_PATTERN,
    ):
        for output in (completed.stderr, completed.stdout):
            if match := pattern.search(output):
                return _bounded_console_line(match.group(0).strip())
    return f"command exited with status {completed.returncode}"


def report_failure(label: str, completed: CommandResult) -> None:
    console_stdout, console_stderr = console_output(label, completed)
    excerpt = "".join((console_stdout, console_stderr)).strip()
    headline = failure_headline(completed)
    title = _github_command_property(label)
    message = _github_command_message(headline)
    print(f"::error title={title}::{message}", file=sys.stdout, flush=True)
    print(
        f"=== {label} FAILED (exit {completed.returncode}) ===",
        file=sys.stdout,
    )
    if excerpt:
        print(excerpt, file=sys.stdout)
    sys.stdout.flush()
    summary_name = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_name is None:
        return
    with Path(summary_name).open("a", encoding="utf-8") as summary:
        summary.write(
            f"### Failed: {html.escape(label)}\n\n"
            f"Exit code: `{completed.returncode}`\n\n"
            f"<pre>{html.escape(excerpt or headline)}</pre>\n\n"
        )


def _bounded_command(arguments: tuple[str, ...]) -> str:
    maximum_arguments = 10
    if len(arguments) <= maximum_arguments:
        return " ".join(arguments)
    shown = " ".join(arguments[:maximum_arguments])
    return f"{shown} … ({len(arguments) - maximum_arguments} more arguments)"


def _github_command_message(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _github_command_property(value: str) -> str:
    return _github_command_message(value).replace(":", "%3A").replace(",", "%2C")


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _merge_output(initial: str, final: str) -> str:
    if final.startswith(initial):
        return final
    if initial.startswith(final):
        return initial
    return initial + final
