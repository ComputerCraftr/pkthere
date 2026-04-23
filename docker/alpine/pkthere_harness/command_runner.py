"""Bounded subprocess execution shared by Alpine build and CI tooling."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import time

from .timing import COMMAND_TERMINATION_GRACE_SECONDS


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
    ) -> CommandResult:
        argv = tuple(command)
        started = time.monotonic()
        creation_flags = (
            int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            if os.name == "nt"
            else 0
        )
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            start_new_session=os.name != "nt",
            creationflags=creation_flags,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as timeout:
            partial_stdout = _text(timeout.stdout)
            partial_stderr = _text(timeout.stderr)
            self._terminate_process_tree(process)
            timeout_stdout: str | bytes | None
            timeout_stderr: str | bytes | None
            try:
                timeout_stdout, timeout_stderr = process.communicate(
                    timeout=COMMAND_TERMINATION_GRACE_SECONDS
                )
            except subprocess.TimeoutExpired:
                self._kill_process_tree(process)
                try:
                    timeout_stdout, timeout_stderr = process.communicate(
                        timeout=COMMAND_TERMINATION_GRACE_SECONDS
                    )
                except subprocess.TimeoutExpired as forced_timeout:
                    timeout_stdout = forced_timeout.stdout
                    timeout_stderr = forced_timeout.stderr
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

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
        if os.name == "nt":
            process.kill()
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return

    @staticmethod
    def _kill_process_tree(process: subprocess.Popen[str]) -> None:
        if os.name == "nt":
            process.kill()
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return


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
