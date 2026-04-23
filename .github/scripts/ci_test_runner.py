#!/usr/bin/env python3
"""Authoritative cross-platform native and privileged Cargo test runner."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from docker.alpine.pkthere_harness.cargo import resolve_test_executable  # noqa: E402
from docker.alpine.pkthere_harness.command_runner import (  # noqa: E402
    CommandResult,
    CommandRunner,
)
from docker.alpine.pkthere_harness.test_manifest import (  # noqa: E402
    RAW_SOCKET_REALITY_TEST,
    native_platform_name,
    privileged_icmp_tests_for_platform,
)
from docker.alpine.pkthere_harness.timing import (  # noqa: E402
    ARTIFACT_BUILD_TIMEOUT_SECONDS,
    DOCKER_CONTROL_TIMEOUT_SECONDS,
)


class TestRunner:
    def __init__(self, log_file: Path, runner: CommandRunner | None = None) -> None:
        self.log_file = log_file
        self.runner = runner or CommandRunner()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.log_file.write_text("", encoding="utf-8")

    def native(self) -> None:
        self._run(
            "Workspace unit and integration tests",
            (
                "cargo",
                "test",
                "--locked",
                "--workspace",
                "--lib",
                "--bins",
                "--tests",
                "--",
                "--nocapture",
            ),
        )
        if os.environ.get("PKTHERE_ALLOW_RAW_ICMP", "0") == "1":
            platform = native_platform_name()
            for selection in privileged_icmp_tests_for_platform(platform):
                self._run(
                    f"Privileged ICMP test ({platform}): {selection.test_name}",
                    selection.cargo_arguments(),
                )
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
        )

    def raw_reality(self) -> None:
        if "TEST_APP_BIN" not in os.environ:
            raise RuntimeError("TEST_APP_BIN must name the prepared test binary")
        executable = resolve_test_executable(
            RAW_SOCKET_REALITY_TEST.package,
            RAW_SOCKET_REALITY_TEST.target_name or "socket_reality",
            root=ROOT,
            runner=self.runner,
        )
        if os.name != "nt":
            self._run(
                "Grant RAW capability to socket-reality executable",
                (
                    "bash",
                    str(ROOT / ".github/scripts/grant_raw_capability.sh"),
                    str(executable),
                ),
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            )
        self._run(
            "Privileged RAW socket reality",
            RAW_SOCKET_REALITY_TEST.executable_arguments(str(executable)),
        )

    def _run(
        self,
        label: str,
        command: tuple[str, ...],
        *,
        timeout_seconds: float = ARTIFACT_BUILD_TIMEOUT_SECONDS,
    ) -> None:
        print(f"::group::{label}", flush=True)
        completed = self.runner.run(
            command,
            timeout_seconds=timeout_seconds,
            cwd=ROOT,
            env=os.environ.copy(),
            check=False,
            capture_output=True,
        )
        self._record(label, completed)
        print("::endgroup::", flush=True)
        if completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                completed.argv,
                output=completed.stdout,
                stderr=completed.stderr,
            )

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
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        sys.stdout.flush()
        sys.stderr.flush()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("native", "raw-reality"))
    parser.add_argument("--log", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    runner = TestRunner(args.log.resolve())
    if args.command == "native":
        runner.native()
    else:
        runner.raw_reality()


if __name__ == "__main__":
    main()
