"""Host-side Alpine Compose orchestration with one authoritative lifecycle owner."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

from docker.alpine.pkthere_harness.command_runner import (
    CommandResult,
    CommandRunner,
)
from docker.alpine.pkthere_harness.timing import (
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    DOCKER_PROFILE_TIMEOUT_SECONDS,
    DOCKER_REALITY_PROFILE_TIMEOUT_SECONDS,
    DOCKER_TEARDOWN_TIMEOUT_SECONDS,
)

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "compose.yaml"
ENV_FILE = ROOT / "docker/alpine/topology.env"
FAILURE_LOG_TAIL_LINES = 200


class Orchestrator:
    def __init__(
        self,
        artifact_dir: Path,
        *,
        runner: CommandRunner | None = None,
        project_name: str | None = None,
    ) -> None:
        self.artifact_dir = artifact_dir.resolve()
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.environment = os.environ.copy()
        self.environment["PKTHERE_ARTIFACT_DIR"] = str(self.artifact_dir)
        self.runner = runner or CommandRunner()
        self.project_name = project_name or (
            f"pkthere-reality-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        )

    def compose(
        self,
        arguments: Sequence[str],
        *,
        capture: bool = False,
        check: bool = True,
        timeout_seconds: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
    ) -> CommandResult:
        return self.runner.run(
            [
                "docker",
                "compose",
                "--project-name",
                self.project_name,
                "--env-file",
                str(ENV_FILE),
                "-f",
                str(COMPOSE_FILE),
                *arguments,
            ],
            timeout_seconds=timeout_seconds,
            cwd=ROOT,
            env=self.environment,
            check=check,
            capture_output=capture,
        )

    def reality(self) -> None:
        self._run_services("reality", "reality")
        self._require_artifacts("reality")

    def topology(self) -> None:
        self._run_services("topology", "driver")
        self._require_artifacts("topology")

    def timeout(self) -> None:
        self._run_services("timeout", "timeout-driver")
        self._require_artifacts("timeout")

    def _teardown(self) -> None:
        self.compose(
            [
                "--profile",
                "reality",
                "--profile",
                "topology",
                "--profile",
                "timeout",
                "down",
                "--remove-orphans",
            ],
            timeout_seconds=DOCKER_TEARDOWN_TIMEOUT_SECONDS,
        )

    def _run_services(self, profile: str, verdict_service: str) -> None:
        self._prepare_profile(profile)
        primary: BaseException | None = None
        secondary: list[tuple[str, BaseException]] = []
        try:
            self.compose(["--profile", profile, "up", "-d", "--no-build"])
            container_id = self.compose(
                ["--profile", profile, "ps", "-q", verdict_service],
                capture=True,
            ).stdout.strip()
            if not container_id:
                raise RuntimeError(f"Compose did not create {verdict_service}")
            waited = self.runner.run(
                ["docker", "wait", container_id],
                timeout_seconds=(
                    DOCKER_REALITY_PROFILE_TIMEOUT_SECONDS
                    if profile == "reality"
                    else DOCKER_PROFILE_TIMEOUT_SECONDS
                ),
                cwd=ROOT,
                env=self.environment,
                capture_output=True,
            )
            exit_code = int(waited.stdout.strip())
            inspection = self.runner.run(
                ["docker", "inspect", container_id],
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
                cwd=ROOT,
                env=self.environment,
                capture_output=True,
            )
            (self.artifact_dir / f"{profile}-container-inspect.json").write_text(
                inspection.stdout, encoding="utf-8"
            )
            if exit_code != 0:
                raise RuntimeError(
                    f"{verdict_service} exited with authoritative status {exit_code}"
                )
        except BaseException as primary_error:
            primary = primary_error
        try:
            self._collect(profile)
        except BaseException as collection_error:
            secondary.append(("artifact collection", collection_error))
        if primary is not None:
            try:
                self._print_failure_log_tail(profile)
            except BaseException as log_error:
                secondary.append(("failure log rendering", log_error))
        try:
            self._teardown()
        except BaseException as teardown_error:
            secondary.append(("teardown", teardown_error))

        if primary is None and secondary:
            primary = secondary.pop(0)[1]
        if primary is not None:
            for label, secondary_error in secondary:
                primary.add_note(f"secondary {label} failure: {secondary_error}")
            raise primary

    def _print_failure_log_tail(self, profile: str) -> None:
        for stream in ("out", "err"):
            path = self.artifact_dir / f"{profile}-services.{stream}"
            if not path.is_file():
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            if not lines:
                continue
            print(
                f"=== Docker Compose {profile} {stream} tail ===",
                file=sys.stderr,
            )
            print("\n".join(lines[-FAILURE_LOG_TAIL_LINES:]), file=sys.stderr)

    def _collect(self, profile: str) -> None:
        logs = self.compose(["--profile", profile, "logs", "--no-color"], capture=True)
        self._write_completed(f"{profile}-services", logs)
        services = self.compose(
            ["--profile", profile, "ps", "-a", "--format", "json"], capture=True
        )
        (self.artifact_dir / f"{profile}-compose-ps.json").write_text(
            services.stdout, encoding="utf-8"
        )
        container_ids = self.compose(
            ["--profile", profile, "ps", "-a", "-q"], capture=True
        ).stdout.split()
        if container_ids:
            inspections = self.runner.run(
                ["docker", "inspect", *container_ids],
                timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
                cwd=ROOT,
                env=self.environment,
                capture_output=True,
            )
            (self.artifact_dir / f"{profile}-all-container-inspect.json").write_text(
                inspections.stdout, encoding="utf-8"
            )

    def _write_completed(self, name: str, completed: CommandResult) -> None:
        (self.artifact_dir / f"{name}.out").write_text(
            completed.stdout, encoding="utf-8"
        )
        (self.artifact_dir / f"{name}.err").write_text(
            completed.stderr, encoding="utf-8"
        )

    def _prepare_profile(self, profile: str) -> None:
        profile_dir = self.artifact_dir / profile
        runtime_dir = profile_dir / "runtime"
        if profile_dir.exists():
            shutil.rmtree(profile_dir)
        runtime_dir.mkdir(parents=True)
        runtime_dir.chmod(0o777)
        self.environment["PKTHERE_ARTIFACT_DIR"] = str(profile_dir)

    def _require_artifacts(self, profile: str) -> None:
        common = (
            f"{profile}-all-container-inspect.json",
            f"{profile}-compose-ps.json",
            f"{profile}-container-inspect.json",
            f"{profile}-services.err",
            f"{profile}-services.out",
        )
        runtime = {
            "reality": (),
            "topology": (
                "topology/runtime/node-a.err",
                "topology/runtime/node-a.out",
                "topology/runtime/node-b.err",
                "topology/runtime/node-b.out",
                "topology/runtime/topology-verdict.json",
            ),
            "timeout": (
                "timeout/runtime/timeout-node.err",
                "timeout/runtime/timeout-node.out",
                "timeout/runtime/timeout-verdict.json",
            ),
        }[profile]
        missing = [
            path
            for path in (*common, *runtime)
            if not (self.artifact_dir / path).is_file()
        ]
        if missing:
            raise RuntimeError(
                f"{profile} profile did not preserve artifacts: {missing}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("reality", "topology", "timeout", "all"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("docker-artifacts"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    orchestrator = Orchestrator(args.artifact_dir)
    if args.command == "all":
        orchestrator.reality()
        orchestrator.topology()
        orchestrator.timeout()
    else:
        command = getattr(orchestrator, args.command)
        command()
    print(json.dumps({"ok": True, "command": args.command}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        raise
