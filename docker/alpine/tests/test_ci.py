from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest

from docker.alpine.ci import Orchestrator
from docker.alpine.pkthere_harness.command_runner import CommandResult, CommandRunner
from docker.alpine.pkthere_harness.timing import (
    DOCKER_PROFILE_TIMEOUT_SECONDS,
    DOCKER_REALITY_PROFILE_TIMEOUT_SECONDS,
)


class FakeRunner(CommandRunner):
    def __init__(
        self,
        *,
        verdict: int = 0,
        fail_when_arguments_contain: str | None = None,
        failure: BaseException | None = None,
        service_logs: str = "",
    ) -> None:
        self.commands: list[list[str]] = []
        self.timeouts: list[float] = []
        self.verdict = verdict
        self.fail_when_arguments_contain = fail_when_arguments_contain
        self.failure = failure
        self.service_logs = service_logs

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
        del cwd, env, check, capture_output
        rendered = list(command)
        self.commands.append(rendered)
        self.timeouts.append(timeout_seconds)
        if (
            self.fail_when_arguments_contain is not None
            and self.fail_when_arguments_contain in rendered
        ):
            if self.failure is not None:
                raise self.failure
            raise RuntimeError(f"forced {self.fail_when_arguments_contain} failure")
        if rendered[:2] == ["docker", "wait"]:
            stdout = f"{self.verdict}\n"
        elif "ps" in rendered and "-q" in rendered:
            stdout = "container-id\n"
        elif rendered[:2] == ["docker", "inspect"]:
            stdout = "[]\n"
        elif "logs" in rendered:
            stdout = self.service_logs
        else:
            stdout = ""
        return CommandResult(tuple(rendered), 0, stdout, "", 0.0)


class OrchestratorTests(unittest.TestCase):
    def test_driver_exit_is_authoritative_and_teardown_is_last(self) -> None:
        runner = FakeRunner(
            verdict=7,
            service_logs='timeout-driver | {"ok":false,"error":"missing ack"}\n',
        )
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator(
                Path(directory), runner=runner, project_name="pkthere-test"
            )
            with (
                redirect_stderr(stderr),
                self.assertRaisesRegex(RuntimeError, "authoritative status 7"),
            ):
                orchestrator._run_services("topology", "driver")
        self.assertEqual(runner.commands[-1][-2:], ["down", "--remove-orphans"])
        self.assertTrue(
            any(command[:2] == ["docker", "wait"] for command in runner.commands)
        )
        self.assertIn("Docker Compose topology out tail", stderr.getvalue())
        self.assertIn("missing ack", stderr.getvalue())

    def test_compose_commands_use_unique_project_name(self) -> None:
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator(
                Path(directory), runner=runner, project_name="stable-project"
            )
            orchestrator.compose(["version"])
        self.assertIn("--project-name", runner.commands[0])
        self.assertIn("stable-project", runner.commands[0])

    def test_success_collects_artifacts_before_teardown(self) -> None:
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator(
                Path(directory), runner=runner, project_name="pkthere-test"
            )
            orchestrator._run_services("reality", "reality")
        logs_at = next(
            index for index, command in enumerate(runner.commands) if "logs" in command
        )
        teardown_at = next(
            index for index, command in enumerate(runner.commands) if "down" in command
        )
        self.assertLess(logs_at, teardown_at)

    def test_collection_failure_still_tears_down(self) -> None:
        runner = FakeRunner(fail_when_arguments_contain="logs")
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator(
                Path(directory), runner=runner, project_name="pkthere-test"
            )
            with self.assertRaisesRegex(RuntimeError, "forced logs failure"):
                orchestrator._run_services("topology", "driver")
        self.assertIn("down", runner.commands[-1])

    def test_timeout_profile_waits_for_timeout_driver(self) -> None:
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator(
                Path(directory), runner=runner, project_name="pkthere-test"
            )
            orchestrator._run_services("timeout", "timeout-driver")
        compose_ps = next(command for command in runner.commands if "ps" in command)
        self.assertIn("timeout-driver", compose_ps)
        docker_wait = next(
            command for command in runner.commands if command[:2] == ["docker", "wait"]
        )
        self.assertEqual(docker_wait[-1], "container-id")

    def test_reality_profile_has_room_for_measured_suites_but_other_profiles_do_not(
        self,
    ) -> None:
        for profile, service, expected_timeout in (
            ("reality", "reality", DOCKER_REALITY_PROFILE_TIMEOUT_SECONDS),
            ("topology", "driver", DOCKER_PROFILE_TIMEOUT_SECONDS),
        ):
            runner = FakeRunner()
            with tempfile.TemporaryDirectory() as directory:
                orchestrator = Orchestrator(
                    Path(directory), runner=runner, project_name="pkthere-test"
                )
                orchestrator._run_services(profile, service)
            wait_index = next(
                index
                for index, command in enumerate(runner.commands)
                if command[:2] == ["docker", "wait"]
            )
            self.assertEqual(runner.timeouts[wait_index], expected_timeout)

    def test_primary_failure_remains_authoritative_when_teardown_fails(self) -> None:
        runner = FakeRunner(verdict=9, fail_when_arguments_contain="down")
        with tempfile.TemporaryDirectory() as directory:
            orchestrator = Orchestrator(
                Path(directory), runner=runner, project_name="pkthere-test"
            )
            with self.assertRaisesRegex(
                RuntimeError, "authoritative status 9"
            ) as raised:
                orchestrator._run_services("topology", "driver")
        self.assertTrue(
            any(
                "secondary teardown failure" in note
                for note in raised.exception.__notes__
            )
        )


if __name__ == "__main__":
    unittest.main()
