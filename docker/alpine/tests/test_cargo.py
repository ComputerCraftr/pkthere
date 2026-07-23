from __future__ import annotations

from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from docker.alpine.pkthere_harness.cargo import cargo_executables, cargo_messages
from docker.alpine.pkthere_harness.command_runner import CommandResult, CommandRunner


class CargoArtifactDiscoveryTests(unittest.TestCase):
    def test_non_json_stdout_reports_the_exact_line(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"line 2 was not JSON: 'cross status text'",
        ):
            cargo_messages('{"reason":"build-finished"}\ncross status text\n')

    def test_cross_rustup_status_can_precede_cargo_json(self) -> None:
        messages = cargo_messages(
            "  stable-x86_64-unknown-linux-gnu installed "
            "- (error reading rustc version)\n"
            '{"reason":"build-finished","success":true}\n',
            allow_rustup_status=True,
        )
        self.assertEqual(
            messages,
            [{"reason": "build-finished", "success": True}],
        )

    def test_cross_host_fallback_is_rejected_with_preserved_stderr(self) -> None:
        runner = Mock(spec=CommandRunner)
        runner.run.return_value = CommandResult(
            argv=("cross", "build"),
            returncode=0,
            stdout="[cross] note: Falling back to `cargo` on the host.\n",
            stderr="cross configuration warning\n",
            duration_seconds=0.1,
        )
        captured_stderr = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as temporary_directory,
            redirect_stderr(captured_stderr),
            self.assertRaisesRegex(RuntimeError, "refused container execution"),
        ):
            cargo_executables(
                ["build", "--locked"],
                {"pkthere"},
                root=Path(temporary_directory),
                runner=runner,
                cargo_command=("cross",),
            )

        self.assertEqual(captured_stderr.getvalue(), "cross configuration warning\n")

    def test_cross_container_artifact_path_maps_to_host_target_mount(self) -> None:
        runner = Mock(spec=CommandRunner)
        runner.run.return_value = CommandResult(
            argv=("cross", "build"),
            returncode=0,
            stdout=(
                '{"reason":"compiler-artifact",'
                '"target":{"name":"pkthere"},'
                '"executable":"/target/aarch64-unknown-linux-musl/release/pkthere"}\n'
            ),
            stderr="",
            duration_seconds=0.1,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            host_target = root / "target/cross-aarch64-musl"
            executables = cargo_executables(
                ["build", "--locked"],
                {"pkthere"},
                root=root,
                runner=runner,
                cargo_command=("cross",),
                container_target_dir=host_target,
            )

        self.assertEqual(
            executables["pkthere"],
            host_target / "aarch64-unknown-linux-musl/release/pkthere",
        )


if __name__ == "__main__":
    unittest.main()
