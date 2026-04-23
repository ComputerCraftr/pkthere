from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from docker.alpine.pkthere_harness import topology
from docker.alpine.pkthere_harness.command_runner import CommandResult


class VerifierArtifactTests(unittest.TestCase):
    def test_four_id_nodes_select_shared_and_single_worker_modes(self) -> None:
        environment = {
            "CLIENT_UDP_PORT": "5000",
            "NODE_B_IP": "172.28.0.20",
            "SERVER_DESTINATION_ID": "9999",
            "CLIENT_SOURCE_ID": "40000",
            "CLIENT_REPLY_ID": "40001",
            "NODE_A_WORKERS": "3",
            "SERVER_SOURCE_ID": "7777",
            "ECHO_IP": "172.28.0.10",
            "ECHO_UDP_PORT": "7000",
            "NODE_B_WORKERS": "3",
        }
        with (
            patch.dict("os.environ", environment, clear=True),
            patch.object(topology, "exec_forwarder") as exec_forwarder,
        ):
            topology.node_a()
            topology.node_b()

        node_a_args = exec_forwarder.call_args_list[0].args[1]
        node_b_args = exec_forwarder.call_args_list[1].args[1]
        self.assertEqual(
            node_a_args[
                node_a_args.index("--workers") : node_a_args.index("--workers") + 4
            ],
            ["--workers", "3", "--worker-flow-mode", "shared-flow"],
        )
        self.assertEqual(
            node_b_args[
                node_b_args.index("--workers") : node_b_args.index("--workers") + 4
            ],
            ["--workers", "3", "--worker-flow-mode", "single-flow"],
        )

    def test_failure_output_is_retained_until_successful_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            failed = CommandResult(
                argv=("topology-verifier",),
                returncode=1,
                stdout="",
                stderr="partial diagnostic record",
                duration_seconds=0.0,
            )
            succeeded = CommandResult(
                argv=("topology-verifier",),
                returncode=0,
                stdout='{"ok":true}\n',
                stderr="",
                duration_seconds=0.0,
            )
            with (
                patch.object(topology, "LOG_DIR", log_dir),
                patch(
                    "docker.alpine.pkthere_harness.topology.RUNNER.run",
                    side_effect=[failed, succeeded],
                ),
            ):
                self.assertFalse(
                    topology.run_verifier("timeout", "timeout-verdict.json")
                )
                self.assertEqual(
                    (log_dir / "timeout-verifier.err").read_text(encoding="utf-8"),
                    "stderr:\npartial diagnostic record\n",
                )
                self.assertTrue(
                    topology.run_verifier("timeout", "timeout-verdict.json")
                )

            self.assertFalse((log_dir / "timeout-verifier.err").exists())
            self.assertEqual(
                (log_dir / "timeout-verdict.json").read_text(encoding="utf-8"),
                succeeded.stdout,
            )

    def test_structured_stdout_failure_is_included_in_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir)
            failed = CommandResult(
                argv=("topology-verifier",),
                returncode=1,
                stdout='{"ok":false,"error":"missing ack-matched transition"}\n',
                stderr="",
                duration_seconds=0.0,
            )
            with (
                patch.object(topology, "LOG_DIR", log_dir),
                patch(
                    "docker.alpine.pkthere_harness.topology.RUNNER.run",
                    return_value=failed,
                ),
            ):
                self.assertFalse(
                    topology.run_verifier("timeout", "timeout-verdict.json")
                )
                error = topology.verifier_timeout(
                    "timeout", "verifier deadline expired"
                )

            self.assertIn("missing ack-matched transition", str(error))
            self.assertIn("last verifier failure", str(error))


if __name__ == "__main__":
    unittest.main()
