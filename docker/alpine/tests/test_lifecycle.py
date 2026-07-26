from __future__ import annotations

import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from docker.alpine.pkthere_harness import lifecycle


class ProcessLifecycleTests(unittest.TestCase):
    def test_snapshot_records_only_exact_forwarder_executables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc_root = Path(directory)
            forwarder = proc_root / "pkthere"
            forwarder.touch()
            self._write_process(proc_root, 10, forwarder)
            self._write_process(proc_root, 11, Path("/bin/sh"))

            with patch.object(
                lifecycle,
                "FORWARDER_EXECUTABLES",
                frozenset((forwarder.resolve(),)),
            ):
                records = lifecycle.snapshot_forwarders(proc_root=proc_root)

        self.assertEqual([record.pid for record in records], [10])
        self.assertEqual(records[0].parent_pid, 1)
        self.assertEqual(records[0].process_group, 10)
        self.assertEqual(records[0].session, 10)
        self.assertEqual(records[0].start_ticks, 1234)

    def test_clean_audit_records_evidence_without_signalling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "lifecycle.jsonl"
            with (
                patch.object(lifecycle, "PROCESS_LIFECYCLE_EVIDENCE", evidence),
                patch.object(lifecycle, "LOG_DIR", Path(directory)),
            ):
                lifecycle.audit_forwarder_lifecycle(
                    "clean test", proc_root=Path(directory)
                )
            rendered = evidence.read_text(encoding="utf-8")
        self.assertIn('"label": "clean test"', rendered)
        self.assertIn('"outcome": "clean"', rendered)

    def test_unavailable_proc_inventory_fails_closed_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "lifecycle.jsonl"
            missing_proc = Path(directory) / "missing-proc"
            with (
                patch.object(lifecycle, "PROCESS_LIFECYCLE_EVIDENCE", evidence),
                patch.object(lifecycle, "LOG_DIR", Path(directory)),
                self.assertRaises(lifecycle.ProcessLifecycleAuditError),
            ):
                lifecycle.audit_forwarder_lifecycle(
                    "unavailable proc", proc_root=missing_proc
                )
            rendered = evidence.read_text(encoding="utf-8")
        self.assertIn('"outcome": "audit-error"', rendered)
        self.assertIn('"error":', rendered)

    def test_stale_audit_records_and_signals_survivor_before_failing(self) -> None:
        record = lifecycle.ProcessEvidence(
            pid=12,
            parent_pid=1,
            process_group=12,
            session=12,
            state="S",
            start_ticks=1234,
            executable="/usr/local/libexec/pkthere/pkthere-priv",
            command=("pkthere-priv",),
            wait_channel="do_poll",
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "lifecycle.jsonl"
            with (
                patch.object(lifecycle, "PROCESS_LIFECYCLE_EVIDENCE", evidence),
                patch.object(lifecycle, "LOG_DIR", Path(directory)),
                patch.object(lifecycle, "snapshot_forwarders", return_value=(record,)),
                patch.object(
                    lifecycle,
                    "_wait_for_exit",
                    side_effect=((record,), ()),
                ),
                patch.object(lifecycle, "_signal_matching") as signal_matching,
                self.assertRaises(lifecycle.StaleForwarderError),
            ):
                lifecycle.audit_forwarder_lifecycle("leaking test")
            signals = [
                invocation.args[1] for invocation in signal_matching.call_args_list
            ]
            self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
            rendered = evidence.read_text(encoding="utf-8")
        self.assertIn('"label": "leaking test"', rendered)
        self.assertIn('"outcome": "stale"', rendered)

    @staticmethod
    def _write_process(proc_root: Path, pid: int, executable: Path) -> None:
        process = proc_root / str(pid)
        process.mkdir()
        process.joinpath("exe").symlink_to(executable)
        fields = [
            str(pid),
            "(pkthere)",
            "S",
            "1",
            str(pid),
            str(pid),
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "1234",
        ]
        process.joinpath("stat").write_text(" ".join(fields), encoding="utf-8")
        process.joinpath("cmdline").write_bytes(b"pkthere\0--debug-fast-stats\0")
        process.joinpath("wchan").write_text("do_poll", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
