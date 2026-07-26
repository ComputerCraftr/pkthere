"""Tests for bounded Alpine process helpers."""

from __future__ import annotations

import unittest

from docker.alpine.pkthere_harness.processes import FORWARDER_DEBUG_LOGS


class ForwarderDiagnosticsTests(unittest.TestCase):
    def test_topology_diagnostics_exclude_full_packet_dumps(self) -> None:
        self.assertNotIn("packet-dump", FORWARDER_DEBUG_LOGS)
        self.assertEqual(
            FORWARDER_DEBUG_LOGS,
            ("drops", "handles", "handshake"),
        )


if __name__ == "__main__":
    unittest.main()
