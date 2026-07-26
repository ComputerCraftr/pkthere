"""Source and artifact provenance tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ci.pkthere_ci.command_runner import CommandRunner
from ci.pkthere_ci.provenance import record_source_provenance

ROOT = Path(__file__).resolve().parents[2]


class SourceProvenanceTests(unittest.TestCase):
    def test_dirty_worktree_is_recorded_in_build_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            repository, runner = self._repository(temporary_root)
            (repository / "source.txt").write_text("dirty fixture\n", encoding="utf-8")

            evidence = record_source_provenance(
                repository,
                temporary_root / "evidence",
                runner=runner,
                environment={},
            )

            self.assertIs(evidence["dirty_worktree"], True)
            self.assertIs(evidence["release_eligible"], False)
            self.assertEqual(
                evidence["artifact_source_contract"],
                "dirty-worktree-development-build",
            )
            self.assertEqual(len(str(evidence["workspace_input_sha256"])), 64)

    def test_canonical_archive_is_hash_bound_to_commit_tree_and_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            repository, runner = self._repository(temporary_root)
            evidence_dir = temporary_root / "evidence"
            first = record_source_provenance(
                repository,
                evidence_dir,
                runner=runner,
                environment={},
            )
            second = record_source_provenance(
                repository,
                evidence_dir,
                runner=runner,
                environment={},
            )

            self.assertEqual(
                first["canonical_source_tar_sha256"],
                second["canonical_source_tar_sha256"],
            )
            self.assertEqual(len(str(first["commit_sha"])), 40)
            self.assertEqual(len(str(first["tree_sha"])), 40)
            self.assertEqual(len(str(first["cargo_lock_sha256"])), 64)
            self.assertIs(first["release_eligible"], True)
            self.assertEqual(first["artifact_source_contract"], "canonical-commit-tree")
            self.assertEqual(len(str(first["workspace_input_sha256"])), 64)
            on_disk = json.loads(
                (evidence_dir / "source-provenance.json").read_text(encoding="utf-8")
            )
            self.assertEqual(on_disk, second)

    @staticmethod
    def _repository(temporary_root: Path) -> tuple[Path, CommandRunner]:
        repository = temporary_root / "repository"
        repository.mkdir()
        (repository / "Cargo.lock").write_text(
            "# provenance fixture\n",
            encoding="utf-8",
        )
        (repository / "source.txt").write_text("fixture\n", encoding="utf-8")
        runner = CommandRunner()
        for command in (
            ("git", "init", "--quiet"),
            ("git", "add", "Cargo.lock", "source.txt"),
            (
                "git",
                "-c",
                "user.name=pkthere tests",
                "-c",
                "user.email=tests@pkthere.invalid",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--quiet",
                "-m",
                "provenance fixture",
            ),
        ):
            runner.run(command, cwd=repository, env={}, timeout_seconds=10)
        return repository, runner


if __name__ == "__main__":
    unittest.main()
