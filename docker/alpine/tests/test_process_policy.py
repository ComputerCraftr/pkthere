from __future__ import annotations

import ast
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
PYTHON_ROOTS = (ROOT / "docker/alpine", ROOT / ".github/scripts")
IGNORED_SOURCE_DIRS = {
    ".artifacts",
    ".git",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "cross-artifacts",
    "docker-artifacts",
    "target",
}


class ProcessBoundaryPolicyTests(unittest.TestCase):
    def test_alpine_runtime_artifacts_remain_in_docker_context(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".artifacts/*", dockerignore)
        self.assertIn("!.artifacts/alpine", dockerignore)
        self.assertIn("!.artifacts/alpine/**", dockerignore)
        self.assertNotIn(".artifacts", dockerignore)

        runtime_dockerfile = (ROOT / "docker/alpine/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "COPY .artifacts/alpine/ /usr/local/libexec/pkthere/",
            runtime_dockerfile,
        )

    def test_python_tooling_covers_every_workspace_source(self) -> None:
        configuration = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            configuration["tool"]["mypy"]["files"],
            [".github/scripts", "docker"],
        )

        configured_files = {
            path.resolve()
            for configured_root in configuration["tool"]["mypy"]["files"]
            for path in (ROOT / configured_root).rglob("*.py")
            if not IGNORED_SOURCE_DIRS.intersection(path.parts)
        }
        workspace_files = {
            path.resolve()
            for path in ROOT.rglob("*.py")
            if not IGNORED_SOURCE_DIRS.intersection(path.relative_to(ROOT).parts)
        }
        self.assertEqual(configured_files, workspace_files)

        workflow = (ROOT / ".github/workflows/rust.yml").read_text(encoding="utf-8")
        self.assertIn("ruff==0.15.22 format --check .", workflow)
        self.assertIn("ruff==0.15.22 check .", workflow)
        self.assertIn("pipx run mypy==2.3.0 --strict", workflow)

    def test_subprocess_execution_is_centralized_and_runner_calls_are_bounded(
        self,
    ) -> None:
        violations: list[str] = []
        for root in PYTHON_ROOTS:
            for path in sorted(root.rglob("*.py")):
                relative = path.relative_to(ROOT).as_posix()
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    dotted = _dotted_name(node.func)
                    if dotted in {
                        "subprocess.Popen",
                        "subprocess.call",
                        "subprocess.check_call",
                        "subprocess.check_output",
                        "subprocess.run",
                    }:
                        if (
                            relative
                            != "docker/alpine/pkthere_harness/command_runner.py"
                        ):
                            violations.append(f"{relative}: direct {dotted}")
                    if dotted == "os.execve" and relative != (
                        "docker/alpine/pkthere_harness/processes.py"
                    ):
                        violations.append(
                            f"{relative}: os.execve outside service replacement"
                        )
                    if dotted is not None and dotted.endswith(".run"):
                        if not any(
                            keyword.arg == "timeout_seconds"
                            for keyword in node.keywords
                        ):
                            violations.append(
                                f"{relative}: command runner call lacks timeout_seconds"
                            )
        self.assertEqual(violations, [])

    def test_ordinary_icmp_integration_keeps_default_parallelism(self) -> None:
        source = (ROOT / "docker/alpine/pkthere_harness/reality.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"--test-threads=1"', source)

    def test_privileged_test_names_have_one_authoritative_manifest(self) -> None:
        manifest = ROOT / "docker/alpine/pkthere_harness/test_manifest.py"
        names = (
            "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node",
            "raw_icmp_locked_flow_rejects_wrong_source_id",
            "test_raw_icmp_independent_ids",
            "raw_icmp_wildcard_upstream_locks_on_localhost",
            "raw_icmp_forwarder_packet_dump_matches_policy",
        )
        governed = (
            ROOT / ".github/scripts",
            ROOT / "docker/alpine/pkthere_harness",
        )
        violations: list[str] = []
        for name in names:
            owners: list[str] = []
            for root in governed:
                for path in root.rglob("*.py"):
                    if name in path.read_text(encoding="utf-8"):
                        owners.append(path.relative_to(ROOT).as_posix())
            if owners != [manifest.relative_to(ROOT).as_posix()]:
                violations.append(f"{name}: {owners}")
        self.assertEqual(violations, [])

    def test_retired_duplicate_build_and_test_runners_stay_removed(self) -> None:
        retired = (
            ".github/scripts/run-native-tests.sh",
            ".github/scripts/run-raw-reality.sh",
            ".github/scripts/resolve_cargo_test_executable.py",
            ".github/scripts/build-aarch64-musl.sh",
            ".github/scripts/build-x86_64-musl-artifacts.sh",
            ".github/scripts/portable-build-env.sh",
            ".github/scripts/verify-static-musl-elf.sh",
            "docker/alpine/build_artifacts.py",
        )
        self.assertEqual([path for path in retired if (ROOT / path).exists()], [])


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


if __name__ == "__main__":
    unittest.main()
