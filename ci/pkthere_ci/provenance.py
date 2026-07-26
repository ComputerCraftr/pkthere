"""Canonical source and artifact provenance for release builders."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path

from .command_runner import CommandRunner
from .timing import ARTIFACT_BUILD_TIMEOUT_SECONDS, DOCKER_CONTROL_TIMEOUT_SECONDS

WORKSPACE_SOURCE_EXCLUDED_PARTS = frozenset(
    {
        ".artifacts",
        ".git",
        ".mypy_cache",
        ".ruff_cache",
        "__pycache__",
        "cross-artifacts",
        "docker-artifacts",
        "target",
    }
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def workspace_input_hashes(
    root: Path,
    excluded_parts: frozenset[str],
) -> dict[str, str]:
    inputs: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in excluded_parts for part in relative.parts):
            continue
        if path.is_symlink():
            digest = hashlib.sha256(os.readlink(path).encode("utf-8")).hexdigest()
        elif path.is_file():
            digest = sha256_file(path)
        else:
            continue
        inputs[relative.as_posix()] = digest
    return inputs


def workspace_input_sha256(inputs: Mapping[str, str]) -> str:
    aggregate = hashlib.sha256()
    for path, digest in sorted(inputs.items()):
        aggregate.update(path.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\0")
    return aggregate.hexdigest()


def workspace_source_identity(root: Path) -> str:
    """Return the content identity used to isolate mutable-worktree build outputs."""

    return workspace_input_sha256(
        workspace_input_hashes(root, WORKSPACE_SOURCE_EXCLUDED_PARTS)
    )


def candidate_file_paths(
    root: Path,
    patterns: tuple[str, ...],
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> tuple[str, ...]:
    """Return candidate tracked/untracked regular files from one Git authority."""

    result = runner.run(
        (
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *patterns,
        ),
        cwd=root,
        env=environment,
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        capture_output=True,
    )
    files = []
    for relative in result.stdout.split("\0"):
        if not relative:
            continue
        candidate = root / relative
        if candidate.is_symlink():
            raise RuntimeError(f"candidate repository file is a symlink: {relative}")
        if candidate.is_file():
            files.append(relative)
    return tuple(files)


def record_source_provenance(
    root: Path,
    evidence_dir: Path,
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
) -> dict[str, object]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    commit = _git_value(
        root,
        ("git", "rev-parse", "HEAD"),
        runner=runner,
        environment=environment,
    )
    tree = _git_value(
        root,
        ("git", "rev-parse", f"{commit}^{{tree}}"),
        runner=runner,
        environment=environment,
    )
    dirty = bool(
        _git_value(
            root,
            ("git", "status", "--porcelain=v1"),
            runner=runner,
            environment=environment,
            permit_empty=True,
        )
    )
    archive = evidence_dir / "canonical-source.tar"
    runner.run(
        ("git", "archive", "--format=tar", f"--output={archive}", commit),
        cwd=root,
        env=environment,
        timeout_seconds=ARTIFACT_BUILD_TIMEOUT_SECONDS,
    )
    workspace_inputs = workspace_input_hashes(root, WORKSPACE_SOURCE_EXCLUDED_PARTS)
    evidence: dict[str, object] = {
        "artifact_source_contract": (
            "canonical-commit-tree" if not dirty else "dirty-worktree-development-build"
        ),
        "canonical_source_contract": "git archive --format=tar <commit>",
        "canonical_source_tar": str(archive),
        "canonical_source_tar_sha256": sha256_file(archive),
        "cargo_lock_sha256": sha256_file(root / "Cargo.lock"),
        "commit_sha": commit,
        "dirty_worktree": dirty,
        "release_eligible": not dirty,
        "tree_sha": tree,
        "workspace_input_sha256": workspace_input_sha256(workspace_inputs),
    }
    (evidence_dir / "source-provenance.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence


def _git_value(
    root: Path,
    command: tuple[str, ...],
    *,
    runner: CommandRunner,
    environment: Mapping[str, str],
    permit_empty: bool = False,
) -> str:
    result = runner.run(
        command,
        cwd=root,
        env=environment,
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        capture_output=True,
    )
    value = result.stdout.strip()
    if not value and not permit_empty:
        raise RuntimeError(f"{' '.join(command)} returned no provenance value")
    return value
