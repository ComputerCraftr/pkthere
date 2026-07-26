"""Source-aware Cargo target-cache ownership shared by portable builders."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

from .provenance import (
    WORKSPACE_SOURCE_EXCLUDED_PARTS,
    workspace_input_hashes,
    workspace_input_sha256,
)

SOURCE_CACHE_STATE_NAME = ".pkthere-workspace-inputs-v1.json"


def prepare_source_aware_target_cache(
    root: Path,
    target_dir: Path,
    cache_identity: Mapping[str, str] | None = None,
) -> tuple[Path, dict[str, str], dict[str, object]]:
    target_dir.mkdir(parents=True, exist_ok=True)
    state_path = target_dir / SOURCE_CACHE_STATE_NAME
    previous_inputs: dict[str, str] = {}
    previous_completed_at_ns = 0
    previous_cache_identity: dict[str, str] = {}
    cold_cache = True
    if state_path.is_file():
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
            encoded_inputs = previous.get("inputs")
            encoded_completed = previous.get("completed_at_ns")
            encoded_identity = previous.get("cache_identity")
            if isinstance(encoded_inputs, dict) and isinstance(encoded_completed, int):
                previous_inputs = {
                    str(path): str(digest) for path, digest in encoded_inputs.items()
                }
                previous_completed_at_ns = encoded_completed
                if isinstance(encoded_identity, dict):
                    previous_cache_identity = {
                        str(key): str(value) for key, value in encoded_identity.items()
                    }
                cold_cache = False
        except (OSError, ValueError, TypeError):
            previous_inputs = {}

    current_cache_identity = dict(sorted((cache_identity or {}).items()))
    identity_changed = previous_cache_identity != current_cache_identity
    current_inputs = workspace_input_hashes(root, WORKSPACE_SOURCE_EXCLUDED_PARTS)
    changed = sorted(
        path
        for path, digest in current_inputs.items()
        if previous_inputs.get(path) != digest
    )
    removed = sorted(set(previous_inputs).difference(current_inputs))
    touched = set(changed)
    if identity_changed:
        touched.update(current_inputs)
    if removed:
        touched.update(
            path
            for path in current_inputs
            if path == "Cargo.lock"
            or path.endswith("/Cargo.toml")
            or path == "Cargo.toml"
        )

    touched_at_ns = max(time.time_ns(), previous_completed_at_ns + 1)
    for relative in sorted(touched):
        source = root / relative
        if source.is_file() or source.is_symlink():
            os.utime(source, ns=(touched_at_ns, touched_at_ns), follow_symlinks=False)

    refresh: dict[str, object] = {
        "cold_cache": cold_cache,
        "workspace_input_sha256": workspace_input_sha256(current_inputs),
        "input_count": len(current_inputs),
        "changed_input_count": len(changed),
        "removed_input_count": len(removed),
        "touched_input_count": len(touched),
        "cache_identity_changed": identity_changed,
        "cache_identity": current_cache_identity,
    }
    return state_path, current_inputs, refresh


def commit_source_aware_target_cache(
    state_path: Path,
    inputs: Mapping[str, str],
    cache_identity: Mapping[str, str] | None = None,
) -> None:
    state = {
        "cache_identity": dict(sorted((cache_identity or {}).items())),
        "completed_at_ns": time.time_ns(),
        "inputs": dict(sorted(inputs.items())),
        "version": 2,
    }
    temporary = state_path.with_name(f"{state_path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(state, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, state_path)


def target_cache_identity(
    target: str | None,
    cargo_command: Sequence[str],
    environment: Mapping[str, str],
) -> dict[str, str]:
    rustflags = environment.get("RUSTFLAGS", "")
    encoded_rustflags = environment.get("CARGO_ENCODED_RUSTFLAGS", "")
    return {
        "cargo_command": "\x1f".join(cargo_command),
        "host_machine": platform.machine().lower(),
        "host_system": platform.system().lower(),
        "rustflags_sha256": hashlib.sha256(rustflags.encode()).hexdigest(),
        "encoded_rustflags_sha256": hashlib.sha256(
            encoded_rustflags.encode()
        ).hexdigest(),
        "target": target or "host",
    }
