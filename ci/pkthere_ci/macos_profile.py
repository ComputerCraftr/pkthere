"""Policy helpers for reproducible macOS Time Profiler artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from ci.pkthere_ci.build_environment import sanitize_environment

SUPPORTED_TARGETS = frozenset({"aarch64-apple-darwin", "x86_64-apple-darwin"})
CPU_POLICIES = frozenset({"portable", "native"})
ENCODED_FLAG_SEPARATOR = "\x1f"
_UUID_PATTERN = re.compile(r"UUID:\s+([0-9A-Fa-f-]{36})\s+\([^)]+\)\s+.+")


@dataclass(frozen=True)
class ProfilingPaths:
    target_dir: Path
    binary: Path
    dsym: Path
    dwarf_directory: Path
    evidence_dir: Path


def parse_rustc_host(verbose_version: str) -> str:
    for line in verbose_version.splitlines():
        if line.startswith("host: "):
            host = line.removeprefix("host: ").strip()
            if host:
                return host
    raise ValueError("rustc verbose version omitted its host triple")


def intentional_flags(cpu_policy: str) -> tuple[str, ...]:
    if cpu_policy not in CPU_POLICIES:
        raise ValueError(f"unsupported macOS CPU policy: {cpu_policy}")
    target_cpu = "generic" if cpu_policy == "portable" else "native"
    return (
        "-C",
        f"target-cpu={target_cpu}",
        "-C",
        "force-frame-pointers=yes",
    )


def profiling_environment(
    source: dict[str, str],
    *,
    cpu_policy: str,
    target_dir: Path,
) -> tuple[dict[str, str], tuple[str, ...], tuple[str, ...]]:
    environment, removed = sanitize_environment(source)
    flags = intentional_flags(cpu_policy)
    environment["CARGO_ENCODED_RUSTFLAGS"] = ENCODED_FLAG_SEPARATOR.join(flags)
    environment["CARGO_TARGET_DIR"] = str(target_dir)
    return environment, removed, flags


def profiling_paths(
    root: Path,
    evidence_root: Path,
    target: str,
    cpu_policy: str,
) -> ProfilingPaths:
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported macOS profiling target: {target}")
    if cpu_policy not in CPU_POLICIES:
        raise ValueError(f"unsupported macOS CPU policy: {cpu_policy}")
    target_dir = root / "target" / "macos_profile" / target / cpu_policy
    binary = target_dir / target / "profiling" / "pkthere"
    dsym = binary.with_name(f"{binary.name}.dSYM")
    dwarf_directory = dsym / "Contents" / "Resources" / "DWARF"
    return ProfilingPaths(
        target_dir=target_dir,
        binary=binary,
        dsym=dsym,
        dwarf_directory=dwarf_directory,
        evidence_dir=evidence_root / target / cpu_policy,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_dwarf_payload(paths: ProfilingPaths) -> Path:
    payloads = sorted(
        path for path in paths.dwarf_directory.iterdir() if path.is_file()
    )
    if len(payloads) != 1:
        raise ValueError("profiling dSYM must contain exactly one DWARF payload")
    return payloads[0]


def deterministic_bundle_manifest(bundle: Path) -> tuple[str, str]:
    bundle = bundle.resolve()
    entries = [
        {
            "path": path.relative_to(bundle).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(
            candidate for candidate in bundle.rglob("*") if candidate.is_file()
        )
    ]
    rendered = json.dumps(entries, indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(rendered.encode()).hexdigest()
    return rendered, digest


def parse_dwarfdump_uuids(output: str) -> frozenset[str]:
    return frozenset(match.group(1).upper() for match in _UUID_PATTERN.finditer(output))
