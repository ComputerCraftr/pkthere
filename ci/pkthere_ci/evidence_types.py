"""Typed CI evidence identities."""

from __future__ import annotations

import stat
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path

PRIVILEGED_RAW_SOCKET_PLATFORMS = frozenset(
    {"linux", "android", "macos", "windows", "freebsd"}
)
PRODUCTION_RAW_FORWARDING_PLATFORMS = frozenset({"linux", "android", "windows"})


@dataclass(frozen=True)
class ArtifactIdentity:
    path: Path
    sha256: str
    mode: int
    uid: int
    gid: int
    privilege_metadata: str

    @classmethod
    def inspect(cls, path: Path, privilege_metadata: str) -> ArtifactIdentity:
        from .provenance import sha256_file

        metadata = path.stat()
        return cls(
            path=path,
            sha256=sha256_file(path),
            mode=stat.S_IMODE(metadata.st_mode),
            uid=getattr(metadata, "st_uid", 0),
            gid=getattr(metadata, "st_gid", 0),
            privilege_metadata=privilege_metadata,
        )

    def evidence_payload(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "privilege_metadata": self.privilege_metadata,
        }


@dataclass(frozen=True)
class EvidenceContract:
    invariant_id: str
    evidence_class: str


@dataclass(frozen=True)
class DiscoveredTestEvidence:
    evidence_id: str
    invariant_id: str
    evidence_class: str
    package: str
    target_flag: str
    target_name: str | None
    test_name: str
    executable: str


class EvidenceBindingMixin:
    evidence_id: str
    evidence_class: str
    package: str
    target_flag: str
    target_name: str | None
    test_name: str

    @property
    @abstractmethod
    def invariant_id(self) -> str: ...

    def bind_discovered_test(
        self, listing_output: str, executable: str
    ) -> DiscoveredTestEvidence:
        from .test_discovery import require_exactly_one_listed_rust_test

        require_exactly_one_listed_rust_test(listing_output, self.test_name)
        return DiscoveredTestEvidence(
            evidence_id=self.evidence_id,
            invariant_id=self.invariant_id,
            evidence_class=self.evidence_class,
            package=self.package,
            target_flag=self.target_flag,
            target_name=self.target_name,
            test_name=self.test_name,
            executable=executable,
        )
