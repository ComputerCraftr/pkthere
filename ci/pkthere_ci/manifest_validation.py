"""Typed CI manifest validation."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Protocol

from .evidence_types import EvidenceContract


class ManifestSelection(Protocol):
    @property
    def evidence_id(self) -> str: ...

    @property
    def invariant_id(self) -> str: ...

    @property
    def evidence_class(self) -> str: ...


def validate_manifest(
    selections: Sequence[ManifestSelection],
    contracts: Mapping[str, EvidenceContract],
) -> None:
    evidence_ids = [selection.evidence_id for selection in selections]
    duplicates = sorted(
        evidence_id
        for evidence_id, count in Counter(evidence_ids).items()
        if count != 1
    )
    if duplicates:
        raise RuntimeError(f"duplicate release evidence IDs: {duplicates}")
    selected = frozenset(evidence_ids)
    contracted = frozenset(contracts)
    if selected != contracted:
        raise RuntimeError(
            "release evidence contracts and selections differ: "
            f"missing={sorted(contracted - selected)}, "
            f"uncontracted={sorted(selected - contracted)}"
        )
    mismatches = [
        selection.evidence_id
        for selection in selections
        if (
            selection.invariant_id != contracts[selection.evidence_id].invariant_id
            or selection.evidence_class
            != contracts[selection.evidence_id].evidence_class
        )
    ]
    if mismatches:
        raise RuntimeError(f"release evidence contracts differ: {sorted(mismatches)}")
