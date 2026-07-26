"""Exact argument construction for manifest-owned selections."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .evidence_types import (
    PRIVILEGED_RAW_SOCKET_PLATFORMS,
    EvidenceBindingMixin,
)


class CargoArgumentMixin:
    test_name: str
    ignored: bool
    target_flag: str
    target_name: str | None
    package: str

    def harness_arguments(self) -> tuple[str, ...]:
        arguments = [self.test_name, "--exact"]
        if self.ignored:
            arguments.append("--ignored")
        arguments.append("--nocapture")
        return tuple(arguments)

    def cargo_arguments(self) -> tuple[str, ...]:
        target = (
            (self.target_flag, self.target_name)
            if self.target_name is not None
            else (self.target_flag,)
        )
        return (
            "cargo",
            "test",
            "--locked",
            "-p",
            self.package,
            *target,
            "--",
            *self.harness_arguments(),
        )

    def cargo_listing_arguments(self) -> tuple[str, ...]:
        target = (
            (self.target_flag, self.target_name)
            if self.target_name is not None
            else (self.target_flag,)
        )
        return (
            "cargo",
            "test",
            "--locked",
            "-p",
            self.package,
            *target,
            "--",
            "--list",
        )

    def executable_arguments(self, executable: str) -> tuple[str, ...]:
        return (executable, *self.harness_arguments())


class ExecutionIsolation(Enum):
    NATIVE_BASE = "native-base"
    WINDOWS_RESTRICTED = "windows-restricted"


@dataclass(frozen=True)
class CargoTestSelection(CargoArgumentMixin, EvidenceBindingMixin):
    evidence_id: str
    package: str
    target_flag: str
    target_name: str | None
    test_name: str
    staged_executable: str
    platforms: frozenset[str]
    ignored: bool
    evidence_class: str
    execution_isolation: ExecutionIsolation = ExecutionIsolation.NATIVE_BASE

    @property
    def invariant_id(self) -> str:
        from .test_manifest import EVIDENCE_CONTRACTS

        contract = EVIDENCE_CONTRACTS.get(self.evidence_id)
        if contract is None:
            raise RuntimeError(f"unknown release evidence ID: {self.evidence_id}")
        if contract.evidence_class != self.evidence_class:
            raise RuntimeError(
                f"evidence class mismatch for {self.evidence_id}: "
                f"manifest={self.evidence_class}, contract={contract.evidence_class}"
            )
        return contract.invariant_id


def production_core_test(evidence_id: str, test_name: str) -> CargoTestSelection:
    return _authority_test(
        evidence_id, test_name, "production-core", "--bin", "pkthere"
    )


def negative_control_test(evidence_id: str, test_name: str) -> CargoTestSelection:
    return _authority_test(
        evidence_id, test_name, "negative-control", "--bin", "pkthere"
    )


def structural_policy_test(evidence_id: str, test_name: str) -> CargoTestSelection:
    return _authority_test(
        evidence_id, test_name, "structural-policy", "--test", "policy"
    )


def platform_reality_test(
    evidence_id: str,
    test_name: str,
    *,
    isolation: ExecutionIsolation = ExecutionIsolation.NATIVE_BASE,
) -> CargoTestSelection:
    return CargoTestSelection(
        evidence_id=evidence_id,
        package="pkthere",
        target_flag="--test",
        target_name="socket_reality",
        test_name=test_name,
        staged_executable="socket-reality-test",
        platforms=PRIVILEGED_RAW_SOCKET_PLATFORMS,
        ignored=True,
        evidence_class="platform-reality",
        execution_isolation=isolation,
    )


def _authority_test(
    evidence_id: str,
    test_name: str,
    evidence_class: str,
    target_flag: str,
    target_name: str,
) -> CargoTestSelection:
    return CargoTestSelection(
        evidence_id=evidence_id,
        package="pkthere",
        target_flag=target_flag,
        target_name=target_name,
        test_name=test_name,
        staged_executable=(
            "pkthere-authority-audit-test" if target_flag == "--bin" else "policy-test"
        ),
        platforms=PRIVILEGED_RAW_SOCKET_PLATFORMS,
        ignored=False,
        evidence_class=evidence_class,
    )
