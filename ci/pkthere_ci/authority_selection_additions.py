"""Authority-audit test selection additions."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

from .evidence_types import EvidenceContract
from .negative_control_specs import NEGATIVE_AUTHORITY_SMOKE_SPECS

ADDITIONAL_AUTHORITY_CONTRACTS: Mapping[str, EvidenceContract] = MappingProxyType(
    {
        "fifo-lease-explicit-completion": EvidenceContract(
            "FIFO-RESERVATION-001", "production-core"
        ),
        "fifo-lease-emergency-drop": EvidenceContract(
            "FIFO-RESERVATION-001", "production-core"
        ),
        "send-arm-control-retirement": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "observation-overlapping-writer": EvidenceContract(
            "OBSERVATION-LIFECYCLE-001", "production-core"
        ),
        "recovery-recognition-completion": EvidenceContract(
            "RECOVERY-SEND-CORE-001", "production-core"
        ),
        "recovery-deferred-reset": EvidenceContract(
            "RECOVERY-SEND-CORE-001", "production-core"
        ),
        "shutdown-completion-final-state": EvidenceContract(
            "SUPERVISOR-CLEANUP-001", "production-core"
        ),
        "diagnostic-capture-transaction": EvidenceContract(
            "DIAGNOSTIC-CAPTURE-001", "production-core"
        ),
        "worker-state-transaction": EvidenceContract(
            "WORKER-STATE-TRANSACTION-001", "production-core"
        ),
    }
)

ADDITIONAL_CORE_AUTHORITY_TEST_SPECS = (
    (
        "fifo-lease-explicit-completion",
        "net::sock_mgr::fifo_core_loom::production_fifo_lease_explicit_completion_cannot_double_release",
    ),
    (
        "fifo-lease-emergency-drop",
        "net::sock_mgr::fifo_core_loom::production_fifo_lease_drop_releases_exact_ticket",
    ),
    (
        "send-arm-control-retirement",
        "net::icmp_sequence::send_completion_loom::production_core_arm_control_and_retirement_dispose_every_accepted_control",
    ),
    (
        "observation-overlapping-writer",
        "flow_state::observation_core_loom::production_observation_lifecycle_rejects_overlapping_lane_writers",
    ),
    (
        "recovery-recognition-completion",
        "flow_state::recovery_core_loom::production_recovery_core_recognition_and_send_completion_do_not_lose_ownership",
    ),
    (
        "recovery-deferred-reset",
        "flow_state::recovery_core_loom::production_recovery_core_deferred_reset_is_returned_exactly_once",
    ),
    (
        "shutdown-completion-final-state",
        "shutdown_publication::loom_tests::production_shutdown_core_reloads_fatal_after_supervisor_completion",
    ),
    (
        "diagnostic-capture-transaction",
        "stats::diagnostic_capture_loom::production_diagnostic_capture_never_holds_flow_while_recapturing_manager",
    ),
    (
        "worker-state-transaction",
        "worker_support::cache::transaction_loom::production_worker_state_transaction_never_publishes_mixed_resources",
    ),
)


def additional_core_authority_tests[Selection](
    factory: Callable[[str, str], Selection],
) -> tuple[Selection, ...]:
    return tuple(
        factory(evidence_id, test_name)
        for evidence_id, test_name in ADDITIONAL_CORE_AUTHORITY_TEST_SPECS
    )


def negative_authority_tests[Selection](
    factory: Callable[[str, str], Selection],
) -> tuple[Selection, ...]:
    return tuple(
        factory(evidence_id, test_name)
        for evidence_id, test_name in NEGATIVE_AUTHORITY_SMOKE_SPECS
    )


def structural_authority_tests[Selection](
    factory: Callable[[str, str], Selection],
) -> tuple[Selection, ...]:
    return (
        factory(
            "test-state-authority-policy",
            "production_types_have_no_mutable_test_only_authority",
        ),
        factory(
            "interior-mutability-inventory-policy",
            "interior_mutability_authorities_are_registered",
        ),
    )
