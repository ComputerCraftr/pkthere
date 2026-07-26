"""Canonical test ownership manifest."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .authority_selection_additions import (
    ADDITIONAL_AUTHORITY_CONTRACTS,
    additional_core_authority_tests,
    negative_authority_tests,
    structural_authority_tests,
)
from .evidence_types import (
    PRIVILEGED_RAW_SOCKET_PLATFORMS,
    PRODUCTION_RAW_FORWARDING_PLATFORMS,
    EvidenceContract,
)
from .manifest_validation import validate_manifest
from .platform_selection import selections_for_platform
from .selection_arguments import (
    CargoTestSelection,
    ExecutionIsolation,
    negative_control_test,
    platform_reality_test,
    production_core_test,
    structural_policy_test,
)

RAW_ICMP_TEST_ENVIRONMENT = MappingProxyType({"PKTHERE_ALLOW_RAW_ICMP": "1"})
EVIDENCE_CONTRACTS: Mapping[str, EvidenceContract] = MappingProxyType(
    {
        **ADDITIONAL_AUTHORITY_CONTRACTS,
        "unprivileged-udp-socket-reality": EvidenceContract(
            "UNPRIVILEGED-REALITY-001", "platform-reality"
        ),
        "unprivileged-icmp-dgram-socket-reality": EvidenceContract(
            "UNPRIVILEGED-REALITY-001", "platform-reality"
        ),
        "unprivileged-raw-privilege-boundary": EvidenceContract(
            "PRIVILEGE-ISOLATION-001", "platform-reality"
        ),
        "native-udp-lifecycle-reality": EvidenceContract(
            "PLAT-UDP-LIFECYCLE-001", "platform-reality"
        ),
        "hotpath-udp-c2u-allocation": EvidenceContract(
            "HOTPATH-ALLOC-001", "production-core"
        ),
        "hotpath-udp-u2c-allocation": EvidenceContract(
            "HOTPATH-ALLOC-001", "production-core"
        ),
        "hotpath-icmp-c2u-allocation": EvidenceContract(
            "HOTPATH-ALLOC-001", "production-core"
        ),
        "hotpath-icmp-u2c-allocation": EvidenceContract(
            "HOTPATH-ALLOC-001", "production-core"
        ),
        "payload-copy-initial-handshake": EvidenceContract(
            "PAYLOAD-COPY-001", "production-core"
        ),
        "payload-copy-activation-recovery": EvidenceContract(
            "PAYLOAD-COPY-001", "production-core"
        ),
        "payload-copy-critical-retry": EvidenceContract(
            "PAYLOAD-COPY-001", "production-core"
        ),
        "payload-copy-sync-replacement": EvidenceContract(
            "PAYLOAD-COPY-001", "production-core"
        ),
        "udp-complete-pipeline-overlap": EvidenceContract(
            "BARRIER-UDP-001", "production-core"
        ),
        "icmp-complete-pipeline-overlap": EvidenceContract(
            "BARRIER-ICMP-001", "production-core"
        ),
        "stable-send-reset": EvidenceContract("STALE-SEND-001", "production-core"),
        "stable-send-prepared-session": EvidenceContract(
            "STALE-SEND-001", "production-core"
        ),
        "flow-snapshot": EvidenceContract("ATOMIC-PUB-001", "production-core"),
        "idle-transition-current": EvidenceContract(
            "IDLE-TRANSITION-CORE-001", "production-core"
        ),
        "idle-transition-retired": EvidenceContract(
            "IDLE-TRANSITION-CORE-001", "production-core"
        ),
        "send-completion-success": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-failure": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-success-retirement": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-failure-retirement": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-duplicate-control": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-conflicting-control": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-reservation-retirement": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-reservation-abandonment": EvidenceContract(
            "SEND-RESERVATION-CLEANUP-001", "production-core"
        ),
        "send-completion-terminal-retirement": EvidenceContract(
            "SEND-COMPLETION-CORE-001", "production-core"
        ),
        "send-completion-two-sequence-slot": EvidenceContract(
            "SEND-DEFERRED-SLOTS-001", "production-core"
        ),
        "send-completion-weakened-stranding": EvidenceContract(
            "LOOM-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "observation-lifecycle-publish-clear": EvidenceContract(
            "OBSERVATION-LIFECYCLE-001", "production-core"
        ),
        "observation-lifecycle-stale-publish": EvidenceContract(
            "OBSERVATION-LIFECYCLE-001", "production-core"
        ),
        "observation-lifecycle-empty-receive": EvidenceContract(
            "OBSERVATION-LIFECYCLE-001", "production-core"
        ),
        "observation-lifecycle-exact-expiry": EvidenceContract(
            "ICMP-OBS-BINDING-001", "production-core"
        ),
        "observation-exact-binding": EvidenceContract(
            "ICMP-OBS-BINDING-001", "production-core"
        ),
        "flow-reservation-consuming": EvidenceContract(
            "RESERVATION-TYPESTATE-001", "production-core"
        ),
        "flow-reservation-unwind": EvidenceContract(
            "RESERVATION-TYPESTATE-001", "production-core"
        ),
        "local-recorder-thread-owned": EvidenceContract(
            "LOCAL-RECORDER-OWNERSHIP-001", "production-core"
        ),
        "local-recorder-panic-cleanup": EvidenceContract(
            "LOCAL-RECORDER-OWNERSHIP-001", "production-core"
        ),
        "test-state-authority-policy": EvidenceContract(
            "TEST-STATE-AUTHORITY-001", "structural-policy"
        ),
        "interior-mutability-inventory-policy": EvidenceContract(
            "INTERIOR-MUTABILITY-INVENTORY-001", "structural-policy"
        ),
        "fifo-ticket-allocation": EvidenceContract(
            "FIFO-RESERVATION-001", "production-core"
        ),
        "fifo-cancellation-release": EvidenceContract(
            "FIFO-RESERVATION-001", "production-core"
        ),
        "fifo-contiguous-cancellation": EvidenceContract(
            "FIFO-RESERVATION-001", "production-core"
        ),
        "fifo-foreign-release": EvidenceContract(
            "FIFO-RESERVATION-001", "production-core"
        ),
        "sync-send-lifecycle": EvidenceContract(
            "SYNC-SEND-LIFECYCLE-001", "production-core"
        ),
        "flow-writer-fifo-progress": EvidenceContract(
            "WRITER-PROGRESS-001", "production-core"
        ),
        "stale-retry-reset-binding": EvidenceContract(
            "STALE-SEND-001", "production-core"
        ),
        "stale-retry-payload-ownership": EvidenceContract(
            "STALE-SEND-001", "production-core"
        ),
        "stale-retry-foreign-flow": EvidenceContract(
            "STALE-SEND-001", "production-core"
        ),
        "receiver-transfer-unique-owner": EvidenceContract(
            "RECEIVER-TRANSFER-001", "production-core"
        ),
        "receiver-transfer-publication": EvidenceContract(
            "RECEIVER-TRANSFER-001", "production-core"
        ),
        "receiver-transfer-exit": EvidenceContract(
            "RECEIVER-TRANSFER-001", "production-core"
        ),
        "stats-finality-fifo-marker": EvidenceContract(
            "STATS-FINALITY-001", "production-core"
        ),
        "stats-finality-queue-full": EvidenceContract(
            "STATS-FINALITY-001", "production-core"
        ),
        "stats-finality-abandonment": EvidenceContract(
            "STATS-FINALITY-001", "production-core"
        ),
        "stats-finality-notification": EvidenceContract(
            "STATS-FINALITY-001", "production-core"
        ),
        "fifo-wake-generation": EvidenceContract(
            "WRITER-PROGRESS-001", "production-core"
        ),
        "fifo-shutdown-cancellation": EvidenceContract(
            "WRITER-PROGRESS-001", "production-core"
        ),
        "stats-finality-weakened-order": EvidenceContract(
            "LOOM-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "wait-reacquire-shutdown": EvidenceContract(
            "WAIT-REACQUIRE-001", "production-core"
        ),
        "wait-poison-fail-closed": EvidenceContract(
            "AUTH-POISON-001", "production-core"
        ),
        "wait-absolute-deadline": EvidenceContract(
            "WAIT-REACQUIRE-001", "production-core"
        ),
        "wait-spurious-recheck": EvidenceContract(
            "WAIT-REACQUIRE-001", "production-core"
        ),
        "authority-unwind-cleanup": EvidenceContract(
            "AUTH-UNWIND-001", "production-core"
        ),
        "shutdown-cause-publication": EvidenceContract(
            "SHUTDOWN-PUBLICATION-001", "production-core"
        ),
        "shutdown-primary-election": EvidenceContract(
            "SHUTDOWN-PUBLICATION-001", "production-core"
        ),
        "shutdown-cleanup-terminal": EvidenceContract(
            "SUPERVISOR-CLEANUP-001", "production-core"
        ),
        "shutdown-cleanup-owner": EvidenceContract(
            "SUPERVISOR-CLEANUP-001", "production-core"
        ),
        "group-publication-complete": EvidenceContract(
            "GROUP-PUBLICATION-001", "production-core"
        ),
        "group-publication-poison": EvidenceContract(
            "GROUP-PUBLICATION-001", "production-core"
        ),
        "group-publication-mutation-failure": EvidenceContract(
            "GROUP-PUBLICATION-001", "production-core"
        ),
        "group-publication-weakened-split": EvidenceContract(
            "LOOM-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "receiver-publication-weakened-split": EvidenceContract(
            "LOOM-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "atomic-publication-weakened-release": EvidenceContract(
            "LOOM-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "lane-admission-weakened-store-scan": EvidenceContract(
            "LOOM-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "authority-order-negative-smoke": EvidenceContract(
            "AUTHORITY-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "authority-logging-reservation-negative-smoke": EvidenceContract(
            "AUTHORITY-NEGATIVE-SMOKE-001", "negative-control"
        ),
        "handshake-timeout-commit": EvidenceContract(
            "HANDSHAKE-ACK-COMMIT-001", "production-core"
        ),
        "handshake-reset-rollback": EvidenceContract(
            "HANDSHAKE-ACK-COMMIT-001", "production-core"
        ),
        "handshake-stale-token": EvidenceContract(
            "HANDSHAKE-ACK-COMMIT-001", "production-core"
        ),
        "handshake-activation-payload-order": EvidenceContract(
            "HANDSHAKE-ACK-COMMIT-001", "production-core"
        ),
        "handshake-activation-poison": EvidenceContract(
            "HANDSHAKE-ACK-COMMIT-001", "production-core"
        ),
        "handshake-control-success-evidence": EvidenceContract(
            "HANDSHAKE-CONTROL-SEND-001", "production-core"
        ),
        "handshake-control-failure-retry": EvidenceContract(
            "HANDSHAKE-CONTROL-SEND-001", "production-core"
        ),
        "handshake-control-restart": EvidenceContract(
            "HANDSHAKE-CONTROL-SEND-001", "production-core"
        ),
        "handshake-control-unsequenced-release": EvidenceContract(
            "HANDSHAKE-CONTROL-SEND-001", "production-core"
        ),
        "receive-candidate-success-failure": EvidenceContract(
            "RECEIVE-CANDIDATE-ACK-001", "production-core"
        ),
        "receive-candidate-failed-leases": EvidenceContract(
            "RECEIVE-CANDIDATE-ACK-001", "production-core"
        ),
        "receive-candidate-expired-stale": EvidenceContract(
            "RECEIVE-CANDIDATE-ACK-001", "production-core"
        ),
        "recovery-send-lifecycle": EvidenceContract(
            "RECOVERY-SEND-CORE-001", "production-core"
        ),
        "linux-icmp-multihop": EvidenceContract(
            "PLAT-RAW-MULTIHOP-001", "platform-reality"
        ),
        "raw-wrong-source-id": EvidenceContract(
            "PLAT-RAW-ADMISSION-001", "platform-reality"
        ),
        "raw-four-disjoint-ids": EvidenceContract(
            "PLAT-RAW-ENDPOINT-ID-001", "platform-reality"
        ),
        "raw-wildcard-upstream": EvidenceContract(
            "PLAT-RAW-WILDCARD-001", "platform-reality"
        ),
        "raw-socket-reality": EvidenceContract(
            "PLAT-RAW-REALITY-001", "platform-reality"
        ),
        "alpine-multi-worker-udp-authority-stress": EvidenceContract(
            "HOTPATH-DIRECTION-001", "production-core"
        ),
        "alpine-multi-worker-icmp-authority-stress": EvidenceContract(
            "HOTPATH-DIRECTION-001", "production-core"
        ),
        "native-worker-pair-authority-stress": EvidenceContract(
            "HOTPATH-DIRECTION-001", "production-core"
        ),
        "alpine-receive-boundary": EvidenceContract(
            "RECEIVE-BOUNDARY-001", "synthetic-boundary"
        ),
        "alpine-destination-required-race": EvidenceContract(
            "STALE-SEND-001", "production-core"
        ),
        "alpine-shared-flow-publication": EvidenceContract(
            "ATOMIC-PUB-001", "production-core"
        ),
    }
)


PRIVILEGED_ICMP_TESTS = (
    CargoTestSelection(
        evidence_id="linux-icmp-multihop",
        package="pkthere",
        target_flag="--test",
        target_name="icmp_integration",
        test_name=(
            "icmp_sync_multihop_bridge_preserves_payload_through_pure_icmp_node"
        ),
        staged_executable="icmp-integration-test",
        platforms=frozenset({"linux", "android"}),
        ignored=True,
        evidence_class="platform-reality",
    ),
    CargoTestSelection(
        evidence_id="raw-wrong-source-id",
        package="pkthere",
        target_flag="--test",
        target_name="icmp_integration",
        test_name="raw_icmp_locked_flow_rejects_wrong_source_id",
        staged_executable="icmp-integration-test",
        platforms=PRODUCTION_RAW_FORWARDING_PLATFORMS,
        ignored=True,
        evidence_class="platform-reality",
    ),
    CargoTestSelection(
        evidence_id="raw-four-disjoint-ids",
        package="pkthere",
        target_flag="--test",
        target_name="icmp_integration",
        test_name="test_raw_icmp_independent_ids",
        staged_executable="icmp-integration-test",
        platforms=PRODUCTION_RAW_FORWARDING_PLATFORMS,
        ignored=True,
        evidence_class="platform-reality",
    ),
    CargoTestSelection(
        evidence_id="raw-wildcard-upstream",
        package="pkthere-test-support",
        target_flag="--lib",
        target_name=None,
        test_name=(
            "icmp_wildcard_cases::raw_icmp_wildcard_upstream_locks_on_localhost"
        ),
        staged_executable="pkthere-test-support-test",
        platforms=PRIVILEGED_RAW_SOCKET_PLATFORMS,
        ignored=True,
        evidence_class="platform-reality",
    ),
)

NATIVE_AUTHORITY_STRESS_TESTS = (
    CargoTestSelection(
        evidence_id="native-worker-pair-authority-stress",
        package="pkthere",
        target_flag="--test",
        target_name="stress",
        test_name="stress_test_ipv4",
        staged_executable="stress-test",
        platforms=frozenset({"macos", "windows", "freebsd"}),
        ignored=True,
        evidence_class="production-core",
    ),
)

RAW_SOCKET_REALITY_TEST = platform_reality_test(
    "raw-socket-reality",
    "raw_icmp_forwarder_packet_dump_matches_policy",
)

UNPRIVILEGED_SOCKET_REALITY_TESTS = (
    platform_reality_test(
        "unprivileged-raw-privilege-boundary",
        "unprivileged_raw_privilege_boundary_is_enforced",
        isolation=ExecutionIsolation.WINDOWS_RESTRICTED,
    ),
    platform_reality_test(
        "unprivileged-udp-socket-reality",
        "udp_reality_matches_policy",
        isolation=ExecutionIsolation.WINDOWS_RESTRICTED,
    ),
    platform_reality_test(
        "native-udp-lifecycle-reality",
        "udp_lifecycle_reality_matches_policy",
    ),
    platform_reality_test(
        "unprivileged-icmp-dgram-socket-reality",
        "icmp_dgram_reality_matches_policy",
        isolation=ExecutionIsolation.WINDOWS_RESTRICTED,
    ),
)

ALPINE_CONCURRENCY_TESTS = (
    CargoTestSelection(
        evidence_id="alpine-multi-worker-udp-authority-stress",
        package="pkthere",
        target_flag="--test",
        target_name="stress",
        test_name="stress_multi_worker_distributed_udp_ipv4",
        staged_executable="stress-test",
        platforms=frozenset({"linux"}),
        ignored=True,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="alpine-multi-worker-icmp-authority-stress",
        package="pkthere",
        target_flag="--test",
        target_name="stress",
        test_name="stress_multi_worker_distributed_icmp_ipv4",
        staged_executable="stress-test",
        platforms=frozenset({"linux"}),
        ignored=True,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="alpine-receive-boundary",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "net::managed_socket::receive_tests::"
            "multi_worker_receive_boundary_covers_zero_capacity_reuse_and_mixed_syscalls"
        ),
        staged_executable="pkthere-unit-test",
        platforms=frozenset({"linux"}),
        ignored=False,
        evidence_class="synthetic-boundary",
    ),
    CargoTestSelection(
        evidence_id="alpine-destination-required-race",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "net::managed_socket::concurrency_tests::"
            "concurrent_destination_required_sends_return_stale_without_inline_transition"
        ),
        staged_executable="pkthere-unit-test",
        platforms=frozenset({"linux"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="alpine-shared-flow-publication",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "net::sock_mgr::transaction_failure_tests::"
            "shared_flow_reader_blocks_until_all_managers_and_global_lock_are_published"
        ),
        staged_executable="pkthere-unit-test",
        platforms=frozenset({"linux"}),
        ignored=False,
        evidence_class="production-core",
    ),
)

CORE_AUTHORITY_TESTS = (
    *additional_core_authority_tests(production_core_test),
    CargoTestSelection(
        evidence_id="hotpath-udp-c2u-allocation",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "worker_support::dispatch::tests::"
            "locked_udp_production_send_path_is_allocation_and_copy_free_with_exact_delivery"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="hotpath-udp-u2c-allocation",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "worker_support::upstream::tests::"
            "locked_udp_u2c_production_send_path_is_allocation_copy_and_global_authority_free"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="hotpath-icmp-c2u-allocation",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "worker_support::dispatch::tests::"
            "active_icmp_c2u_production_send_path_is_allocation_copy_and_global_authority_free"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="hotpath-icmp-u2c-allocation",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "worker_support::upstream::tests::"
            "active_icmp_u2c_production_send_path_is_allocation_copy_and_global_authority_free"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="payload-copy-initial-handshake",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "flow_state::tests::handshake_completion::"
            "send_failure_retries_from_internal_state_without_duplicate_ack"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="payload-copy-activation-recovery",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "flow_state::recovery_tests::"
            "reset_required_recovers_retained_first_payload_without_echoing_it"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="payload-copy-critical-retry",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "flow_state::tests::rekey_tests::"
            "transmit_rekey_retains_triggering_payload_and_rejects_a_second_buffer"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    CargoTestSelection(
        evidence_id="payload-copy-sync-replacement",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "worker_support::sync_buffer::tests::"
            "sync_replacement_reports_old_trace_and_keeps_new_trace_pending"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    production_core_test(
        "udp-complete-pipeline-overlap",
        "worker_support::upstream_overlap_tests::"
        "udp_directions_overlap_through_complete_production_receive_to_send_pipeline",
    ),
    production_core_test(
        "icmp-complete-pipeline-overlap",
        "worker_support::upstream_overlap_tests::"
        "icmp_directions_overlap_through_complete_production_receive_to_send_pipeline",
    ),
    production_core_test(
        "stable-send-reset",
        "worker_support::stale_association_loom::"
        "production_stable_send_core_releases_protocol_socket_then_flow",
    ),
    production_core_test(
        "stable-send-prepared-session",
        "worker_support::stale_association_loom::"
        "production_prepared_session_reservation_cannot_cross_flow_publication",
    ),
    production_core_test(
        "flow-snapshot",
        "atomic_core::loom_tests::"
        "production_flow_snapshot_core_installs_snapshot_before_visibility",
    ),
    production_core_test(
        "idle-transition-current",
        "atomic_core::loom_tests::"
        "production_idle_transition_revalidates_activity_after_reader_drain",
    ),
    production_core_test(
        "idle-transition-retired",
        "atomic_core::loom_tests::"
        "production_idle_transition_ignores_retired_flow_activity",
    ),
    production_core_test(
        "send-completion-success",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_success_disposes_every_accepted_control_once",
    ),
    production_core_test(
        "send-completion-failure",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_failure_rejects_every_deferred_control_once",
    ),
    production_core_test(
        "send-completion-success-retirement",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_retirement_cannot_strand_or_double_apply_control",
    ),
    production_core_test(
        "send-completion-failure-retirement",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_failed_send_retirement_rejects_control_once",
    ),
    production_core_test(
        "send-completion-duplicate-control",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_duplicate_control_retains_one_disposition_owner",
    ),
    production_core_test(
        "send-completion-conflicting-control",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_conflicting_controls_have_one_deferred_owner",
    ),
    production_core_test(
        "send-completion-reservation-retirement",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_reservation_cannot_cross_retirement",
    ),
    production_core_test(
        "send-completion-terminal-retirement",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_completion_and_retirement_have_one_terminal_owner",
    ),
    production_core_test(
        "send-reservation-abandonment",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_abandoned_reservation_and_retirement_have_one_terminal_owner",
    ),
    production_core_test(
        "send-completion-two-sequence-slot",
        "net::icmp_sequence::send_completion_loom::"
        "production_core_two_sequences_have_independent_deferred_slots",
    ),
    production_core_test(
        "observation-lifecycle-publish-clear",
        "flow_state::observation_core_loom::"
        "production_observation_lifecycle_never_exposes_partial_or_stale_ownership",
    ),
    production_core_test(
        "observation-lifecycle-stale-publish",
        "flow_state::observation_core_loom::"
        "production_observation_lifecycle_rejects_publish_after_clear",
    ),
    production_core_test(
        "observation-lifecycle-empty-receive",
        "flow_state::observation_core_loom::"
        "production_observation_lifecycle_clears_polling_when_receive_has_no_control",
    ),
    production_core_test(
        "observation-lifecycle-exact-expiry",
        "flow_state::observation_core_loom::"
        "production_observation_expiry_requires_the_exact_binding_and_predeadline_receive",
    ),
    production_core_test(
        "observation-exact-binding",
        "flow_state::tests::handshake_completion::"
        "only_the_exact_pending_client_control_transaction_can_delay_expiry",
    ),
    production_core_test(
        "flow-reservation-consuming",
        "flow_state::tests::client_flow_reservation_commit_and_rollback_are_consuming",
    ),
    production_core_test(
        "flow-reservation-unwind",
        "flow_state::tests::client_flow_reservation_unwind_emergency_cleanup_releases_once",
    ),
    production_core_test(
        "local-recorder-thread-owned",
        "stats::tests::thread_owned_recorder_packet_updates_use_no_allocation_or_queue_rmw",
    ),
    production_core_test(
        "local-recorder-panic-cleanup",
        "stats::tests::worker_panic_flushes_recorder_before_terminal_publication",
    ),
    production_core_test(
        "fifo-ticket-allocation",
        "net::sock_mgr::fifo_core_loom::"
        "production_fifo_allocation_cannot_observe_a_false_exhaustion_during_progress",
    ),
    production_core_test(
        "fifo-cancellation-release",
        "net::sock_mgr::fifo_core_loom::"
        "production_fifo_core_cancellation_and_release_cannot_strand_successor",
    ),
    production_core_test(
        "fifo-contiguous-cancellation",
        "net::sock_mgr::fifo_core_loom::"
        "production_fifo_core_current_cancellation_drains_cancelled_successor",
    ),
    production_core_test(
        "fifo-foreign-release",
        "net::sock_mgr::fifo_core_loom::"
        "production_fifo_core_wrong_owner_cannot_release_current_ticket",
    ),
    production_core_test(
        "fifo-wake-generation",
        "net::sock_mgr::fifo_core_loom::"
        "production_fifo_reservation_wake_generation_closes_last_owner_race",
    ),
    production_core_test(
        "fifo-shutdown-cancellation",
        "net::sock_mgr::fifo_core_loom::"
        "production_fifo_reservation_shutdown_prevents_new_ownership",
    ),
    CargoTestSelection(
        evidence_id="flow-writer-fifo-progress",
        package="pkthere",
        target_flag="--bin",
        target_name="pkthere",
        test_name=(
            "flow_state::topology::tests::"
            "competing_flow_writers_are_served_fifo_without_reader_barging"
        ),
        staged_executable="pkthere-authority-audit-test",
        platforms=frozenset({"linux", "android", "macos", "windows", "freebsd"}),
        ignored=False,
        evidence_class="production-core",
    ),
    production_core_test(
        "stale-retry-reset-binding",
        "worker_support::stale_association_loom::"
        "production_stale_retry_core_holds_flow_lane_through_retry_or_loses_to_reset",
    ),
    production_core_test(
        "stale-retry-payload-ownership",
        "worker_support::stale_association_loom::"
        "production_stale_retry_core_is_one_shot_epoch_bound_and_payload_exact",
    ),
    production_core_test(
        "stale-retry-foreign-flow",
        "worker_support::stale_association_loom::"
        "production_stale_retry_core_rejects_foreign_flow_before_exposing_payload",
    ),
    production_core_test(
        "receiver-transfer-unique-owner",
        "net::sock_mgr::receiver_transfer_loom::"
        "production_receiver_core_allows_exactly_one_initial_owner",
    ),
    production_core_test(
        "receiver-transfer-publication",
        "net::sock_mgr::receiver_transfer_loom::"
        "production_receiver_core_publishes_resource_before_transfer_generation",
    ),
    production_core_test(
        "receiver-transfer-exit",
        "net::sock_mgr::receiver_transfer_loom::"
        "production_receiver_core_exit_and_replacement_never_leave_claimable_authority",
    ),
    production_core_test(
        "stats-finality-fifo-marker",
        "stats::finality_core_loom::"
        "production_stats_core_acknowledges_only_a_fifo_marker_after_its_delta",
    ),
    production_core_test(
        "stats-finality-queue-full",
        "stats::finality_core_loom::"
        "production_stats_core_queue_full_returns_owned_delta_for_exact_retry",
    ),
    production_core_test(
        "stats-finality-abandonment",
        "stats::finality_core_loom::"
        "production_stats_core_sealing_and_abandonment_have_one_terminal_owner",
    ),
    production_core_test(
        "stats-finality-notification",
        "stats::finality_core_loom::"
        "production_stats_core_notification_clear_recheck_cannot_lose_publication",
    ),
    production_core_test(
        "wait-reacquire-shutdown",
        "authority::wait_core_loom::"
        "production_wait_core_releases_waits_reacquires_and_rechecks_shutdown",
    ),
    production_core_test(
        "wait-poison-fail-closed",
        "authority::wait_core_loom::"
        "production_wait_core_never_restores_authority_after_poison",
    ),
    production_core_test(
        "wait-absolute-deadline",
        "authority::wait_core_loom::"
        "production_wait_core_propagates_timeout_and_reacquires_once",
    ),
    production_core_test(
        "wait-spurious-recheck",
        "authority::tests::condition_wait_rechecks_after_a_spurious_notification",
    ),
    production_core_test(
        "authority-unwind-cleanup",
        "authority::tests::unwind_releases_the_exact_audit_instance_without_panicking",
    ),
    production_core_test(
        "shutdown-cause-publication",
        "shutdown_publication::loom_tests::"
        "production_shutdown_core_never_exposes_fatal_without_its_cause",
    ),
    production_core_test(
        "shutdown-primary-election",
        "shutdown_publication::loom_tests::"
        "production_shutdown_core_gives_one_primary_owner_and_retains_secondary_cause",
    ),
    production_core_test(
        "shutdown-cleanup-terminal",
        "shutdown_publication::loom_tests::"
        "production_shutdown_core_requires_cleanup_before_terminal_publication",
    ),
    production_core_test(
        "shutdown-cleanup-owner",
        "shutdown_publication::loom_tests::production_shutdown_core_has_one_cleanup_owner",
    ),
    production_core_test(
        "group-publication-complete",
        "net::sock_mgr::group_publication_loom::"
        "production_group_publication_core_exposes_only_complete_published_state",
    ),
    production_core_test(
        "group-publication-poison",
        "net::sock_mgr::group_publication_loom::"
        "production_group_publication_core_poison_is_terminal_after_session_commit",
    ),
    production_core_test(
        "group-publication-mutation-failure",
        "net::sock_mgr::group_publication_loom::"
        "production_group_publication_core_validates_before_mutation_and_poison_on_failure",
    ),
    production_core_test(
        "handshake-timeout-commit",
        "flow_state::handshake::commit_core_loom::"
        "production_handshake_core_timeout_and_commit_have_one_payload_disposition",
    ),
    production_core_test(
        "handshake-reset-rollback",
        "flow_state::handshake::commit_core_loom::"
        "production_handshake_core_reset_and_manager_rollback_cannot_restore_retry",
    ),
    production_core_test(
        "handshake-stale-token",
        "flow_state::handshake::commit_core_loom::"
        "production_handshake_core_rejects_stale_and_duplicate_completion_tokens",
    ),
    production_core_test(
        "handshake-activation-payload-order",
        "flow_state::handshake::commit_core_loom::"
        "production_handshake_core_never_leases_payload_before_receive_activation",
    ),
    production_core_test(
        "handshake-activation-poison",
        "flow_state::handshake::commit_core_loom::"
        "production_handshake_core_poison_after_session_commit_is_terminal",
    ),
    production_core_test(
        "handshake-control-success-evidence",
        "flow_state::handshake::control_send_core_loom::"
        "production_control_send_core_keeps_ack_evidence_during_success_completion",
    ),
    production_core_test(
        "handshake-control-failure-retry",
        "flow_state::handshake::control_send_core_loom::"
        "production_control_send_core_failure_and_retry_retain_one_lease_owner",
    ),
    production_core_test(
        "handshake-control-restart",
        "flow_state::handshake::control_send_core_loom::"
        "production_control_send_core_restart_cannot_clear_an_owned_send",
    ),
    production_core_test(
        "handshake-control-unsequenced-release",
        "flow_state::handshake::control_send_core_loom::"
        "production_control_send_core_unsequenced_release_consumes_its_attempt",
    ),
    production_core_test(
        "receive-candidate-success-failure",
        "flow_state::receive_candidate_ack_loom::"
        "production_candidate_core_concurrent_success_and_failure_have_one_ready_state",
    ),
    production_core_test(
        "receive-candidate-failed-leases",
        "flow_state::receive_candidate_ack_loom::"
        "production_candidate_core_all_failed_leases_return_to_negotiating",
    ),
    production_core_test(
        "receive-candidate-expired-stale",
        "flow_state::receive_candidate_ack_loom::"
        "production_candidate_core_rejects_expired_and_stale_send_authority",
    ),
    production_core_test(
        "recovery-send-lifecycle",
        "flow_state::recovery_core_loom::"
        "production_recovery_core_timeout_and_completion_have_one_terminal_owner",
    ),
    production_core_test(
        "sync-send-lifecycle",
        "flow_state::sync_slot::sync_slot_loom::"
        "production_sync_core_models_reset_and_replacement_ownership",
    ),
)

NEGATIVE_AUTHORITY_SMOKE_TESTS = negative_authority_tests(negative_control_test)
STRUCTURAL_AUTHORITY_TESTS = structural_authority_tests(structural_policy_test)

ALL_RELEASE_TEST_SELECTIONS = (
    *CORE_AUTHORITY_TESTS,
    *NEGATIVE_AUTHORITY_SMOKE_TESTS,
    *STRUCTURAL_AUTHORITY_TESTS,
    *PRIVILEGED_ICMP_TESTS,
    *UNPRIVILEGED_SOCKET_REALITY_TESTS,
    RAW_SOCKET_REALITY_TEST,
    *ALPINE_CONCURRENCY_TESTS,
    *NATIVE_AUTHORITY_STRESS_TESTS,
)


def validate_release_test_manifest() -> None:
    validate_manifest(ALL_RELEASE_TEST_SELECTIONS, EVIDENCE_CONTRACTS)


def privileged_icmp_tests_for_platform(platform: str) -> tuple[CargoTestSelection, ...]:
    return selections_for_platform(PRIVILEGED_ICMP_TESTS, platform)


def alpine_concurrency_tests_for_platform(
    platform: str,
) -> tuple[CargoTestSelection, ...]:
    return selections_for_platform(ALPINE_CONCURRENCY_TESTS, platform)


def authority_stress_tests_for_platform(
    platform: str,
) -> tuple[CargoTestSelection, ...]:
    return tuple(
        selection
        for selection in selections_for_platform(
            (*ALPINE_CONCURRENCY_TESTS, *NATIVE_AUTHORITY_STRESS_TESTS), platform
        )
        if selection.staged_executable == "stress-test"
    )
