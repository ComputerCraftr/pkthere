"""Negative-control identities owned by CI."""

from __future__ import annotations

NEGATIVE_AUTHORITY_SMOKE_SPECS = (
    (
        "atomic-publication-weakened-release",
        "atomic_core::loom_tests::production_core_model_detects_weakened_release_publication",
    ),
    (
        "lane-admission-weakened-store-scan",
        "atomic_core::loom_tests::weakened_lane_store_and_scan_recreates_hidden_reader",
    ),
    (
        "send-completion-weakened-stranding",
        "net::icmp_sequence::send_completion_loom::weakened_split_pending_check_recreates_the_stranded_control",
    ),
    (
        "stats-finality-weakened-order",
        "stats::finality_core_loom::weakened_marker_before_delta_is_rejected_by_the_production_consumer",
    ),
    (
        "group-publication-weakened-split",
        "net::sock_mgr::group_publication_loom::weakened_split_manager_and_receiver_publication_exposes_mixed_state",
    ),
    (
        "receiver-publication-weakened-split",
        "net::sock_mgr::receiver_transfer_loom::weakened_split_receiver_generation_exposes_missing_resource",
    ),
    (
        "authority-order-negative-smoke",
        "authority::tests::negative_smoke_reversed_send_order_is_rejected_by_authority_graph",
    ),
    (
        "authority-logging-reservation-negative-smoke",
        "authority::tests::negative_smoke_logging_is_rejected_under_flow_and_manager_authorities",
    ),
)
