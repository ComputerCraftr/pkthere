use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use syn::visit::Visit;

const TEST_CONTRACTS: &[TestContract] = &[
    TestContract::new(
        "src/worker_support/dispatch/tests.rs",
        "locked_udp_production_send_path_is_allocation_and_copy_free_with_exact_delivery",
        &[
            "count_allocations",
            "count_payload_copies",
            "count_lock_candidate_constructions",
            "capture",
            "assert_unchanged",
            "send_user_payload_event",
            "recv_from",
        ],
    ),
    TestContract::new(
        "src/worker_support/dispatch/tests.rs",
        "active_icmp_c2u_production_send_path_is_allocation_copy_and_global_authority_free",
        &[
            "count_allocations",
            "count_payload_copies",
            "count_lock_candidate_constructions",
            "capture",
            "assert_unchanged",
            "send_user_payload_event",
            "recv_from",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream/tests.rs",
        "locked_udp_u2c_production_send_path_is_allocation_copy_and_global_authority_free",
        &[
            "count_allocations",
            "count_payload_copies",
            "capture",
            "assert_unchanged",
            "process_admitted_upstream_event",
            "recv_from",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream/tests.rs",
        "active_icmp_u2c_production_send_path_is_allocation_copy_and_global_authority_free",
        &[
            "count_allocations",
            "count_payload_copies",
            "capture",
            "assert_unchanged",
            "process_admitted_upstream_event",
            "recv_from",
        ],
    ),
    TestContract::new(
        "src/flow_state/tests/handshake_completion.rs",
        "send_failure_retries_from_internal_state_without_duplicate_ack",
        &[
            "count_payload_copies",
            "begin_upstream_reply_id_handshake",
            "release_upstream_reply_id_payload_send",
            "lease_due_upstream_reply_id_payload",
            "shares_payload_storage",
        ],
    ),
    TestContract::new(
        "src/flow_state/recovery_tests.rs",
        "reset_required_recovers_retained_first_payload_without_echoing_it",
        &[
            "count_payload_copies",
            "retain_first_upstream_recovery_payload",
            "recover_upstream_session",
        ],
    ),
    TestContract::new(
        "src/flow_state/tests/rekey_tests.rs",
        "transmit_rekey_retains_triggering_payload_and_rejects_a_second_buffer",
        &[
            "count_payload_copies",
            "begin_upstream_rekey_from_event",
            "release_upstream_reply_id_payload_send",
            "lease_due_upstream_reply_id_payload",
            "shares_payload_storage",
        ],
    ),
    TestContract::new(
        "src/worker_support/sync_buffer/tests.rs",
        "sync_replacement_reports_old_trace_and_keeps_new_trace_pending",
        &[
            "count_payload_copies",
            "store_sync_payload",
            "lease_sync_send",
            "payload_storage_strong_count",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "udp_directions_overlap_through_complete_production_receive_to_send_pipeline",
        &[
            "prove_udp_complete_pipeline_overlap",
            "COMPLETE_PIPELINE_STAGES",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "prove_udp_complete_pipeline_overlap",
        &[
            "arm",
            "wait_until_arrived",
            "run_client_to_upstream_thread",
            "run_upstream_to_client_thread",
            "send_to",
            "receive_exact",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "receive_exact",
        &["recv_from"],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "icmp_directions_overlap_through_complete_production_receive_to_send_pipeline",
        &[
            "prove_icmp_complete_pipeline_overlap",
            "COMPLETE_PIPELINE_STAGES",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "prove_icmp_complete_pipeline_overlap",
        &[
            "arm",
            "wait_until_arrived",
            "run_client_to_upstream_thread",
            "run_upstream_to_client_thread",
            "send_to",
            "receive_icmp_payload",
        ],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "prove_bidirectional_send_overlap",
        &[
            "arm",
            "wait_until_arrived",
            "recv_timeout",
            "run_c2u",
            "run_u2c",
        ],
    ),
    TestContract::new(
        "src/worker_support/stale_association_loom.rs",
        "production_stable_send_core_releases_protocol_socket_then_flow",
        &[
            "new",
            "acquire_socket",
            "reserve_protocol",
            "perform",
            "close_epoch_gate",
        ],
    ),
    TestContract::new(
        "src/atomic_core/loom_tests.rs",
        "production_flow_snapshot_core_installs_snapshot_before_visibility",
        &["new", "install_snapshot", "publish_visibility"],
    ),
    TestContract::new(
        "src/atomic_core/loom_tests.rs",
        "production_idle_transition_revalidates_activity_after_reader_drain",
        &["attempt_idle_transition"],
    ),
    TestContract::new(
        "src/atomic_core/loom_tests.rs",
        "production_idle_transition_ignores_retired_flow_activity",
        &["attempt_idle_transition"],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "run_c2u",
        &["send_user_payload_event"],
    ),
    TestContract::new(
        "src/worker_support/upstream_overlap_tests.rs",
        "run_u2c",
        &["process_admitted_upstream_event"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_success_disposes_every_accepted_control_once",
        &["model_completion"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_failure_rejects_every_deferred_control_once",
        &["model_completion"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_retirement_cannot_strand_or_double_apply_control",
        &["model_completion"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_failed_send_retirement_rejects_control_once",
        &["model_completion"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_duplicate_control_retains_one_disposition_owner",
        &["observe_peer_control", "complete_send_success"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_reservation_cannot_cross_retirement",
        &["reserve_send", "request_retirement"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_completion_and_retirement_have_one_terminal_owner",
        &["complete_send_success", "request_retirement"],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_abandoned_reservation_and_retirement_have_one_terminal_owner",
        &[
            "reserve_next",
            "cancel_unexposed_reservation",
            "request_retirement",
        ],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "production_core_two_sequences_have_independent_deferred_slots",
        &[
            "reserve_send",
            "observe_peer_control",
            "complete_send_success",
        ],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "model_completion",
        &[
            "reserve_send",
            "observe_peer_control",
            "complete_send_success",
            "complete_send_failure",
            "request_retirement",
        ],
    ),
    TestContract::new(
        "src/flow_state/observation_core_loom.rs",
        "production_observation_lifecycle_never_exposes_partial_or_stale_ownership",
        &["begin", "finish_receive", "observed", "clear"],
    ),
    TestContract::new(
        "src/flow_state/observation_core_loom.rs",
        "production_observation_lifecycle_rejects_publish_after_clear",
        &["begin", "clear", "finish_receive"],
    ),
    TestContract::new(
        "src/flow_state/observation_core_loom.rs",
        "production_observation_lifecycle_clears_polling_when_receive_has_no_control",
        &["begin", "finish_receive"],
    ),
    TestContract::new(
        "src/flow_state/observation_core_loom.rs",
        "production_observation_lifecycle_rejects_overlapping_lane_writers",
        &["begin", "clear"],
    ),
    TestContract::new(
        "src/flow_state/observation_tests.rs",
        "polling_without_control_clears_exactly_once_and_allows_the_next_receive",
        &[
            "reserve_control_observation",
            "finish",
            "control_observation_count_for_tests",
        ],
    ),
    TestContract::new(
        "src/flow_state/observation_core_loom.rs",
        "production_observation_expiry_requires_the_exact_binding_and_predeadline_receive",
        &["begin", "finish_receive", "blocks_exact"],
    ),
    TestContract::new(
        "src/flow_state/tests/handshake_completion.rs",
        "only_the_exact_pending_client_control_transaction_can_delay_expiry",
        &[
            "set_pending_icmp_client_lock_until",
            "reserve_control_observation",
            "ControlTransactionKey",
            "new_control",
            "expire_pending_icmp_client_lock",
        ],
    ),
    TestContract::new(
        "src/flow_state/tests.rs",
        "client_flow_reservation_commit_and_rollback_are_consuming",
        &["reserve_client_flow", "commit", "rollback"],
    ),
    TestContract::new(
        "src/flow_state/tests.rs",
        "client_flow_reservation_unwind_emergency_cleanup_releases_once",
        &["catch_unwind", "reserve_client_flow", "commit"],
    ),
    TestContract::new(
        "src/stats/tests.rs",
        "thread_owned_recorder_packet_updates_use_no_allocation_or_queue_rmw",
        &[
            "recorder",
            "count_allocations",
            "shared_rmw_count_for_test",
            "update_at",
            "flush",
        ],
    ),
    TestContract::new(
        "src/stats/tests.rs",
        "worker_panic_flushes_recorder_before_terminal_publication",
        &[
            "recorder",
            "spawn_forwarder_with_stats",
            "send_add",
            "finish",
        ],
    ),
    TestContract::new(
        "tests/policy.rs",
        "interior_mutability_authorities_are_registered",
        &["assert_interior_mutability_authorities_are_registered"],
    ),
    TestContract::new(
        "tests/policy.rs",
        "production_types_have_no_mutable_test_only_authority",
        &["assert_production_types_have_no_mutable_test_only_authority"],
    ),
    TestContract::new(
        "src/net/sock_mgr/fifo_core_loom.rs",
        "production_fifo_core_allocates_unique_bounded_tickets",
        &["FifoReservationCore", "allocate"],
    ),
    TestContract::new(
        "src/net/sock_mgr/fifo_core_loom.rs",
        "production_fifo_core_cancellation_and_release_cannot_strand_successor",
        &["FifoReservationCore", "cancel", "release", "tickets"],
    ),
    TestContract::new(
        "src/net/sock_mgr/fifo_core_loom.rs",
        "production_fifo_core_current_cancellation_drains_cancelled_successor",
        &["FifoReservationCore", "cancel", "release", "tickets"],
    ),
    TestContract::new(
        "src/net/sock_mgr/fifo_core_loom.rs",
        "production_fifo_core_wrong_owner_cannot_release_current_ticket",
        &[
            "FifoReservationCore",
            "allocate",
            "release",
            "OwnershipLost",
        ],
    ),
    TestContract::new(
        "src/net/sock_mgr/fifo_core_loom.rs",
        "production_fifo_reservation_wake_generation_closes_last_owner_race",
        &["FifoReservationCore", "poll", "wait_required", "release"],
    ),
    TestContract::new(
        "src/net/sock_mgr/fifo_core_loom.rs",
        "production_fifo_reservation_shutdown_prevents_new_ownership",
        &[
            "FifoReservationCore",
            "allocate",
            "poll",
            "cancel",
            "Shutdown",
        ],
    ),
    TestContract::new(
        "src/flow_state/topology/tests.rs",
        "competing_flow_writers_are_served_fifo_without_reader_barging",
        &["reserve_until", "try_read_lane", "rollback"],
    ),
    TestContract::new(
        "src/net/sock_mgr/receiver_transfer_loom.rs",
        "production_receiver_core_allows_exactly_one_initial_owner",
        &["ReceiverTransferCore", "claim", "AlreadyOwned"],
    ),
    TestContract::new(
        "src/net/sock_mgr/receiver_transfer_loom.rs",
        "production_receiver_core_publishes_resource_before_transfer_generation",
        &[
            "ReceiverTransferCore",
            "publish_replacement",
            "changed",
            "transfer_replacement_to_owner",
        ],
    ),
    TestContract::new(
        "src/net/sock_mgr/receiver_transfer_loom.rs",
        "production_receiver_core_exit_and_replacement_never_leave_claimable_authority",
        &[
            "ReceiverTransferCore",
            "owner_exit",
            "publish_replacement",
            "claim",
        ],
    ),
    TestContract::new(
        "src/stats/finality_core_loom.rs",
        "production_stats_core_acknowledges_only_a_fifo_marker_after_its_delta",
        &[
            "StatsFinalityCore",
            "queue_publication",
            "StatsSealingTransaction",
            "begin",
            "seal",
            "accept_next",
            "acknowledged",
        ],
    ),
    TestContract::new(
        "src/stats/finality_core_loom.rs",
        "production_stats_core_queue_full_returns_owned_delta_for_exact_retry",
        &["StatsFinalityCore", "queue_publication", "accept_next"],
    ),
    TestContract::new(
        "src/stats/finality_core_loom.rs",
        "production_stats_core_sealing_and_abandonment_have_one_terminal_owner",
        &[
            "StatsFinalityCore",
            "StatsSealingTransaction",
            "begin",
            "seal",
            "abandon",
        ],
    ),
    TestContract::new(
        "src/stats/finality_core_loom.rs",
        "production_stats_core_notification_clear_recheck_cannot_lose_publication",
        &[
            "StatsFinalityCore",
            "queue_publication",
            "ready_generation",
            "rearm_notification",
        ],
    ),
    TestContract::new(
        "src/authority/wait_core_loom.rs",
        "production_wait_core_releases_waits_reacquires_and_rechecks_shutdown",
        &["wait_reacquire", "LoomWaitBackend", "notify_all"],
    ),
    TestContract::new(
        "src/authority/wait_core_loom.rs",
        "production_wait_core_never_restores_authority_after_poison",
        &["wait_reacquire", "FailingWaitBackend", "reacquired"],
    ),
    TestContract::new(
        "src/authority/tests.rs",
        "condition_wait_releases_and_reacquires_audited_authority",
        &["AuthorityCondvar", "wait_until", "timed_out"],
    ),
    TestContract::new(
        "src/authority/tests.rs",
        "condition_wait_rechecks_after_a_spurious_notification",
        &["AuthorityCondvar", "wait_until", "notify_all"],
    ),
    TestContract::new(
        "src/authority/tests.rs",
        "unwind_releases_the_exact_audit_instance_without_panicking",
        &["catch_unwind", "AuthorityScope"],
    ),
    TestContract::new(
        "src/shutdown_publication/loom_tests.rs",
        "production_shutdown_core_never_exposes_fatal_without_its_cause",
        &["ShutdownPublicationCore", "publish_fatal", "load"],
    ),
    TestContract::new(
        "src/shutdown_publication/loom_tests.rs",
        "production_shutdown_core_gives_one_primary_owner_and_retains_secondary_cause",
        &["ShutdownPublicationCore", "publish_fatal", "primary_won"],
    ),
    TestContract::new(
        "src/net/sock_mgr/group_publication_loom.rs",
        "production_group_publication_core_exposes_only_complete_published_state",
        &["GroupPublicationCore", "new", "publish_committed"],
    ),
    TestContract::new(
        "src/net/sock_mgr/group_publication_loom.rs",
        "production_group_publication_core_poison_is_terminal_after_session_commit",
        &[
            "GroupPublicationCore",
            "new",
            "publish_committed",
            "Poisoned",
        ],
    ),
    TestContract::new(
        "src/net/sock_mgr/group_publication_loom.rs",
        "production_group_publication_core_validates_before_mutation_and_poison_on_failure",
        &["publish_committed", "fail_receiver", "Poisoned"],
    ),
    TestContract::new(
        "src/flow_state/handshake/commit_core_loom.rs",
        "production_handshake_core_timeout_and_commit_have_one_payload_disposition",
        &[
            "HandshakeCommitCore",
            "request_timeout",
            "begin_send",
            "complete_success",
        ],
    ),
    TestContract::new(
        "src/flow_state/handshake/commit_core_loom.rs",
        "production_handshake_core_reset_and_manager_rollback_cannot_restore_retry",
        &["HandshakeCommitCore", "request_reset", "rollback"],
    ),
    TestContract::new(
        "src/flow_state/handshake/commit_core_loom.rs",
        "production_handshake_core_rejects_stale_and_duplicate_completion_tokens",
        &[
            "HandshakeCommitCore",
            "begin_send",
            "complete_failure",
            "begin_retry",
        ],
    ),
    TestContract::new(
        "src/flow_state/handshake/control_send_core_loom.rs",
        "production_control_send_core_keeps_ack_evidence_during_success_completion",
        &[
            "ControlSendCore",
            "complete_sequence",
            "acknowledges",
            "was_sent",
        ],
    ),
    TestContract::new(
        "src/flow_state/handshake/control_send_core_loom.rs",
        "production_control_send_core_failure_and_retry_retain_one_lease_owner",
        &[
            "ControlSendCore",
            "complete_sequence",
            "lease_due",
            "in_flight",
        ],
    ),
    TestContract::new(
        "src/flow_state/handshake/control_send_core_loom.rs",
        "production_control_send_core_restart_cannot_clear_an_owned_send",
        &[
            "ControlSendCore",
            "complete_sequence",
            "restart",
            "was_sent",
        ],
    ),
    TestContract::new(
        "src/flow_state/receive_candidate_ack_loom.rs",
        "production_candidate_core_concurrent_success_and_failure_have_one_ready_state",
        &["ReceiveCandidateAckCore", "begin_send", "complete_send"],
    ),
    TestContract::new(
        "src/flow_state/receive_candidate_ack_loom.rs",
        "production_candidate_core_all_failed_leases_return_to_negotiating",
        &[
            "ReceiveCandidateAckCore",
            "begin_send",
            "complete_send",
            "is_negotiating",
        ],
    ),
    TestContract::new(
        "src/flow_state/receive_candidate_ack_loom.rs",
        "production_candidate_core_rejects_expired_and_stale_send_authority",
        &[
            "ReceiveCandidateAckCore",
            "begin_send",
            "complete_send",
            "is_expired",
        ],
    ),
    TestContract::new(
        "src/flow_state/recovery_core_loom.rs",
        "production_recovery_core_timeout_and_completion_have_one_terminal_owner",
        &[
            "RecoverySendCore",
            "request_timeout",
            "complete_send",
            "is_terminal",
        ],
    ),
    TestContract::new(
        "src/flow_state/sync_slot/sync_slot_loom.rs",
        "production_sync_core_models_reset_and_replacement_ownership",
        &[
            "model_reset_and_completion",
            "model_replacement_and_failure",
        ],
    ),
];

const NEGATIVE_CONTROL_CONTRACTS: &[TestContract] = &[
    TestContract::new(
        "src/worker_support/reresolve_publication_loom.rs",
        "weakened_split_reresolution_publication_exposes_mixed_state",
        &["AtomicBool", "spawn", "load", "store", "Acquire", "Release"],
    ),
    TestContract::new(
        "src/atomic_core/loom_tests.rs",
        "production_core_model_detects_weakened_release_publication",
        &["AtomicUsize", "spawn", "load", "store", "Relaxed"],
    ),
    TestContract::new(
        "src/atomic_core/loom_tests.rs",
        "weakened_lane_store_and_scan_recreates_hidden_reader",
        &[
            "AtomicU64",
            "spawn",
            "compare_exchange",
            "load",
            "store",
            "Acquire",
            "Release",
        ],
    ),
    TestContract::new(
        "src/net/icmp_sequence/send_completion_loom.rs",
        "weakened_split_pending_check_recreates_the_stranded_control",
        &["AtomicU32", "Mutex", "spawn", "load", "store"],
    ),
    TestContract::new(
        "src/stats/finality_core_loom.rs",
        "weakened_marker_before_delta_is_rejected_by_the_production_consumer",
        &[
            "StatsFinalityCore",
            "accept_publication",
            "MarkerBeforeDelta",
        ],
    ),
    TestContract::new(
        "src/net/sock_mgr/group_publication_loom.rs",
        "weakened_split_manager_and_receiver_publication_exposes_mixed_state",
        &["AtomicU64", "spawn", "send", "recv", "load", "store"],
    ),
    TestContract::new(
        "src/net/sock_mgr/receiver_transfer_loom.rs",
        "weakened_split_receiver_generation_exposes_missing_resource",
        &[
            "AtomicU64",
            "Mutex",
            "spawn",
            "send",
            "recv",
            "load",
            "store",
        ],
    ),
    TestContract::new(
        "src/authority/tests.rs",
        "negative_smoke_reversed_send_order_is_rejected_by_authority_graph",
        &[
            "ProtocolTransmit",
            "SocketIo",
            "AuthorityScope",
            "AcquisitionConflict",
            "failed",
        ],
    ),
];

#[derive(Clone, Copy)]
pub(super) struct TestContract {
    path: &'static str,
    function: &'static str,
    required_semantics: &'static [&'static str],
}

impl TestContract {
    pub(super) const fn new(
        path: &'static str,
        function: &'static str,
        required_semantics: &'static [&'static str],
    ) -> Self {
        Self {
            path,
            function,
            required_semantics,
        }
    }
}

#[derive(Clone, Default)]
struct FunctionSemantics {
    identifiers: BTreeSet<String>,
    calls: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for FunctionSemantics {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.identifiers.extend(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string()),
        );
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.identifiers.insert(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && path.qself.is_none()
            && path.path.segments.len() == 1
            && let Some(called) = path.path.segments.first()
        {
            self.calls.insert(called.ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_item_fn(&mut self, _function: &'ast syn::ItemFn) {
        // A nested function declaration does not execute its body. A direct
        // call is followed separately by the reachable-call traversal.
    }

    fn visit_impl_item_fn(&mut self, _function: &'ast syn::ImplItemFn) {
        // An implementation declared inside a block is likewise not executed
        // merely because the declaration is reachable.
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        collect_token_identifiers(item.tokens.clone(), &mut self.identifiers);
        syn::visit::visit_macro(self, item);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.visit_expr(&expression.cond);
        match literal_bool(&expression.cond) {
            Some(true) => self.visit_block(&expression.then_branch),
            Some(false) => {
                if let Some((_, alternative)) = &expression.else_branch {
                    self.visit_expr(alternative);
                }
            }
            None => {
                self.visit_block(&expression.then_branch);
                if let Some((_, alternative)) = &expression.else_branch {
                    self.visit_expr(alternative);
                }
            }
        }
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.visit_expr(&expression.cond);
        if literal_bool(&expression.cond) != Some(false) {
            self.visit_block(&expression.body);
        }
    }
}

fn literal_bool(expression: &syn::Expr) -> Option<bool> {
    let mut current = expression;
    loop {
        match current {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Bool(value),
                ..
            }) => return Some(value.value),
            syn::Expr::Group(group) => current = &group.expr,
            syn::Expr::Paren(paren) => current = &paren.expr,
            _ => return None,
        }
    }
}

fn collect_token_identifiers(tokens: proc_macro2::TokenStream, identifiers: &mut BTreeSet<String>) {
    let mut pending = vec![tokens];
    while let Some(tokens) = pending.pop() {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Group(group) => pending.push(group.stream()),
                proc_macro2::TokenTree::Ident(ident) => {
                    identifiers.insert(ident.to_string());
                }
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
}

fn reachable_semantics(
    syntax: &syn::File,
    root: &str,
    initial: FunctionSemantics,
) -> Result<FunctionSemantics, String> {
    let mut combined = FunctionSemantics::default();
    let mut pending = vec![(root.to_owned(), initial, vec![root.to_owned()])];
    let mut visited = BTreeSet::new();
    while let Some((name, semantics, path)) = pending.pop() {
        if !visited.insert(name) {
            continue;
        }
        combined.identifiers.extend(semantics.identifiers);
        combined.calls.extend(semantics.calls.iter().cloned());
        for called in semantics.calls {
            if path.contains(&called) {
                let mut cycle = path.clone();
                cycle.push(called);
                return Err(format!(
                    "recursive release-evidence helper graph: {}",
                    cycle.join(" -> ")
                ));
            }
            if path.len() >= super::function_logic::MAX_RESOLVED_CALL_DEPTH {
                return Err(format!(
                    "release-evidence helper depth exceeds {}: {}",
                    super::function_logic::MAX_RESOLVED_CALL_DEPTH,
                    path.join(" -> ")
                ));
            }
            if visited.contains(&called) {
                continue;
            }
            let mut collector = NamedFunctionCollector {
                name: &called,
                matches: Vec::new(),
            };
            collector.visit_file(syntax);
            if let [called_semantics] = collector.matches.as_slice() {
                let mut called_path = path.clone();
                called_path.push(called.clone());
                pending.push((called, called_semantics.clone(), called_path));
            }
        }
    }
    Ok(combined)
}

struct NamedFunctionCollector<'a> {
    name: &'a str,
    matches: Vec<FunctionSemantics>,
}

impl NamedFunctionCollector<'_> {
    fn collect(&mut self, block: &syn::Block) {
        let mut semantics = FunctionSemantics::default();
        semantics.visit_block(block);
        self.matches.push(semantics);
    }
}

impl<'ast> Visit<'ast> for NamedFunctionCollector<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if function.sig.ident == self.name {
            self.collect(&function.block);
        }
        syn::visit::visit_item_fn(self, function);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if function.sig.ident == self.name {
            self.collect(&function.block);
        }
        syn::visit::visit_impl_item_fn(self, function);
    }
}

#[derive(Default)]
struct ShouldPanicCollector {
    functions: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ShouldPanicCollector {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if function
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("should_panic"))
        {
            self.functions.insert(function.sig.ident.to_string());
        }
        syn::visit::visit_item_fn(self, function);
    }
}

fn unallowlisted_should_panic_controls(root: &Path) -> Vec<String> {
    let allowlisted = NEGATIVE_CONTROL_CONTRACTS
        .iter()
        .map(|contract| (contract.path, contract.function))
        .collect::<BTreeSet<_>>();
    let source_root = root.join("src");
    let mut violations = Vec::new();
    for source in &super::workspace_inventory().sources {
        if !source.starts_with(&source_root) {
            continue;
        }
        let relative = source
            .strip_prefix(root)
            .expect("workspace source must remain below repository root");
        let relative = relative
            .to_str()
            .expect("governed Rust source paths are UTF-8")
            .replace('\\', "/");
        let text =
            fs::read_to_string(source).unwrap_or_else(|error| panic!("read {relative}: {error}"));
        let syntax =
            syn::parse_file(&text).unwrap_or_else(|error| panic!("parse {relative}: {error}"));
        let mut collector = ShouldPanicCollector::default();
        collector.visit_file(&syntax);
        for function in collector.functions {
            if !allowlisted.contains(&(relative.as_str(), function.as_str())) {
                violations.push(format!(
                    "{relative}::{function}: #[should_panic] test is not an allowlisted negative control"
                ));
            }
        }
    }
    violations
}

pub(super) fn assert_release_evidence_tests_execute_required_semantics() {
    let root_path = crate::common::policy::repository_root();
    let root = root_path.as_path();
    let mut parsed = BTreeMap::<&str, syn::File>::new();
    for contract in TEST_CONTRACTS.iter().chain(NEGATIVE_CONTROL_CONTRACTS) {
        if parsed.contains_key(contract.path) {
            continue;
        }
        let source = fs::read_to_string(root.join(contract.path))
            .unwrap_or_else(|error| panic!("read {}: {error}", contract.path));
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("parse {}: {error}", contract.path));
        parsed.insert(contract.path, syntax);
    }
    let violations = validate_contracts(&parsed, TEST_CONTRACTS);
    let negative_control_violations = validate_contracts(&parsed, NEGATIVE_CONTROL_CONTRACTS);
    let negative_control_inventory_violations = unallowlisted_should_panic_controls(root);
    assert!(
        violations.is_empty()
            && negative_control_violations.is_empty()
            && negative_control_inventory_violations.is_empty(),
        "Release evidence or allowlisted negative controls lost required executable semantics:\n{}\n{}\n{}",
        violations.join("\n"),
        negative_control_violations.join("\n"),
        negative_control_inventory_violations.join("\n")
    );
}

pub(super) fn validate_contracts(
    parsed: &BTreeMap<&str, syn::File>,
    contracts: &[TestContract],
) -> Vec<String> {
    let mut violations = Vec::new();
    for contract in contracts {
        let Some(syntax) = parsed.get(contract.path) else {
            violations.push(format!("{}: source is missing", contract.path));
            continue;
        };
        let mut collector = NamedFunctionCollector {
            name: contract.function,
            matches: Vec::new(),
        };
        collector.visit_file(syntax);
        if collector.matches.len() != 1 {
            violations.push(format!(
                "{}::{}: expected one function, found {}",
                contract.path,
                contract.function,
                collector.matches.len()
            ));
            continue;
        }
        let semantics =
            match reachable_semantics(syntax, contract.function, collector.matches.remove(0)) {
                Ok(semantics) => semantics,
                Err(error) => {
                    violations.push(format!("{}::{}: {error}", contract.path, contract.function));
                    continue;
                }
            };
        for required in contract.required_semantics {
            if !semantics.identifiers.contains(*required) {
                violations.push(format!(
                    "{}::{}: missing semantic operation {required}",
                    contract.path, contract.function
                ));
            }
        }
    }
    violations
}
