#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum CoreContractId {
    ReresolvePublication,
    IdleTransition,
    DescriptorCache,
    FlowSnapshotPublication,
    WaitReacquire,
    HandshakeCommit,
    ControlSend,
    ControlObservation,
    ReceiveCandidateAck,
    RecoverySend,
    SyncPayload,
    SendCompletion,
    FifoReservation,
    GroupPublication,
    TopologyReservationBatch,
    WorkerStateTransaction,
    ReceiverTransfer,
    ThreadOutcome,
    ShutdownPublication,
    StatsFinality,
    StatsQueuePublication,
    StaleAssociationRetry,
    StableSend,
    Pacing,
    MaintenanceRepair,
    FlowClaimOwnership,
    AuditSlotPublication,
    SingleConsumerTransfer,
    AssociationState,
    FlowTopologyTypestate,
    SocketRetirementTypestate,
    DiagnosticCapture,
}

#[derive(Clone, Copy)]
pub(super) struct CoreBinding {
    pub(super) id: CoreContractId,
    pub(super) loom_source: &'static str,
    pub(super) core_source: &'static str,
    pub(super) core_symbol: &'static str,
    pub(super) loom_call: CallPattern,
    pub(super) loom_required_calls: &'static [CallPattern],
    pub(super) production_source: &'static str,
    pub(super) production_call: CallPattern,
}

#[derive(Clone, Copy)]
pub(super) enum TransactionKind {
    Function,
    Method,
}

#[derive(Clone, Copy)]
pub(super) struct TransactionContract {
    pub(super) function: &'static str,
    pub(super) parameter: &'static str,
    pub(super) kind: TransactionKind,
}

impl TransactionContract {
    const fn function(function: &'static str, parameter: &'static str) -> Self {
        Self {
            function,
            parameter,
            kind: TransactionKind::Function,
        }
    }

    const fn method(function: &'static str, parameter: &'static str) -> Self {
        Self {
            function,
            parameter,
            kind: TransactionKind::Method,
        }
    }
}

impl CoreBinding {
    pub(super) const fn calls(
        id: CoreContractId,
        loom_source: &'static str,
        core_source: &'static str,
        symbol: &'static str,
        loom_call: CallPattern,
        production_source: &'static str,
        production_call: CallPattern,
    ) -> Self {
        Self {
            id,
            loom_source,
            core_source,
            core_symbol: symbol,
            loom_call,
            loom_required_calls: &[],
            production_source,
            production_call,
        }
    }

    pub(super) const fn requiring_loom_calls(mut self, calls: &'static [CallPattern]) -> Self {
        self.loom_required_calls = calls;
        self
    }

    pub(super) const fn free(
        id: CoreContractId,
        loom_source: &'static str,
        core_source: &'static str,
        symbol: &'static str,
        production_source: &'static str,
        production_call: CallPattern,
    ) -> Self {
        Self::calls(
            id,
            loom_source,
            core_source,
            symbol,
            CallPattern::free(symbol),
            production_source,
            production_call,
        )
    }

    pub(super) const fn associated(
        id: CoreContractId,
        loom_source: &'static str,
        core_source: &'static str,
        symbol: &'static str,
        production_source: &'static str,
        owner: &'static str,
        method: &'static str,
    ) -> Self {
        Self::calls(
            id,
            loom_source,
            core_source,
            symbol,
            CallPattern::associated(owner, method),
            production_source,
            CallPattern::associated(owner, method),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct CallPattern {
    pub(super) owner: Option<&'static str>,
    pub(super) function: &'static str,
}

impl CallPattern {
    pub(super) const fn free(function: &'static str) -> Self {
        Self {
            owner: None,
            function,
        }
    }

    pub(super) const fn associated(owner: &'static str, function: &'static str) -> Self {
        Self {
            owner: Some(owner),
            function,
        }
    }
}

impl CoreContractId {
    pub(super) const fn positive_tests(self) -> &'static [&'static str] {
        match self {
            Self::ReresolvePublication => {
                &["production_reresolve_core_never_exposes_flow_before_manager_topology"]
            }
            Self::IdleTransition => &[
                "production_idle_transition_revalidates_activity_after_reader_drain",
                "production_idle_transition_ignores_retired_flow_activity",
            ],
            Self::DescriptorCache => {
                &["production_descriptor_borrow_rejects_revoked_generation_publication"]
            }
            Self::FlowSnapshotPublication => {
                &["production_flow_snapshot_core_installs_snapshot_before_visibility"]
            }
            Self::WaitReacquire => &[
                "production_wait_core_releases_waits_reacquires_and_rechecks_shutdown",
                "production_wait_core_never_restores_authority_after_poison",
                "production_wait_core_propagates_timeout_and_reacquires_once",
            ],
            Self::HandshakeCommit => &[
                "production_handshake_core_timeout_and_commit_have_one_payload_disposition",
                "production_handshake_core_reset_and_manager_rollback_cannot_restore_retry",
                "production_handshake_core_rejects_stale_and_duplicate_completion_tokens",
                "production_handshake_core_never_leases_payload_before_receive_activation",
                "production_handshake_core_poison_after_session_commit_is_terminal",
            ],
            Self::ControlSend => &[
                "production_control_send_core_keeps_ack_evidence_during_success_completion",
                "production_control_send_core_failure_and_retry_retain_one_lease_owner",
                "production_control_send_core_restart_cannot_clear_an_owned_send",
                "production_control_send_core_unsequenced_release_consumes_its_attempt",
            ],
            Self::ControlObservation => &[
                "production_observation_lifecycle_never_exposes_partial_or_stale_ownership",
                "production_observation_lifecycle_rejects_publish_after_clear",
                "production_observation_lifecycle_rejects_overlapping_lane_writers",
                "production_observation_lifecycle_clears_polling_when_receive_has_no_control",
                "production_observation_expiry_requires_the_exact_binding_and_predeadline_receive",
            ],
            Self::ReceiveCandidateAck => &[
                "production_candidate_core_concurrent_success_and_failure_have_one_ready_state",
                "production_candidate_core_all_failed_leases_return_to_negotiating",
                "production_candidate_core_rejects_expired_and_stale_send_authority",
            ],
            Self::RecoverySend => &[
                "production_recovery_core_timeout_and_completion_have_one_terminal_owner",
                "production_recovery_core_recognition_and_send_completion_do_not_lose_ownership",
                "production_recovery_core_deferred_reset_is_returned_exactly_once",
            ],
            Self::SyncPayload => &["production_sync_core_models_reset_and_replacement_ownership"],
            Self::SendCompletion => &[
                "production_core_success_disposes_every_accepted_control_once",
                "production_core_failure_rejects_every_deferred_control_once",
                "production_core_retirement_cannot_strand_or_double_apply_control",
                "production_core_failed_send_retirement_rejects_control_once",
                "production_core_duplicate_control_retains_one_disposition_owner",
                "production_core_reservation_cannot_cross_retirement",
                "production_core_arm_control_and_retirement_dispose_every_accepted_control",
                "production_core_abandoned_reservation_and_retirement_have_one_terminal_owner",
                "production_core_completion_and_retirement_have_one_terminal_owner",
                "production_core_conflicting_controls_have_one_deferred_owner",
                "production_core_two_sequences_have_independent_deferred_slots",
            ],
            Self::FifoReservation => &[
                "production_fifo_lease_explicit_completion_cannot_double_release",
                "production_fifo_lease_drop_releases_exact_ticket",
                "production_fifo_core_allocates_unique_bounded_tickets",
                "production_fifo_core_cancellation_and_release_cannot_strand_successor",
                "production_fifo_allocation_cannot_observe_a_false_exhaustion_during_progress",
                "production_fifo_core_wrong_owner_cannot_release_current_ticket",
                "production_fifo_core_current_cancellation_drains_cancelled_successor",
                "production_fifo_reservation_wake_generation_closes_last_owner_race",
                "production_fifo_reservation_shutdown_prevents_new_ownership",
            ],
            Self::GroupPublication => &[
                "production_group_publication_core_exposes_only_complete_published_state",
                "production_group_publication_core_poison_is_terminal_after_session_commit",
                "production_group_publication_core_validates_before_mutation_and_poison_on_failure",
            ],
            Self::TopologyReservationBatch => &[
                "production_topology_batch_parks_all_resources_before_publication_in_reverse_order",
                "production_topology_batch_returns_remaining_resources_for_reverse_rollback",
            ],
            Self::WorkerStateTransaction => {
                &["production_worker_state_transaction_never_publishes_mixed_resources"]
            }
            Self::ReceiverTransfer => &[
                "production_receiver_core_allows_exactly_one_initial_owner",
                "production_receiver_core_publishes_resource_before_transfer_generation",
                "production_receiver_core_exit_and_replacement_never_leave_claimable_authority",
            ],
            Self::ThreadOutcome => &["production_shutdown_core_has_one_cleanup_owner"],
            Self::ShutdownPublication => &[
                "production_shutdown_core_never_exposes_fatal_without_its_cause",
                "production_shutdown_core_gives_one_primary_owner_and_retains_secondary_cause",
                "production_shutdown_core_requires_cleanup_before_terminal_publication",
                "production_worker_termination_preserves_pre_return_emergency_cause",
                "production_shutdown_core_reloads_fatal_after_supervisor_completion",
            ],
            Self::StatsFinality => &[
                "production_stats_core_acknowledges_only_a_fifo_marker_after_its_delta",
                "production_stats_core_sealing_and_abandonment_have_one_terminal_owner",
            ],
            Self::StatsQueuePublication => &[
                "production_stats_core_queue_full_returns_owned_delta_for_exact_retry",
                "production_stats_core_notification_clear_recheck_cannot_lose_publication",
            ],
            Self::StaleAssociationRetry => &[
                "production_stale_retry_core_holds_flow_lane_through_retry_or_loses_to_reset",
                "production_stale_retry_core_is_one_shot_epoch_bound_and_payload_exact",
                "production_stale_retry_core_rejects_foreign_flow_before_exposing_payload",
            ],
            Self::StableSend => &[
                "production_stable_send_core_releases_protocol_socket_then_flow",
                "production_prepared_session_reservation_cannot_cross_flow_publication",
            ],
            Self::Pacing => &[
                "production_pacing_core_elects_one_sender_per_interval",
                "production_pacing_core_does_not_overwrite_a_newer_claim",
            ],
            Self::MaintenanceRepair => &[
                "production_maintenance_publication_owns_repair_and_never_exposes_stale_late_deadline",
            ],
            Self::FlowClaimOwnership => {
                &["delayed_old_flow_claim_release_cannot_clear_a_new_generation"]
            }
            Self::AuditSlotPublication => {
                &["audit_slot_publication_never_exposes_terminal_without_its_record"]
            }
            Self::SingleConsumerTransfer => {
                &["single_consumer_bootstrap_moves_payload_to_exactly_one_runtime_owner"]
            }
            Self::AssociationState => {
                &["association_authority_publishes_state_and_required_bind_coherently"]
            }
            Self::FlowTopologyTypestate => {
                &["flow_topology_typestate_publishes_only_after_consuming_session_commit"]
            }
            Self::SocketRetirementTypestate => {
                &["socket_retirement_typestate_publishes_only_retired_or_replacement_bound_owner"]
            }
            Self::DiagnosticCapture => {
                &["production_diagnostic_capture_never_holds_flow_while_recapturing_manager"]
            }
        }
    }

    pub(super) const fn negative_tests(self) -> &'static [&'static str] {
        match self {
            Self::ReresolvePublication => {
                &["weakened_split_reresolution_publication_exposes_mixed_state"]
            }
            Self::SendCompletion => {
                &["weakened_split_pending_check_recreates_the_stranded_control"]
            }
            Self::GroupPublication => {
                &["weakened_split_manager_and_receiver_publication_exposes_mixed_state"]
            }
            Self::ReceiverTransfer => {
                &["weakened_split_receiver_generation_exposes_missing_resource"]
            }
            Self::StatsFinality => {
                &["weakened_marker_before_delta_is_rejected_by_the_production_consumer"]
            }
            _ => &[],
        }
    }

    pub(super) const fn consuming_transactions(self) -> [Option<TransactionContract>; 2] {
        match self {
            Self::IdleTransition => [
                Some(TransactionContract::function(
                    "attempt_idle_transition",
                    "backend",
                )),
                None,
            ],
            Self::WaitReacquire => [
                Some(TransactionContract::function("wait_reacquire", "backend")),
                None,
            ],
            Self::HandshakeCommit => [
                Some(TransactionContract::method("commit_session", "publication")),
                None,
            ],
            Self::ControlSend => [
                Some(TransactionContract::method("complete_sequence", "attempt")),
                Some(TransactionContract::method(
                    "release_unsequenced",
                    "attempt",
                )),
            ],
            Self::ReceiveCandidateAck => [
                Some(TransactionContract::method("complete_send", "permit")),
                None,
            ],
            Self::GroupPublication => [
                Some(TransactionContract::method("publish_committed", "backend")),
                None,
            ],
            Self::StableSend => [
                Some(TransactionContract::method("perform", "transaction")),
                None,
            ],
            _ => [None, None],
        }
    }
}
