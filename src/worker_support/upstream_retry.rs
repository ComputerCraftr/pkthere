use super::upstream::{
    UpstreamForwardOutcome, UpstreamWorkerContext, process_admitted_upstream_event,
};
use super::{CachedClientState, PacketTraceId};
use crate::net::payload::PayloadEvent;
use crate::stats::StatsSink;
use std::time::Instant;

pub(super) struct UpstreamOutcomeContext<'borrow, 'runtime, 'packet> {
    pub(super) worker: &'borrow mut UpstreamWorkerContext<'runtime>,
    pub(super) handles: &'borrow crate::net::sock_mgr::SocketHandles,
    pub(super) flow_snapshot_cache: &'borrow mut crate::flow_state::FlowSnapshotCache,
    pub(super) cache: &'borrow mut CachedClientState,
    pub(super) client_side_cache: &'borrow mut crate::net::icmp_sequence::IcmpSequenceCache,
    pub(super) flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    pub(super) event: &'borrow PayloadEvent<'packet>,
    pub(super) trace: PacketTraceId,
    pub(super) received_at: Instant,
}

impl UpstreamOutcomeContext<'_, '_, '_> {
    pub(super) fn handle(self, outcome: UpstreamForwardOutcome) -> bool {
        match outcome {
            UpstreamForwardOutcome::Continue => true,
            UpstreamForwardOutcome::Fatal => false,
            UpstreamForwardOutcome::AssociationStale(stale) => self.retry(stale),
        }
    }

    fn retry(mut self, stale: crate::net::managed_socket::AssociationStale) -> bool {
        let retry = super::stale_association::ObservedStaleRetry::new(
            stale.expected_epoch(),
            self.flow_snapshot,
            self.event,
        );
        let transaction = match self.worker.flow_state.try_reserve_client_flow() {
            Ok(transaction) => transaction,
            Err(error) => {
                if error.class().is_fatal() {
                    self.fatal(format_args!(
                        "listener association recovery could not reserve the flow: {error}"
                    ));
                    return false;
                }
                return true;
            }
        };
        let current = match self.worker.flow_state.packet_snapshot_under(
            &transaction,
            self.event.icmp_meta().map(|metadata| metadata.session_id()),
            Instant::now(),
        ) {
            Ok(current) => current,
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback() {
                    self.fatal(format_args!(
                        "listener association recovery rollback failed: {rollback_error}"
                    ));
                    return false;
                }
                if error.class().is_fatal() {
                    self.fatal(format_args!(
                        "listener association recovery could not revalidate its flow: {error}"
                    ));
                    return false;
                }
                return true;
            }
        };
        let retry = match retry.authorize_transition(current) {
            Ok(retry) => retry,
            Err(_) => {
                if let Err(error) = transaction.rollback() {
                    self.fatal(format_args!(
                        "listener association recovery stale-flow rollback failed: {error}"
                    ));
                    return false;
                }
                return true;
            }
        };
        if let Err(error) = self.worker.sock_mgr.reconcile_stale_send_association(
            self.handles,
            false,
            stale.expected_epoch(),
        ) {
            if let Err(rollback_error) = transaction.rollback() {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "listener association recovery rollback failed: {rollback_error}"
                ));
            }
            self.fatal(format_args!(
                "listener association recovery failed: {error}"
            ));
            return false;
        }
        if let Err(error) = transaction.commit() {
            self.fatal(format_args!(
                "listener association recovery completion failed: {error}"
            ));
            return false;
        }
        let retry = match retry.reconciled(stale.expected_epoch()) {
            Ok(retry) => retry,
            Err(error) => {
                self.fatal(format_args!(
                    "listener association recovery lost retry authority: {error:?}"
                ));
                return false;
            }
        };
        self.resume_and_send(retry)
    }

    fn resume_and_send(
        mut self,
        retry: super::stale_association::ReconciledStaleRetry<
            crate::flow_state::PacketFlowSnapshot,
            &'_ PayloadEvent<'_>,
        >,
    ) -> bool {
        let resumed_read = match self
            .worker
            .flow_state
            .try_topology_read(self.worker.flow_lane)
        {
            Ok(read) => read,
            Err(error) => {
                if error.class().is_fatal() {
                    self.fatal(format_args!(
                        "listener association recovery could not resume flow authority: {error}"
                    ));
                    return false;
                }
                return true;
            }
        };
        let refreshed = match self.worker.flow_state.admission_snapshot_with_read(
            &resumed_read,
            self.flow_snapshot_cache,
            Instant::now(),
        ) {
            Ok(snapshot) => {
                snapshot.for_packet(self.event.icmp_meta().map(|metadata| metadata.session_id()))
            }
            Err(error) => {
                drop(resumed_read);
                if error.class().is_fatal() {
                    self.fatal(format_args!(
                        "listener association recovery could not refresh flow identity: {error}"
                    ));
                    return false;
                }
                return true;
            }
        };
        let retry = match retry.authorize(refreshed) {
            Ok(retry) => retry,
            Err(_) => {
                drop(resumed_read);
                return true;
            }
        };
        let outcome = process_admitted_upstream_event(
            self.worker,
            self.handles,
            self.cache,
            self.client_side_cache,
            resumed_read,
            refreshed,
            retry.payload(),
            self.trace,
            self.received_at,
        );
        let stale_again = matches!(outcome, UpstreamForwardOutcome::AssociationStale(_));
        if retry.complete(stale_again).is_err() {
            self.fatal(format_args!(
                "listener association remained stale after one managed retry"
            ));
            return false;
        }
        !matches!(outcome, UpstreamForwardOutcome::Fatal)
    }

    fn fatal(&mut self, message: std::fmt::Arguments<'_>) {
        crate::runtime_support::publish_process_fatal(message);
        self.worker.stats.invariant_failure(false);
    }
}
