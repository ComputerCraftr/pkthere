use super::packet_admission::{
    AdmittedWirePacket, RejectedPacketExtent, RejectionLogContext, SocketLeg, log_rejected_packet,
    record_rejection_stats,
};
use super::work_budget::{
    AuthenticatedFrameBudget, PacketDumpDetailBudget, RejectionLogDecision, RejectionLogLimiter,
};
use super::{
    PacketDisposition, PacketDumpAdmissionContext, PacketTraceId, ReceivedPacketAdmission,
    admit_received_packet_with_dump, client_receive_context, log_packet_disposition,
    upstream_receive_context,
};
use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::managed_socket::ReceiveBuffer;
use crate::net::sock_mgr::{
    ReceiverClaim, ReceiverRole, SocketHandles, SocketManager, StateVersion,
};
use crate::stats::StatsSink;
use pkthere_socket_policy::ResolvedSocketPolicy;
use std::io;
use std::time::Instant;

pub(crate) struct PacketReceiver<const CAPACITY: usize> {
    socket: ReceiverClaim,
    buffer: ReceiveBuffer<CAPACITY>,
    next_packet_id: u64,
    authenticated_frame_budget: AuthenticatedFrameBudget,
    packet_dump_detail_budget: PacketDumpDetailBudget,
    rejection_log_limiter: RejectionLogLimiter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PollReceiveStatus {
    Wake,
    Timeout,
    Received,
}

pub(crate) struct PollReceiveOutcome<'buffer, 'state> {
    pub(crate) status: PollReceiveStatus,
    pub(crate) outcome: ReceiveOutcome<'buffer, 'state>,
}

impl<'buffer, 'state> PollReceiveOutcome<'buffer, 'state> {
    fn received(outcome: ReceiveOutcome<'buffer, 'state>) -> Self {
        Self {
            status: PollReceiveStatus::Received,
            outcome,
        }
    }
}

pub(crate) struct ReceivedWirePacket<'buffer, 'state> {
    pub(crate) length: usize,
    pub(crate) received_at: Instant,
    pub(crate) admitted: AdmittedWirePacket<'buffer>,
    pub(crate) authority: ReceiveAuthority,
    pub(crate) flow_snapshot: crate::flow_state::PacketFlowSnapshot,
    packet_dump: Option<super::packet_dump::DeferredPacketDump<'buffer>>,
    _control_observation: Option<crate::flow_state::ControlObservationGuard<'state>>,
}

impl<'buffer> ReceivedWirePacket<'buffer, '_> {
    pub(crate) fn take_packet_dump(
        &mut self,
    ) -> Option<super::packet_dump::DeferredPacketDump<'buffer>> {
        self.packet_dump.take()
    }
}

pub(crate) struct ReceiveOutcome<'buffer, 'state> {
    result: Option<Result<ReceivedWirePacket<'buffer, 'state>, ReceiveMiss<'buffer>>>,
}

pub(crate) struct ReceiveMiss<'buffer> {
    diagnostic: Option<DeferredReceiveDiagnostic<'buffer>>,
}

impl<'buffer, 'state> ReceiveOutcome<'buffer, 'state> {
    fn packet(packet: ReceivedWirePacket<'buffer, 'state>) -> Self {
        Self {
            result: Some(Ok(packet)),
        }
    }

    fn diagnostic(diagnostic: DeferredReceiveDiagnostic<'buffer>) -> Self {
        Self {
            result: Some(Err(ReceiveMiss {
                diagnostic: Some(diagnostic),
            })),
        }
    }

    fn empty() -> Self {
        Self {
            result: Some(Err(ReceiveMiss { diagnostic: None })),
        }
    }

    pub(crate) fn has_packet(&self) -> bool {
        matches!(self.result, Some(Ok(_)))
    }

    pub(crate) fn take_packet(&mut self) -> Option<ReceivedWirePacket<'buffer, 'state>> {
        match self.result.take()? {
            Ok(packet) => Some(packet),
            Err(miss) => {
                self.result = Some(Err(miss));
                None
            }
        }
    }

    pub(crate) fn take_diagnostic(&mut self) -> Option<DeferredReceiveDiagnostic<'buffer>> {
        match self.result.take()? {
            Ok(packet) => {
                self.result = Some(Ok(packet));
                None
            }
            Err(mut miss) => miss.take_diagnostic(),
        }
    }
}

impl<'buffer> ReceiveMiss<'buffer> {
    pub(crate) fn take_diagnostic(&mut self) -> Option<DeferredReceiveDiagnostic<'buffer>> {
        self.diagnostic.take()
    }
}

pub(crate) enum DeferredReceiveDiagnostic<'buffer> {
    Rejected {
        worker_id: usize,
        c2u: bool,
        role: SocketLeg,
        rejected: super::packet_admission::RejectedPacket,
        log: DeferredRejectionLog,
        packet_dump: Option<super::packet_dump::DeferredPacketDump<'buffer>>,
    },
    ReceiveNoise {
        c2u: bool,
        reason: super::packet_admission::ReceiveNoiseReason,
        packet_dump: Option<super::packet_dump::DeferredPacketDump<'buffer>>,
    },
}

pub(crate) enum DeferredRejectionLog {
    None,
    Packet {
        context: RejectionLogContext,
        packet: RejectedPacketExtent,
    },
    SuppressionSummary {
        suppressed: u64,
    },
}

impl DeferredReceiveDiagnostic<'_> {
    pub(crate) fn emit(self, cfg: &RuntimeConfig, stats: &mut dyn StatsSink) {
        match self {
            Self::Rejected {
                worker_id,
                c2u,
                role,
                rejected,
                log,
                packet_dump,
            } => {
                if let Some(packet_dump) = packet_dump {
                    log_packet_disposition(cfg, packet_dump.trace(), PacketDisposition::Filtered);
                    packet_dump.emit(cfg);
                }
                record_rejection_stats(stats, c2u, rejected);
                match log {
                    DeferredRejectionLog::None => {}
                    DeferredRejectionLog::Packet { context, packet } => {
                        log_rejected_packet(
                            worker_id,
                            c2u,
                            cfg,
                            role,
                            rejected,
                            context,
                            Some(packet),
                        );
                    }
                    DeferredRejectionLog::SuppressionSummary { suppressed } => {
                        log_debug_dir!(
                            cfg.debug_logs.drops,
                            worker_id,
                            c2u,
                            "suppressed {} additional rejected-packet diagnostics for {:?}",
                            suppressed,
                            rejected.reason
                        );
                    }
                }
            }
            Self::ReceiveNoise {
                c2u,
                reason,
                packet_dump,
            } => {
                if let Some(packet_dump) = packet_dump {
                    log_packet_disposition(
                        cfg,
                        packet_dump.trace(),
                        PacketDisposition::ReceiveNoise,
                    );
                    packet_dump.emit(cfg);
                }
                if reason == super::packet_admission::ReceiveNoiseReason::UnrelatedIpProtocol {
                    stats.packet_rejection(
                        c2u,
                        crate::stats::PacketRejectionCategory::UnrelatedIpProtocol,
                    );
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReceiveAuthority {
    pub(crate) topology_epoch: u64,
    pub(crate) manager_version: StateVersion,
    pub(crate) receiver_generation: u64,
    pub(crate) association_epoch: u64,
    pub(crate) evidence_generation: u64,
    pub(crate) flow_epoch: u64,
}

pub(crate) struct ReceiveMutationAuthority<'a> {
    flow: crate::flow_state::FlowTopologyReadLease<'a>,
}

impl<'a> ReceiveMutationAuthority<'a> {
    pub(crate) fn new(flow: crate::flow_state::FlowTopologyReadLease<'a>) -> Self {
        Self { flow }
    }

    pub(crate) fn into_flow(self) -> crate::flow_state::FlowTopologyReadLease<'a> {
        self.flow
    }
}

impl ReceiveAuthority {
    pub(crate) fn capture(
        handles: &SocketHandles,
        socket_leg: SocketLeg,
        flow_epoch: u64,
        receiver_generation: u64,
    ) -> Self {
        Self::capture_observed(handles, socket_leg, flow_epoch, receiver_generation, None)
    }

    pub(crate) fn capture_observed(
        handles: &SocketHandles,
        socket_leg: SocketLeg,
        flow_epoch: u64,
        receiver_generation: u64,
        observed_topology_epoch: Option<u64>,
    ) -> Self {
        let (socket, evidence_generation) = match socket_leg {
            SocketLeg::ClientFacing => (
                &handles.client_sock,
                handles.listener.evidence_key.generation,
            ),
            SocketLeg::UpstreamFacing => (
                &handles.upstream_sock,
                handles.upstream.evidence_key.generation,
            ),
        };
        let topology_epoch = observed_topology_epoch.unwrap_or_else(|| socket.topology_epoch());
        Self {
            topology_epoch,
            manager_version: handles.version,
            receiver_generation,
            association_epoch: socket.topology_epoch(),
            evidence_generation,
            flow_epoch,
        }
    }

    pub(crate) fn matches(
        &self,
        handles: &SocketHandles,
        socket_leg: SocketLeg,
        flow_epoch: u64,
        receiver_generation: u64,
    ) -> bool {
        self == &Self::capture(handles, socket_leg, flow_epoch, receiver_generation)
    }
}

pub(crate) struct ReceivePacketContext<'state, 'stats, 'poll> {
    pub(crate) cfg: &'state RuntimeConfig,
    pub(crate) worker_id: usize,
    pub(crate) flow_lane: crate::flow_state::FlowReaderLane,
    pub(crate) c2u: bool,
    pub(crate) socket_leg: SocketLeg,
    pub(crate) proto: SupportedProtocol,
    pub(crate) receive_policy: ResolvedSocketPolicy,
    pub(crate) stats: &'stats mut dyn StatsSink,
    pub(crate) flow_state: &'state crate::flow_state::FlowRuntimeState,
    pub(crate) wake: &'poll std::net::UdpSocket,
    pub(crate) wait: std::time::Duration,
}

pub(crate) fn poll_receive_with_checkpoint<'buffer, 'state, const CAPACITY: usize>(
    context: ReceivePacketContext<'state, '_, '_>,
    receiver: &'buffer mut PacketReceiver<CAPACITY>,
    handles: &SocketHandles,
    manager: &SocketManager,
    flow_read: &crate::flow_state::FlowTopologyReadLease<'_>,
    flow_snapshot_cache: &mut crate::flow_state::FlowSnapshotCache,
) -> io::Result<PollReceiveOutcome<'buffer, 'state>> {
    let c2u = context.c2u;
    let outcome =
        receiver.poll_receive(context, handles, manager, flow_read, flow_snapshot_cache)?;
    if outcome.status == PollReceiveStatus::Received && outcome.outcome.has_packet() {
        super::pipeline_audit::checkpoint(c2u, super::PipelineStage::ReceiveCompleted);
    }
    Ok(outcome)
}

impl<const CAPACITY: usize> PacketReceiver<CAPACITY> {
    pub(crate) fn new(socket: ReceiverClaim) -> Self {
        Self {
            socket,
            buffer: ReceiveBuffer::new(),
            next_packet_id: 1,
            authenticated_frame_budget: AuthenticatedFrameBudget::new(),
            packet_dump_detail_budget: PacketDumpDetailBudget::new(),
            rejection_log_limiter: RejectionLogLimiter::new(),
        }
    }

    /// Refreshes receiver ownership and makes its descriptor cache ready as
    /// one operation. Callers cannot observe a refreshed receiver with an
    /// unreconciled cache or reconcile a cache before ownership refresh.
    pub(crate) fn prepare_for_receive(&mut self) -> io::Result<()> {
        self.socket.prepare_for_receive()
    }

    pub(crate) fn poll_receive<'buffer, 'state, 'stats>(
        &'buffer mut self,
        context: ReceivePacketContext<'state, 'stats, '_>,
        handles: &SocketHandles,
        manager: &SocketManager,
        flow_read: &crate::flow_state::FlowTopologyReadLease<'_>,
        flow_snapshot_cache: &mut crate::flow_state::FlowSnapshotCache,
    ) -> io::Result<PollReceiveOutcome<'buffer, 'state>> {
        let readiness = self
            .socket
            .wait_until_readable_or_wake(context.wake, context.wait)?;
        match readiness.flags() {
            (_, true) => {
                return Ok(PollReceiveOutcome {
                    status: PollReceiveStatus::Wake,
                    outcome: ReceiveOutcome::empty(),
                });
            }
            (false, false) => {
                return Ok(PollReceiveOutcome {
                    status: PollReceiveStatus::Timeout,
                    outcome: ReceiveOutcome::empty(),
                });
            }
            (true, false) => {}
        }
        let syscall = context
            .receive_policy
            .receive_syscall(readiness.connected());
        let control_observation = if context.proto == SupportedProtocol::ICMP {
            context
                .flow_state
                .reserve_control_observation(
                    context.flow_lane.index(),
                    context.flow_state.flow_epoch(),
                    context.c2u,
                )
                .map(Some)?
        } else {
            None
        };
        let observed = readiness.receive_observed(&mut self.buffer, syscall);
        let observed = match observed {
            Ok(observed) => observed,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // Readiness is advisory. A simultaneous wake, descriptor
                // transition, or shared-descriptor consumer may make it stale.
                // Account once and return to the bounded kernel poll instead
                // of retrying recv in this readiness cycle.
                context.stats.spurious_readiness(context.c2u);
                return Ok(PollReceiveOutcome::received(ReceiveOutcome::empty()));
            }
            Err(error) => return Err(error),
        };
        let Some((packet, received_at, connected, topology_epoch)) = observed else {
            return Ok(PollReceiveOutcome::received(ReceiveOutcome::empty()));
        };
        let control_observation =
            control_observation.map(|reservation| reservation.observe(received_at));
        let receiver_generation = self.socket.generation();
        let flow_snapshot = match context.flow_state.admission_snapshot_with_read(
            flow_read,
            flow_snapshot_cache,
            received_at,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if error.class().is_fatal() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "receive admission snapshot failed: {error}"
                    ));
                }
                context.stats.stale_authority_drop(context.c2u);
                return Ok(PollReceiveOutcome::received(ReceiveOutcome::empty()));
            }
        };
        let mut receive_context = match context.socket_leg {
            SocketLeg::ClientFacing => client_receive_context(context.cfg, handles, flow_snapshot),
            SocketLeg::UpstreamFacing => {
                upstream_receive_context(context.cfg, handles, flow_snapshot)
            }
        };
        let observed_authority = ReceiveAuthority::capture_observed(
            handles,
            context.socket_leg,
            flow_read.transaction_epoch(),
            receiver_generation,
            Some(topology_epoch),
        );
        let receiver_role = match context.socket_leg {
            SocketLeg::ClientFacing => ReceiverRole::Listener,
            SocketLeg::UpstreamFacing => ReceiverRole::Upstream,
        };
        let authority_is_current = handles.version == observed_authority.manager_version
            && context.flow_state.flow_epoch() == observed_authority.flow_epoch
            && match manager.try_receiver_generation(receiver_role) {
                Ok(generation) => generation == observed_authority.receiver_generation,
                Err(error) => {
                    if error.class().is_fatal() {
                        crate::runtime_support::publish_process_fatal(format_args!(
                            "receive authority validation failed: {error}"
                        ));
                    }
                    false
                }
            };
        if observed_authority.topology_epoch != topology_epoch
            || observed_authority.association_epoch != topology_epoch
            || self.socket.topology_epoch() != topology_epoch
            || !authority_is_current
        {
            context.stats.stale_authority_drop(context.c2u);
            return Ok(PollReceiveOutcome::received(ReceiveOutcome::empty()));
        }
        // The topology receive lease is held when this timestamp is captured.
        // The reservation closes the receive-to-classification race; after
        // admission it is retained only for the exact parsed session.
        let length = packet.bytes().len();
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.checked_add(1).ok_or_else(|| {
            io::Error::other("worker packet trace sequence exhausted before packet admission")
        })?;
        let bytes = packet.bytes();
        let trace = PacketTraceId {
            worker_id: context.worker_id,
            c2u: context.c2u,
            packet_id,
        };
        receive_context.socket.connected = connected;
        let admission = admit_received_packet_with_dump(
            PacketDumpAdmissionContext {
                cfg: context.cfg,
                trace,
                spec: receive_context,
                received_at,
            },
            bytes,
            packet.source(),
            &mut self.authenticated_frame_budget,
            &mut self.packet_dump_detail_budget,
        );
        let ReceivedPacketAdmission {
            admission,
            authenticated_work_charged,
            deferred_dump,
        } = admission;
        let Some(admission) = admission else {
            context.stats.icmp_abuse_budget_drop(context.c2u);
            return Ok(PollReceiveOutcome::received(ReceiveOutcome::empty()));
        };
        match admission {
            Ok(admitted) => {
                let observation_key = control_transaction_key(
                    &admitted,
                    flow_snapshot,
                    flow_read.transaction_epoch(),
                    context.c2u,
                );
                let control_observation = control_observation
                    .map(|reservation| reservation.finish(observation_key))
                    .transpose()?
                    .flatten();
                let packet_flow_snapshot = flow_snapshot
                    .for_packet(admitted.event.icmp_meta().map(|meta| meta.session_id()));
                Ok(PollReceiveOutcome::received(ReceiveOutcome::packet(
                    ReceivedWirePacket {
                        length,
                        received_at,
                        admitted,
                        authority: observed_authority,
                        flow_snapshot: packet_flow_snapshot,
                        packet_dump: deferred_dump,
                        _control_observation: control_observation,
                    },
                )))
            }
            Err(crate::worker_support::packet_admission::WirePacketRejection::ReceiveNoise(
                reason,
            )) => Ok(PollReceiveOutcome::received(ReceiveOutcome::diagnostic(
                DeferredReceiveDiagnostic::ReceiveNoise {
                    c2u: context.c2u,
                    reason,
                    packet_dump: deferred_dump,
                },
            ))),
            Err(crate::worker_support::packet_admission::WirePacketRejection::Filtered(
                rejected,
            )) => {
                if !authenticated_work_charged
                    && rejected.reason.consumes_authenticated_work()
                    && !self.authenticated_frame_budget.take(received_at)
                {
                    context.stats.icmp_abuse_budget_drop(context.c2u);
                    return Ok(PollReceiveOutcome::received(ReceiveOutcome::empty()));
                }
                let log = match self
                    .rejection_log_limiter
                    .decide(rejected.reason, received_at)
                {
                    RejectionLogDecision::Log => DeferredRejectionLog::Packet {
                        context: RejectionLogContext::capture(receive_context),
                        packet: RejectedPacketExtent::capture(bytes),
                    },
                    RejectionLogDecision::Suppress => DeferredRejectionLog::None,
                    RejectionLogDecision::LogSuppressionSummary(suppressed) => {
                        DeferredRejectionLog::SuppressionSummary { suppressed }
                    }
                };
                Ok(PollReceiveOutcome::received(ReceiveOutcome::diagnostic(
                    DeferredReceiveDiagnostic::Rejected {
                        worker_id: context.worker_id,
                        c2u: context.c2u,
                        role: context.socket_leg,
                        rejected,
                        log,
                        packet_dump: deferred_dump,
                    },
                )))
            }
        }
    }
}

fn control_transaction_key(
    admitted: &AdmittedWirePacket<'_>,
    snapshot: &crate::flow_state::FlowAdmissionSnapshot,
    flow_epoch: u64,
    c2u: bool,
) -> Option<crate::flow_state::ControlTransactionKey> {
    let meta = admitted.event.icmp_meta().copied()?;
    let session_id = meta.session_id();
    let session_is_candidate = if c2u {
        snapshot.client_sessions.is_candidate(session_id)
    } else {
        snapshot.upstream_sessions.is_candidate(session_id)
    };
    let affects_control = admitted.event.is_session_control()
        || admitted.candidate_flow_key().is_some()
        || admitted.unknown_session_for_reset()
        || session_is_candidate
        || (!c2u
            && snapshot.upstream_transmit_session_id == Some(session_id)
            && !snapshot.upstream_reply_id_acked);
    if !affects_control {
        return None;
    }
    let peer_flow = admitted
        .candidate_flow_key()
        .or(snapshot.client_flow)
        .or_else(|| {
            admitted
                .normalized_source
                .map(crate::flow_key::ClientFlowKey::Icmp)
        });
    Some(crate::flow_state::ControlTransactionKey::new(
        flow_epoch, c2u, peer_flow, meta,
    ))
}

#[cfg(all(test, not(miri)))]
mod blocking_tests;
