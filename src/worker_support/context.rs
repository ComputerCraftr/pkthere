use crate::cli::RuntimeConfig;
use crate::flow_state::FlowRuntimeState;
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};
use crate::stats::StatsSink;
use std::time::Instant;

pub(crate) fn log_worker_ready(cfg: &RuntimeConfig, worker_id: usize, c2u: bool) {
    if !cfg.debug_logs.handles {
        return;
    }
    let value = audited_json!({
        "event": "worker-ready",
        "worker": worker_id,
        "worker_pair": worker_id / 2,
        "direction": if c2u { "c2u" } else { "u2c" },
    });
    crate::log_debug!(true, "runtime-trace {}", crate::diagnostics::stamp(value));
}

/// Ownership-bearing stable-send ordering shared by production and Loom.
///
/// The type sequence makes flow authority precede socket authority and socket
/// authority precede direction-local protocol authority. `perform` retains all
/// three until the nonblocking syscall and its protocol disposition complete.
pub(crate) struct StableSendCore<Flow> {
    flow: Flow,
    _order: std::marker::PhantomData<fn() -> Flow>,
}

pub(crate) struct StableSocketSend<Flow, Socket> {
    socket: Socket,
    flow: Flow,
}

pub(crate) struct StableProtocolSend<Flow, Socket, Protocol> {
    protocol: Protocol,
    socket: Socket,
    flow: Flow,
}

pub(crate) trait StableSendTransaction<Flow, Socket, Protocol> {
    type SendResult;
    type Output;

    fn send(
        &mut self,
        flow: &mut Flow,
        socket: &Socket,
        protocol: &mut Protocol,
    ) -> Self::SendResult;

    fn complete(
        self,
        flow: &mut Flow,
        socket: &Socket,
        protocol: &mut Protocol,
        send_result: Self::SendResult,
    ) -> Self::Output;
}

/// A protocol reservation that may be executed only after flow and socket
/// authority have been acquired by [`StableSendCore`].
///
/// Implementations own the protocol-specific cache validation and mutation.
/// Callers can construct a request before entering the authority chain, but
/// cannot execute it directly or obtain its reserved value out of order.
pub(crate) trait StableProtocolReservation {
    type Protocol;
    type Error;

    fn reserve(self) -> Result<Self::Protocol, Self::Error>;
}

impl<Flow> StableSendCore<Flow> {
    pub(crate) const fn new(flow: Flow) -> Self {
        Self {
            flow,
            _order: std::marker::PhantomData,
        }
    }

    pub(crate) fn acquire_socket<Socket>(self, socket: Socket) -> StableSocketSend<Flow, Socket> {
        StableSocketSend {
            socket,
            flow: self.flow,
        }
    }
}

impl<Flow, Socket> StableSocketSend<Flow, Socket> {
    pub(crate) fn reserve_protocol<Reservation>(
        self,
        reservation: Reservation,
    ) -> Result<StableProtocolSend<Flow, Socket, Reservation::Protocol>, Reservation::Error>
    where
        Reservation: StableProtocolReservation,
    {
        let protocol = reservation.reserve()?;
        Ok(StableProtocolSend {
            protocol,
            socket: self.socket,
            flow: self.flow,
        })
    }
}

impl<Flow, Socket, Protocol> StableProtocolSend<Flow, Socket, Protocol> {
    pub(crate) const fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    pub(crate) fn perform<Transaction>(
        mut self,
        mut transaction: Transaction,
    ) -> Transaction::Output
    where
        Transaction: StableSendTransaction<Flow, Socket, Protocol>,
    {
        let send_result = transaction.send(&mut self.flow, &self.socket, &mut self.protocol);
        transaction.complete(
            &mut self.flow,
            &self.socket,
            &mut self.protocol,
            send_result,
        )
    }
}

pub(crate) struct StableForwardPermit<'flow> {
    flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
    snapshot: StableFlowProjection,
    manager_version: crate::net::sock_mgr::StateVersion,
    destination_socket: pkthere_socket_policy::SocketEvidenceKey,
    destination_topology_epoch: u64,
    destination_is_upstream: bool,
    _not_clone_or_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[derive(Clone, Copy)]
pub(crate) struct StableFlowProjection {
    flow_epoch: u64,
    pub(crate) client_transmit_session_id: Option<crate::net::framing_shim::SessionId>,
    pub(crate) upstream_transmit_session_id: Option<crate::net::framing_shim::SessionId>,
    pub(crate) upstream_reply_id_acked: bool,
}

enum StableSnapshotRef<'snapshot> {
    Admission(&'snapshot crate::flow_state::FlowAdmissionSnapshot),
    Packet(&'snapshot crate::flow_state::PacketFlowSnapshot),
}

impl StableFlowProjection {
    fn capture(snapshot: StableSnapshotRef<'_>, flow_epoch: u64) -> Self {
        let (client_transmit_session_id, upstream_transmit_session_id, upstream_reply_id_acked) =
            match snapshot {
                StableSnapshotRef::Admission(snapshot) => (
                    snapshot.client_transmit_session_id,
                    snapshot.upstream_transmit_session_id,
                    snapshot.upstream_reply_id_acked,
                ),
                StableSnapshotRef::Packet(snapshot) => (
                    snapshot.client_transmit_session_id,
                    snapshot.upstream_transmit_session_id,
                    snapshot.upstream_reply_id_acked,
                ),
            };
        Self {
            flow_epoch,
            client_transmit_session_id,
            upstream_transmit_session_id,
            upstream_reply_id_acked,
        }
    }
}

impl<'flow> StableForwardPermit<'flow> {
    pub(crate) fn for_upstream(
        flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
        snapshot: &crate::flow_state::FlowAdmissionSnapshot,
        handles: &crate::net::sock_mgr::SocketHandles,
    ) -> Self {
        Self::for_upstream_admission(flow_read, snapshot, handles, true)
    }

    fn for_upstream_admission(
        flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
        snapshot: &crate::flow_state::FlowAdmissionSnapshot,
        handles: &crate::net::sock_mgr::SocketHandles,
        audit_same_thread_pipeline: bool,
    ) -> Self {
        let flow_epoch = flow_read.transaction_epoch();
        let permit = Self {
            flow_read,
            snapshot: StableFlowProjection::capture(
                StableSnapshotRef::Admission(snapshot),
                flow_epoch,
            ),
            manager_version: handles.version,
            destination_socket: handles.upstream.evidence_key,
            destination_topology_epoch: handles.upstream_sock.topology_epoch(),
            destination_is_upstream: true,
            _not_clone_or_send: std::marker::PhantomData,
        };
        if audit_same_thread_pipeline {
            super::pipeline_audit::checkpoint(true, super::PipelineStage::SnapshotValidated);
        }
        permit
    }

    pub(crate) fn for_upstream_packet(
        flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
        snapshot: &crate::flow_state::PacketFlowSnapshot,
        handles: &crate::net::sock_mgr::SocketHandles,
    ) -> Self {
        let flow_epoch = flow_read.transaction_epoch();
        let permit = Self {
            flow_read,
            snapshot: StableFlowProjection::capture(
                StableSnapshotRef::Packet(snapshot),
                flow_epoch,
            ),
            manager_version: handles.version,
            destination_socket: handles.upstream.evidence_key,
            destination_topology_epoch: handles.upstream_sock.topology_epoch(),
            destination_is_upstream: true,
            _not_clone_or_send: std::marker::PhantomData,
        };
        super::pipeline_audit::checkpoint(true, super::PipelineStage::SnapshotValidated);
        permit
    }

    pub(crate) fn for_listener_packet(
        flow_read: crate::flow_state::FlowTopologyReadLease<'flow>,
        snapshot: &crate::flow_state::PacketFlowSnapshot,
        handles: &crate::net::sock_mgr::SocketHandles,
    ) -> Self {
        let flow_epoch = flow_read.transaction_epoch();
        let permit = Self {
            flow_read,
            snapshot: StableFlowProjection::capture(
                StableSnapshotRef::Packet(snapshot),
                flow_epoch,
            ),
            manager_version: handles.version,
            destination_socket: handles.listener.evidence_key,
            destination_topology_epoch: handles.client_sock.topology_epoch(),
            destination_is_upstream: false,
            _not_clone_or_send: std::marker::PhantomData,
        };
        super::pipeline_audit::checkpoint(false, super::PipelineStage::SnapshotValidated);
        permit
    }

    pub(crate) const fn snapshot(&self) -> StableFlowProjection {
        self.snapshot
    }

    pub(crate) fn validate(
        &self,
        flow_state: &crate::flow_state::FlowRuntimeState,
        handles: &crate::net::sock_mgr::SocketHandles,
    ) -> std::io::Result<()> {
        let (evidence, topology_epoch) = if self.destination_is_upstream {
            (
                handles.upstream.evidence_key,
                handles.upstream_sock.topology_epoch(),
            )
        } else {
            (
                handles.listener.evidence_key,
                handles.client_sock.topology_epoch(),
            )
        };
        if !self.flow_read.is_current()
            || self.snapshot.flow_epoch != flow_state.flow_epoch()
            || self.manager_version != handles.version
            || self.destination_socket != evidence
            || self.destination_topology_epoch != topology_epoch
        {
            return Err(std::io::Error::other(
                "stable forwarding authority changed before send",
            ));
        }
        Ok(())
    }
}

pub(super) fn prepared_upstream_permit<'flow>(
    flow_state: &'flow crate::flow_state::FlowRuntimeState,
    flow_lane: crate::flow_state::FlowReaderLane,
    handles: &crate::net::sock_mgr::SocketHandles,
    sequence_state: &crate::net::icmp_sequence::SharedIcmpSequenceState,
    sequence_cache: &mut crate::net::icmp_sequence::IcmpSequenceCache,
) -> std::io::Result<StableForwardPermit<'flow>> {
    let mut snapshot_cache = crate::flow_state::FlowSnapshotCache::new();
    let mut flow_read = flow_state
        .try_topology_read(flow_lane)
        .map_err(std::io::Error::other)?;
    let session_id = flow_state
        .admission_snapshot_with_read(&flow_read, &mut snapshot_cache, Instant::now())
        .map_err(std::io::Error::other)?
        .upstream_transmit_session_id
        .ok_or_else(|| std::io::Error::other("upstream send has no active transmit session"))?;
    if !crate::net::icmp_sequence::outbound_request_session_is_prepared(
        sequence_state,
        sequence_cache,
        session_id,
    ) {
        let (reacquired, ()) = flow_read
            .run_released(|| {
                crate::net::icmp_sequence::load_installed_outbound_session(
                    sequence_state,
                    sequence_cache,
                    session_id,
                )
            })
            .map_err(|error| match error {
                crate::flow_state::ReleasedFlowOperationError::Operation(error) => {
                    std::io::Error::other(error)
                }
                crate::flow_state::ReleasedFlowOperationError::Reacquire(error) => {
                    std::io::Error::other(error)
                }
            })?;
        flow_read = reacquired;
    }
    let snapshot = flow_state
        .admission_snapshot_with_read(&flow_read, &mut snapshot_cache, Instant::now())
        .map_err(std::io::Error::other)?;
    if snapshot.upstream_transmit_session_id != Some(session_id) {
        return Err(std::io::Error::other(
            "upstream transmit session changed during cache installation",
        ));
    }
    Ok(StableForwardPermit::for_upstream_admission(
        flow_read, snapshot, handles, false,
    ))
}

pub(crate) struct PacketContext<'state, 'stats> {
    pub(crate) worker_id: usize,
    pub(crate) t_start: Instant,
    pub(crate) t_event: Instant,
    pub(crate) cfg: &'state RuntimeConfig,
    pub(crate) stats: &'stats mut dyn StatsSink,
    pub(crate) flow_state: &'state FlowRuntimeState,
    pub(crate) flow_lane: crate::flow_state::FlowReaderLane,
    pub(crate) flow_snapshot: Option<StableFlowProjection>,
}

impl<'state, 'stats> PacketContext<'state, 'stats> {
    #[inline]
    pub(crate) fn new(
        worker_id: usize,
        t_start: Instant,
        t_event: Instant,
        cfg: &'state RuntimeConfig,
        stats: &'stats mut dyn StatsSink,
        flow_state: &'state FlowRuntimeState,
    ) -> Self {
        Self {
            worker_id,
            t_start,
            t_event,
            cfg,
            stats,
            flow_state,
            flow_lane: crate::flow_state::FlowReaderLane::for_worker(
                worker_id,
                cfg.worker_flow_mode,
            ),
            flow_snapshot: None,
        }
    }

    pub(crate) const fn with_flow_snapshot(mut self, snapshot: StableFlowProjection) -> Self {
        self.flow_snapshot = Some(snapshot);
        self
    }
}

pub(crate) struct SequenceContext<'a> {
    pub(crate) client_state: &'a SharedIcmpSequenceState,
    pub(crate) client_cache: &'a mut IcmpSequenceCache,
    pub(crate) upstream_state: &'a SharedIcmpSequenceState,
    pub(crate) upstream_cache: &'a mut IcmpSequenceCache,
}

impl<'a> SequenceContext<'a> {
    #[inline]
    pub(crate) fn new(
        client_state: &'a SharedIcmpSequenceState,
        client_cache: &'a mut IcmpSequenceCache,
        upstream_state: &'a SharedIcmpSequenceState,
        upstream_cache: &'a mut IcmpSequenceCache,
    ) -> Self {
        Self {
            client_state,
            client_cache,
            upstream_state,
            upstream_cache,
        }
    }
}
