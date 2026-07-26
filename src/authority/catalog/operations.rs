use super::super::{
    AtomicProtocolId, AuthorityId, EffectSet, OperationId, OperationRecord, OperationRequirement,
    SharedRmwDisposition, SharedRmwId, SharedRmwRecord,
};

const PACKET_IO_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowRead,
    AuthorityId::SocketIo,
    AuthorityId::ProtocolTransmit,
    AuthorityId::ProtocolReceive,
];

const POLL_AUTHORITIES: &[AuthorityId] = &[AuthorityId::FlowRead, AuthorityId::SocketIo];

const TOPOLOGY_DRAIN_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowWrite,
    AuthorityId::SocketTopology,
    AuthorityId::WaitCoordination,
];

const SOCKET_TRANSITION_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::SocketTopology,
];

const SOCKET_INSPECTION_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::SocketTopology,
    AuthorityId::SocketAssociation,
    AuthorityId::SocketIo,
];

const WAIT_RETAINED_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::SocketTopology,
    AuthorityId::SocketAssociation,
];

const FAILURE_REPORTING_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowRead,
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::ManagerState,
    AuthorityId::SocketTopology,
    AuthorityId::SocketAssociation,
    AuthorityId::SocketDescriptor,
    AuthorityId::SocketIo,
    AuthorityId::ControlObservation,
    AuthorityId::ProtocolTransmit,
    AuthorityId::ProtocolReceive,
    AuthorityId::ResetBudget,
    AuthorityId::SessionControl,
    AuthorityId::Activity,
    AuthorityId::Maintenance,
    AuthorityId::WakeGeneration,
    AuthorityId::ReceiverClaim,
    AuthorityId::WaitCoordination,
    AuthorityId::RuntimeSupervisor,
    AuthorityId::StatsPublication,
    AuthorityId::IdentityAllocation,
    AuthorityId::Pacing,
    AuthorityId::DiagnosticCounter,
    AuthorityId::Diagnostic,
];

const NO_AUTHORITIES: &[AuthorityId] = &[];
const REFCOUNT_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::SocketTopology,
];
const REFCOUNT_FINALIZE_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::SocketTopology,
];
const FIXED_QUEUE_AUTHORITIES: &[AuthorityId] = FAILURE_REPORTING_AUTHORITIES;
const IO_EFFECTS: EffectSet = EffectSet::MAY_PERFORM_IO;
const BLOCKING_IO_EFFECTS: EffectSet = EffectSet::MAY_PERFORM_IO
    .union(EffectSet::MAY_BLOCK)
    .union(EffectSet::MAY_WAIT);
const WAIT_EFFECTS: EffectSet = EffectSet::MAY_BLOCK.union(EffectSet::MAY_WAIT);

pub(crate) const OPERATION_RECORDS: &[OperationRecord] = &[
    OperationRecord {
        id: OperationId::SocketCreate,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketBind,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketConnect,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketDisconnect,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketPeerInspection,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_INSPECTION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketLocalInspection,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_INSPECTION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketConfigure,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketCaptureEnable,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::Poll,
        blocking: true,
        effects: BLOCKING_IO_EFFECTS,
        permitted_while_held: POLL_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketSend,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: PACKET_IO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketReceive,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: PACKET_IO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::WakeSocketSend,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: FAILURE_REPORTING_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::WakeSocketReceive,
        blocking: false,
        effects: IO_EFFECTS,
        permitted_while_held: PACKET_IO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::TopologyDrain,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: TOPOLOGY_DRAIN_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::ThreadSleep,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::CondvarWait,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: WAIT_RETAINED_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SupervisorHintSend,
        blocking: false,
        effects: EffectSet::NONE,
        permitted_while_held: FAILURE_REPORTING_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::ChannelSend,
        blocking: false,
        effects: EffectSet::NONE,
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::ChannelReceive,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::Allocator,
        blocking: true,
        effects: EffectSet::MAY_ALLOCATE.union(EffectSet::MAY_BLOCK),
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::Formatting,
        blocking: true,
        effects: EffectSet::MAY_FORMAT
            .union(EffectSet::MAY_ALLOCATE)
            .union(EffectSet::MAY_BLOCK)
            .union(EffectSet::MAY_INVOKE_CALLBACK),
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::Logging,
        blocking: true,
        effects: EffectSet::MAY_LOG
            .union(EffectSet::MAY_FORMAT)
            .union(EffectSet::MAY_BLOCK)
            .union(EffectSet::MAY_INVOKE_CALLBACK),
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::JsonSerialization,
        blocking: true,
        effects: EffectSet::MAY_FORMAT
            .union(EffectSet::MAY_ALLOCATE)
            .union(EffectSet::MAY_BLOCK)
            .union(EffectSet::MAY_INVOKE_CALLBACK),
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::FatalPublication,
        blocking: false,
        effects: EffectSet::NONE,
        permitted_while_held: FAILURE_REPORTING_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::RefcountFinalize,
        blocking: false,
        effects: EffectSet::MAY_FINALIZE_REFCOUNT,
        permitted_while_held: REFCOUNT_FINALIZE_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::SocketDescriptorClose,
        blocking: true,
        effects: EffectSet::MAY_PERFORM_IO.union(EffectSet::MAY_BLOCK),
        permitted_while_held: SOCKET_TRANSITION_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::ThreadJoin,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::StatsFlush,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::FixedQueue,
        blocking: false,
        effects: EffectSet::NONE,
        permitted_while_held: FIXED_QUEUE_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::ProcessImmediateExit,
        blocking: false,
        effects: EffectSet::MAY_PERFORM_IO,
        permitted_while_held: NO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::PipelineBarrier,
        blocking: true,
        effects: WAIT_EFFECTS,
        permitted_while_held: PACKET_IO_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::RefcountClone,
        blocking: false,
        effects: EffectSet::MAY_CLONE_REFCOUNT,
        permitted_while_held: REFCOUNT_AUTHORITIES,
    },
    OperationRecord {
        id: OperationId::RefcountUpgrade,
        blocking: false,
        effects: EffectSet::MAY_CLONE_REFCOUNT,
        permitted_while_held: REFCOUNT_AUTHORITIES,
    },
];

pub(crate) const OPERATION_REQUIREMENTS: &[OperationRequirement] = &[
    OperationRequirement {
        operation: OperationId::Poll,
        authority: AuthorityId::SocketIo,
    },
    OperationRequirement {
        operation: OperationId::SocketSend,
        authority: AuthorityId::SocketIo,
    },
    OperationRequirement {
        operation: OperationId::SocketReceive,
        authority: AuthorityId::SocketIo,
    },
];

/// Shared read-modify-write operations are default-forbidden on stable packet
/// paths. This catalog records the narrow exceptions and the operations that
/// structural tests must prove absent.
pub(crate) const SHARED_RMW_RECORDS: &[SharedRmwRecord] = &[
    SharedRmwRecord {
        id: SharedRmwId::FlowLanePublication,
        protocol: AtomicProtocolId::FlowGateSnapshot,
        authority: AuthorityId::FlowRead,
        directional: true,
        stable_path: true,
        disposition: SharedRmwDisposition::Approved,
        contract: "one lane-local Acquire/Release ownership CAS on flow-lane entry and exit; worker lanes never contend with one another",
    },
    SharedRmwRecord {
        id: SharedRmwId::SocketLanePublication,
        protocol: AtomicProtocolId::SocketGateAssociation,
        authority: AuthorityId::SocketIo,
        directional: true,
        stable_path: true,
        disposition: SharedRmwDisposition::Approved,
        contract: "one lane-local Acquire/Release ownership CAS on socket-lane entry and exit; worker lanes never contend with one another",
    },
    SharedRmwRecord {
        id: SharedRmwId::ControlObservationLanePublication,
        protocol: AtomicProtocolId::ControlObservation,
        authority: AuthorityId::ControlObservation,
        directional: true,
        stable_path: true,
        disposition: SharedRmwDisposition::Approved,
        contract: "one single-writer directional observation lane owns begin/publish/clear CAS transitions; maintenance readers never write the lane",
    },
    SharedRmwRecord {
        id: SharedRmwId::ManagedSocketLifetimePin,
        protocol: AtomicProtocolId::DescriptorGeneration,
        authority: AuthorityId::SocketDescriptor,
        directional: true,
        stable_path: true,
        disposition: SharedRmwDisposition::Forbidden,
        contract: "I/O leases borrow worker-owned generation caches and retain no per-packet Arc pin",
    },
    SharedRmwRecord {
        id: SharedRmwId::DescriptorReferenceCount,
        protocol: AtomicProtocolId::DescriptorGeneration,
        authority: AuthorityId::SocketDescriptor,
        directional: true,
        stable_path: true,
        disposition: SharedRmwDisposition::Forbidden,
        contract: "worker-owned generation cache borrows the descriptor without upgrade or clone",
    },
    SharedRmwRecord {
        id: SharedRmwId::TransmitSequenceAllocation,
        protocol: AtomicProtocolId::TransmitCompletion,
        authority: AuthorityId::ProtocolTransmit,
        directional: true,
        stable_path: true,
        disposition: SharedRmwDisposition::Approved,
        contract: "one direction-local allocation-status CAS per ICMP transmit sequence",
    },
    SharedRmwRecord {
        id: SharedRmwId::StatsQueuePublication,
        protocol: AtomicProtocolId::StatsFinality,
        authority: AuthorityId::StatsPublication,
        directional: true,
        stable_path: false,
        disposition: SharedRmwDisposition::Approved,
        contract: "bounded batched publication boundary only; never one queue RMW per packet",
    },
    SharedRmwRecord {
        id: SharedRmwId::GlobalCadencePacing,
        protocol: AtomicProtocolId::PacingDeadline,
        authority: AuthorityId::Pacing,
        directional: false,
        stable_path: true,
        disposition: SharedRmwDisposition::Approved,
        contract: "one configured global CAS elects each best-effort cadence transmission; ordinary user data never accesses this authority",
    },
];
