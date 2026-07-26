use super::{AuthorityDomain, AuthorityId, AuthorityRecord, AuthoritySpec, OwnershipModel};

pub(super) const RECORDS: &[AuthorityRecord] = &[
    <FlowRead as AuthoritySpec>::RECORD,
    <FlowReservation as AuthoritySpec>::RECORD,
    <FlowClaim as AuthoritySpec>::RECORD,
    <FlowWrite as AuthoritySpec>::RECORD,
    <ManagerTransaction as AuthoritySpec>::RECORD,
    <ManagerState as AuthoritySpec>::RECORD,
    <SocketTopology as AuthoritySpec>::RECORD,
    <SocketAssociation as AuthoritySpec>::RECORD,
    <SocketDescriptor as AuthoritySpec>::RECORD,
    <SocketIo as AuthoritySpec>::RECORD,
    <ControlObservation as AuthoritySpec>::RECORD,
    <ProtocolTransmit as AuthoritySpec>::RECORD,
    <ProtocolReceive as AuthoritySpec>::RECORD,
    <ResetBudget as AuthoritySpec>::RECORD,
    <SessionControl as AuthoritySpec>::RECORD,
    <Activity as AuthoritySpec>::RECORD,
    <Maintenance as AuthoritySpec>::RECORD,
    <WakeGeneration as AuthoritySpec>::RECORD,
    <ReceiverClaim as AuthoritySpec>::RECORD,
    <WaitCoordination as AuthoritySpec>::RECORD,
    <RuntimeSupervisor as AuthoritySpec>::RECORD,
    <StatsPublication as AuthoritySpec>::RECORD,
    <IdentityAllocation as AuthoritySpec>::RECORD,
    <Pacing as AuthoritySpec>::RECORD,
    <DiagnosticCounter as AuthoritySpec>::RECORD,
    <Diagnostic as AuthoritySpec>::RECORD,
];

pub(crate) trait Sealed {}

macro_rules! tag {
    ($name:ident, $id:ident, $domain:ident, $blocking:expr, $hot:expr, $directional:expr, $owner:ident, $instance_rule:literal, $invalidation:literal, $publication:literal) => {
        pub(crate) enum $name {}
        impl Sealed for $name {}
        impl AuthoritySpec for $name {
            const RECORD: AuthorityRecord = AuthorityRecord {
                id: AuthorityId::$id,
                domain: AuthorityDomain::$domain,
                blocking: $blocking,
                hot_path: $hot,
                directional: $directional,
                owner: OwnershipModel::$owner,
                instance_rule: $instance_rule,
                invalidation: $invalidation,
                publication: $publication,
            };
            const ATOMIC_PROTOCOL: super::AtomicProtocolId =
                super::atomic_protocol_for_authority(AuthorityId::$id);
        }
    };
}

tag!(
    FlowRead,
    FlowRead,
    Flow,
    false,
    true,
    false,
    Lane,
    "one registered worker lane per logical flow",
    "flow publication epoch",
    "flow gate epoch publishes immutable snapshot"
);
tag!(
    FlowReservation,
    FlowReservation,
    Flow,
    true,
    false,
    false,
    FifoReservation,
    "one FIFO reservation queue per logical flow",
    "flow reservation ticket",
    "reservation orders writers before flow-gate closure"
);
tag!(
    FlowClaim,
    FlowClaim,
    Flow,
    true,
    false,
    false,
    Mutex,
    "one process-wide map assigning each single-flow tuple to one worker pair",
    "flow claim insertion or release",
    "claim ownership is visible before client-flow topology publication"
);
tag!(
    FlowWrite,
    FlowWrite,
    Flow,
    true,
    false,
    false,
    FifoReservation,
    "one FIFO writer per logical flow",
    "flow publication epoch",
    "writer reopens flow gate at a fresh epoch"
);
tag!(
    ManagerTransaction,
    ManagerTransaction,
    Manager,
    true,
    false,
    false,
    FifoReservation,
    "socket slots acquired in ascending slot order",
    "manager transaction token",
    "manager versions publish only after complete transaction preparation"
);
tag!(
    ManagerState,
    ManagerState,
    Manager,
    true,
    false,
    false,
    Mutex,
    "socket slots acquired in ascending slot order",
    "manager StateVersion",
    "StateVersion changes only with committed manager state"
);
tag!(
    SocketTopology,
    SocketTopology,
    Socket,
    true,
    false,
    false,
    FifoReservation,
    "socket slots acquired in ascending slot order",
    "socket topology epoch",
    "socket gate reopens only after descriptor and receiver publication"
);
tag!(
    SocketAssociation,
    SocketAssociation,
    Socket,
    true,
    false,
    false,
    Mutex,
    "association and required-bind instances use ascending kind order",
    "socket association epoch",
    "association changes only while the topology gate is closed"
);
tag!(
    SocketDescriptor,
    SocketDescriptor,
    Socket,
    true,
    false,
    false,
    Mutex,
    "one persistent descriptor owner per socket slot",
    "descriptor generation",
    "descriptor ownership changes only through topology publication"
);
tag!(
    SocketIo,
    SocketIo,
    Socket,
    false,
    true,
    true,
    Lane,
    "one direction-local lane per worker and socket",
    "socket topology epoch",
    "lane is valid only for the identical open topology epoch"
);
tag!(
    WaitCoordination,
    WaitCoordination,
    Runtime,
    true,
    false,
    false,
    Mutex,
    "one wait coordinator per gate or reservation",
    "wait generation or shutdown",
    "wake generation and authoritative predicate are rechecked after wake"
);
tag!(
    ControlObservation,
    ControlObservation,
    Protocol,
    false,
    true,
    true,
    SingleWriter,
    "one observation lane per worker direction",
    "observation generation",
    "observed control identity publishes after successful receive"
);
tag!(
    ProtocolTransmit,
    ProtocolTransmit,
    Protocol,
    false,
    true,
    true,
    SingleWriter,
    "at most one transmit session instance held by a stable packet",
    "session status and sequence generation",
    "send-completion CAS owns reservation evidence deferred control outcome and retirement"
);
tag!(
    ProtocolReceive,
    ProtocolReceive,
    Protocol,
    true,
    true,
    true,
    Mutex,
    "at most one same-direction receive session held",
    "receive session generation",
    "replay mutation is visible before receive authority releases"
);
tag!(
    ResetBudget,
    ResetBudget,
    Protocol,
    true,
    false,
    false,
    Mutex,
    "one process-wide hostile-response budget",
    "token-bucket refill epoch",
    "global budget reservation precedes per-flow budget reservation"
);
tag!(
    SessionControl,
    SessionControl,
    Protocol,
    true,
    false,
    true,
    Mutex,
    "candidate batches use flow-direction-kind-session order",
    "flow/session epoch",
    "session controls publish through the flow writer"
);
tag!(
    Activity,
    Activity,
    Flow,
    false,
    true,
    true,
    SingleWriter,
    "one activity lane per worker direction",
    "flow activity generation",
    "seqlock publication keeps epoch and tick coherent; it does not authorize timeout commit"
);
tag!(
    Maintenance,
    Maintenance,
    Runtime,
    true,
    false,
    false,
    Mutex,
    "one maintenance publication authority per logical flow",
    "maintenance epoch",
    "authoritative deadline publishes before its wake"
);
tag!(
    WakeGeneration,
    WakeGeneration,
    Socket,
    false,
    false,
    true,
    SingleWriter,
    "one wake owner per worker direction",
    "wake generation",
    "pending state uses clear-drain-recheck"
);
tag!(
    StatsPublication,
    StatsPublication,
    Stats,
    false,
    false,
    true,
    SingleWriter,
    "one producer queue per supervised producer",
    "producer lifecycle generation",
    "FIFO marker follows every delta through its sequence"
);
tag!(
    RuntimeSupervisor,
    RuntimeSupervisor,
    Runtime,
    true,
    false,
    false,
    Mutex,
    "one shutdown controller and one writer per outcome slot",
    "shutdown state and outcome generation",
    "cause is ready before fatal state publication"
);
tag!(
    IdentityAllocation,
    IdentityAllocation,
    Protocol,
    false,
    false,
    false,
    Counter,
    "one process-wide checked identity allocator",
    "process lifetime",
    "nonzero identities are never reused"
);
tag!(
    Pacing,
    Pacing,
    Protocol,
    false,
    true,
    false,
    SingleWriter,
    "one configured cadence pacer",
    "last cadence send tick",
    "pacing never gates ordinary user data"
);
tag!(
    ReceiverClaim,
    ReceiverClaim,
    Socket,
    true,
    false,
    true,
    UniqueClaim,
    "one owner per role, slot, and receiver generation",
    "receiver generation",
    "receiver generation follows receiver-slot commit"
);
tag!(
    DiagnosticCounter,
    DiagnosticCounter,
    Diagnostic,
    false,
    false,
    false,
    Counter,
    "independent process-wide diagnostic counters",
    "process lifetime",
    "checked counters do not publish protocol authority"
);
tag!(
    Diagnostic,
    Diagnostic,
    Diagnostic,
    false,
    false,
    true,
    SingleWriter,
    "one bounded store per worker direction",
    "worker lifetime",
    "terminal disposition moves a trace exactly once"
);
