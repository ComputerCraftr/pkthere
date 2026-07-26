use super::super::{
    AtomicProtocolId, FieldIdentity, FunctionIdentity, InvariantId, LifecycleOwnershipRecord,
    LoomEvidenceClass, ResourceIdentity, TypeIdentity,
};

const SEND_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::SendCompletionCore,
        field: FieldIdentity::SendStates,
        source_field: "states",
        resource_type: TypeIdentity::SendCompletionCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::SendCompletionCore,
        field: FieldIdentity::SendAllocation,
        source_field: "allocation",
        resource_type: TypeIdentity::SendCompletionCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::SendCompletionCore,
        field: FieldIdentity::SendRetirement,
        source_field: "retirement",
        resource_type: TypeIdentity::SendCompletionCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::SendCompletionCore,
        field: FieldIdentity::DeferredControl,
        source_field: "deferred",
        resource_type: TypeIdentity::DeferredPeerControl,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::TransmitCompletion),
];
const SEND_ACQUIRE: &[FunctionIdentity] =
    &[FunctionIdentity::SendReserve, FunctionIdentity::SendArm];
const SEND_MUTATE: &[FunctionIdentity] = &[
    FunctionIdentity::SendObserveControl,
    FunctionIdentity::SendCompleteSuccess,
    FunctionIdentity::SendCompleteFailure,
    FunctionIdentity::SendRequestRetirement,
    FunctionIdentity::SendCompleteRetirement,
];
const SEND_TERMINAL: &[FunctionIdentity] = &[
    FunctionIdentity::SendCompleteSuccess,
    FunctionIdentity::SendCompleteFailure,
    FunctionIdentity::SendCompleteRetirement,
];

const GROUP_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::GroupPublicationTransaction,
        resource_type: TypeIdentity::GroupPublicationCore,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::GroupPublicationTransaction,
        resource_type: TypeIdentity::DescriptorOwner,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::GroupPublicationTransaction,
        resource_type: TypeIdentity::ManagedReceiver,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::GroupPublicationTransaction,
        resource_type: TypeIdentity::ManagerMetadata,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::GroupPublicationTransaction,
        resource_type: TypeIdentity::FlowSnapshot,
    },
];
const GROUP_ACQUIRE: &[FunctionIdentity] = &[FunctionIdentity::GroupNew];
const GROUP_MUTATE: &[FunctionIdentity] = &[
    FunctionIdentity::GroupSocketTransitionsApplied,
    FunctionIdentity::GroupManagerStatePrepared,
    FunctionIdentity::GroupSessionCommitted,
    FunctionIdentity::GroupPublishCommitted,
    FunctionIdentity::GroupRollback,
    FunctionIdentity::GroupPoison,
];
const GROUP_TERMINAL: &[FunctionIdentity] = &[
    FunctionIdentity::GroupPublishCommitted,
    FunctionIdentity::GroupRollback,
    FunctionIdentity::GroupPoison,
];

const RECEIVER_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ReceiverTransferCore,
        field: FieldIdentity::Receiver,
        source_field: "receiver",
        resource_type: TypeIdentity::ManagedReceiver,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ReceiverTransferCore,
        field: FieldIdentity::ReceiverGeneration,
        source_field: "generation",
        resource_type: TypeIdentity::ReceiverTransferCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ReceiverTransferCore,
        field: FieldIdentity::ReceiverOwner,
        source_field: "owner",
        resource_type: TypeIdentity::ReceiverTransferCore,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::ReceiverGeneration),
];
const RECEIVER_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::ReceiverClaim,
    FunctionIdentity::ReceiverPublishReplacement,
    FunctionIdentity::ReceiverTransferToOwner,
    FunctionIdentity::ReceiverOwnerExit,
];

const OBSERVATION_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ObservationLifecycleCore,
        field: FieldIdentity::ObservationState,
        source_field: "state",
        resource_type: TypeIdentity::ObservationLifecycleCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ObservationLifecycleCore,
        field: FieldIdentity::ObservationBinding,
        source_field: "binding",
        resource_type: TypeIdentity::ObservationLifecycleCore,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::ControlObservation),
];

const WORKER_STATE_RESOURCES: &[ResourceIdentity] = &[ResourceIdentity::OwnedField {
    owner: TypeIdentity::WorkerStateTransaction,
    field: FieldIdentity::WorkerStateBundle,
    source_field: "staged",
    resource_type: TypeIdentity::WorkerStateTransaction,
}];
const WORKER_STATE_METHODS: &[FunctionIdentity] = &[FunctionIdentity::WorkerStateRun];
const DIAGNOSTIC_CAPTURE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::DiagnosticCaptureTransaction,
        field: FieldIdentity::DiagnosticManagerSnapshot,
        source_field: "manager_before",
        resource_type: TypeIdentity::ManagerMetadata,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::DiagnosticCaptureTransaction,
        field: FieldIdentity::DiagnosticFlowLease,
        source_field: "flow_lease",
        resource_type: TypeIdentity::FlowVisibilityLease,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::DiagnosticCaptureTransaction,
        field: FieldIdentity::DiagnosticFlowSnapshot,
        source_field: "flow_snapshot",
        resource_type: TypeIdentity::FlowSnapshot,
    },
];
const OBSERVATION_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::ObservationBegin,
    FunctionIdentity::ObservationFinishReceive,
    FunctionIdentity::ObservationBlocksExact,
    FunctionIdentity::ObservationClear,
];

const RETRY_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ObservedStaleRetry,
        field: FieldIdentity::RetryPayload,
        source_field: "payload",
        resource_type: TypeIdentity::OwnedPayload,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ObservedStaleRetry,
        field: FieldIdentity::RetryIdentity,
        source_field: "identity",
        resource_type: TypeIdentity::ObservedStaleRetry,
    },
];
const RETRY_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::StaleRetryNew,
    FunctionIdentity::StaleRetryAuthorizeTransition,
    FunctionIdentity::StaleRetryReconciled,
    FunctionIdentity::StaleRetryAuthorize,
    FunctionIdentity::StaleRetryComplete,
];

const HANDSHAKE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::HandshakeCommitCore,
        field: FieldIdentity::HandshakePayload,
        source_field: "payload",
        resource_type: TypeIdentity::OwnedPayload,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::HandshakeCommitCore,
        field: FieldIdentity::HandshakePhase,
        source_field: "phase",
        resource_type: TypeIdentity::HandshakeCommitCore,
    },
];
const HANDSHAKE_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::HandshakeNew,
    FunctionIdentity::HandshakeManagerPublished,
    FunctionIdentity::HandshakeCommitSession,
    FunctionIdentity::HandshakeBeginSend,
    FunctionIdentity::HandshakeCompleteSuccess,
    FunctionIdentity::HandshakeCompleteFailure,
    FunctionIdentity::HandshakeRollback,
];

const RECOVERY_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::RecoverySendCore,
        field: FieldIdentity::RecoveryPayload,
        source_field: "payload",
        resource_type: TypeIdentity::OwnedPayload,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::RecoverySendCore,
        field: FieldIdentity::RecoveryPhase,
        source_field: "phase",
        resource_type: TypeIdentity::RecoverySendCore,
    },
];
const RECOVERY_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::RecoveryNew,
    FunctionIdentity::RecoveryLeaseDue,
    FunctionIdentity::RecoveryPrepareSequence,
    FunctionIdentity::RecoveryCompleteSend,
    FunctionIdentity::RecoveryObserveRecognition,
];

const STATS_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::StatsSealingTransaction,
        resource_type: TypeIdentity::StatsPublicationQueue,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::StatsSealingTransaction,
        resource_type: TypeIdentity::StatsFinalityCore,
    },
];
const STATS_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::StatsNew,
    FunctionIdentity::StatsClaim,
    FunctionIdentity::StatsBeginSealing,
    FunctionIdentity::StatsQueuePublication,
    FunctionIdentity::StatsFinishSealing,
    FunctionIdentity::StatsAcceptNext,
    FunctionIdentity::StatsAcknowledge,
    FunctionIdentity::StatsAbandon,
];

const SHUTDOWN_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ShutdownPublicationCore,
        field: FieldIdentity::ShutdownState,
        source_field: "state",
        resource_type: TypeIdentity::ShutdownCause,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::ShutdownPublication),
];
const SHUTDOWN_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::ShutdownPublishFatal,
    FunctionIdentity::WorkerTerminationBegin,
    FunctionIdentity::WorkerTerminationComplete,
];

const OUTCOME_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ThreadOutcomeCore,
        field: FieldIdentity::ThreadOutcome,
        source_field: "outcome",
        resource_type: TypeIdentity::ThreadOutcomeCore,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::ThreadOutcome),
];

const FLOW_GATE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::FlowTopologyCoordinator,
        field: FieldIdentity::GateState,
        source_field: "gate",
        resource_type: TypeIdentity::FlowTopologyCoordinator,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::FlowTopologyCoordinator,
        field: FieldIdentity::GateLanes,
        source_field: "reader_lanes",
        resource_type: TypeIdentity::FlowTopologyCoordinator,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::FlowGateSnapshot),
];

const MAINTENANCE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::MaintenanceDeadline),
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::MaintenanceRepairOwnership),
];

const PACING_RESOURCES: &[ResourceIdentity] = &[ResourceIdentity::AtomicProtocol(
    AtomicProtocolId::PacingDeadline,
)];
const PACING_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::PacingRead,
    FunctionIdentity::PacingPublish,
];

const SOCKET_GATE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ManagedSocketInner,
        field: FieldIdentity::GateState,
        source_field: "io_gate",
        resource_type: TypeIdentity::ManagedSocketInner,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ManagedSocketInner,
        field: FieldIdentity::GateLanes,
        source_field: "worker_io_lanes",
        resource_type: TypeIdentity::ManagedSocketInner,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::SocketGateAssociation),
];

const RESERVATION_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::FifoReservationCore,
        field: FieldIdentity::ReservationTickets,
        source_field: "tickets",
        resource_type: TypeIdentity::FifoReservationCore,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::ReservationOwnership),
];

const DESCRIPTOR_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ManagedSocketInner,
        field: FieldIdentity::DescriptorGeneration,
        source_field: "descriptor_revocation_generation",
        resource_type: TypeIdentity::DescriptorOwner,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ManagedSocketInner,
        field: FieldIdentity::DescriptorAcknowledgements,
        source_field: "worker_io_lanes",
        resource_type: TypeIdentity::ManagedSocketInner,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::DescriptorGeneration),
];

const DESCRIPTOR_CACHE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::DescriptorCacheOwnership),
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::DescriptorCacheCore,
        field: FieldIdentity::CachedDescriptor,
        source_field: "descriptor",
        resource_type: TypeIdentity::DescriptorOwner,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::DescriptorCacheCore,
        field: FieldIdentity::DescriptorCacheRegistration,
        source_field: "registered",
        resource_type: TypeIdentity::DescriptorCacheCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::DescriptorCacheCore,
        field: FieldIdentity::DescriptorCacheEpoch,
        source_field: "topology_epoch",
        resource_type: TypeIdentity::DescriptorCacheCore,
    },
];

const DESCRIPTOR_CACHE_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::DescriptorCacheRegister,
    FunctionIdentity::DescriptorCacheAcknowledge,
    FunctionIdentity::DescriptorCacheUnregister,
];

const RERESOLVE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ReresolvePublicationCore,
        field: FieldIdentity::ReresolveManagerBundle,
        source_field: "manager",
        resource_type: TypeIdentity::PreparedReresolveGroup,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::ReresolvePublicationCore,
        field: FieldIdentity::ReresolveFlowVisibility,
        source_field: "flow",
        resource_type: TypeIdentity::FlowVisibilityLease,
    },
];

const RERESOLVE_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::ReresolvePublishManager,
    FunctionIdentity::ReresolvePublishFlow,
];

const FLOW_CLAIM_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::FlowClaimOwnershipCore,
        field: FieldIdentity::FlowClaimState,
        source_field: "state",
        resource_type: TypeIdentity::FlowClaimOwnershipCore,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::FlowClaimOwnership),
];
const FLOW_CLAIM_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::FlowClaimReserve,
    FunctionIdentity::FlowClaimCommit,
    FunctionIdentity::FlowClaimTake,
    FunctionIdentity::FlowClaimRelease,
];

const AUDIT_SLOT_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::AuditSlotPublicationCore,
        field: FieldIdentity::AuditSlotState,
        source_field: "state",
        resource_type: TypeIdentity::AuditSlotPublicationCore,
    },
    ResourceIdentity::OwnedField {
        owner: TypeIdentity::AuditSlotPublicationCore,
        field: FieldIdentity::AuditSlotPayload,
        source_field: "payload",
        resource_type: TypeIdentity::AuditSlotPublicationCore,
    },
    ResourceIdentity::AtomicProtocol(AtomicProtocolId::AuditSlotPublication),
];
const AUDIT_SLOT_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::AuditSlotRegister,
    FunctionIdentity::AuditSlotBegin,
    FunctionIdentity::AuditSlotSeal,
    FunctionIdentity::AuditSlotAbandon,
];

const SINGLE_CONSUMER_RESOURCES: &[ResourceIdentity] = &[ResourceIdentity::OwnedField {
    owner: TypeIdentity::SingleConsumerBootstrap,
    field: FieldIdentity::SingleConsumerValue,
    source_field: "value",
    resource_type: TypeIdentity::SingleConsumerBootstrap,
}];

const ASSOCIATION_RESOURCES: &[ResourceIdentity] = &[ResourceIdentity::OwnedField {
    owner: TypeIdentity::AssociationAuthorityState,
    field: FieldIdentity::AssociationPair,
    source_field: "association",
    resource_type: TypeIdentity::AssociationAuthorityState,
}];

const FLOW_TOPOLOGY_TYPESTATE_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::FlowTopologyTransaction,
        resource_type: TypeIdentity::FlowTopologyCoordinator,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::FlowTopologyTransaction,
        resource_type: TypeIdentity::FlowSnapshot,
    },
];
const FLOW_TOPOLOGY_TYPESTATE_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::FlowTopologyApplySockets,
    FunctionIdentity::FlowTopologyPrepareManager,
    FunctionIdentity::FlowTopologyCommitSession,
    FunctionIdentity::FlowTopologyPublish,
];

const SOCKET_RETIREMENT_RESOURCES: &[ResourceIdentity] = &[
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::SocketRetirementTransaction,
        resource_type: TypeIdentity::DescriptorOwner,
    },
    ResourceIdentity::ExclusiveLease {
        lease: TypeIdentity::SocketRetirementTransaction,
        resource_type: TypeIdentity::AssociationAuthorityState,
    },
];
const SOCKET_RETIREMENT_METHODS: &[FunctionIdentity] = &[
    FunctionIdentity::SocketRetireDescriptor,
    FunctionIdentity::SocketBindReplacement,
    FunctionIdentity::SocketPublishRetirement,
];

macro_rules! lifecycle {
    ($invariant:ident, $owner:ident, $resources:expr, $acquire:expr, $mutate:expr, $terminal:expr, $runtime:expr, $loom:expr) => {
        LifecycleOwnershipRecord {
            invariant: InvariantId::$invariant,
            loom_class: LoomEvidenceClass::ProductionCore,
            owner: TypeIdentity::$owner,
            resources: $resources,
            acquisition_methods: $acquire,
            mutation_methods: $mutate,
            terminal_methods: $terminal,
            runtime_entry_points: $runtime,
            loom_entry_points: $loom,
        }
    };
}

pub(crate) const LIFECYCLE_OWNERSHIP_RECORDS: &[LifecycleOwnershipRecord] = &[
    lifecycle!(
        SendCompletion,
        SendCompletionCore,
        SEND_RESOURCES,
        SEND_ACQUIRE,
        SEND_MUTATE,
        SEND_TERMINAL,
        SEND_MUTATE,
        SEND_MUTATE
    ),
    lifecycle!(
        GroupPublication,
        GroupPublicationTransaction,
        GROUP_RESOURCES,
        GROUP_ACQUIRE,
        GROUP_MUTATE,
        GROUP_TERMINAL,
        GROUP_MUTATE,
        GROUP_MUTATE
    ),
    lifecycle!(
        ReceiverTransfer,
        ReceiverTransferCore,
        RECEIVER_RESOURCES,
        &[FunctionIdentity::ReceiverClaim],
        RECEIVER_METHODS,
        &[FunctionIdentity::ReceiverOwnerExit],
        RECEIVER_METHODS,
        RECEIVER_METHODS
    ),
    lifecycle!(
        ControlObservation,
        ObservationLifecycleCore,
        OBSERVATION_RESOURCES,
        &[FunctionIdentity::ObservationBegin],
        OBSERVATION_METHODS,
        &[FunctionIdentity::ObservationClear],
        OBSERVATION_METHODS,
        OBSERVATION_METHODS
    ),
    lifecycle!(
        StaleAssociationRetry,
        ObservedStaleRetry,
        RETRY_RESOURCES,
        &[FunctionIdentity::StaleRetryNew],
        RETRY_METHODS,
        &[FunctionIdentity::StaleRetryComplete],
        RETRY_METHODS,
        RETRY_METHODS
    ),
    lifecycle!(
        HandshakeCompletion,
        HandshakeCommitCore,
        HANDSHAKE_RESOURCES,
        &[FunctionIdentity::HandshakeNew],
        HANDSHAKE_METHODS,
        &[
            FunctionIdentity::HandshakeCompleteSuccess,
            FunctionIdentity::HandshakeCompleteFailure,
            FunctionIdentity::HandshakeRollback
        ],
        HANDSHAKE_METHODS,
        HANDSHAKE_METHODS
    ),
    lifecycle!(
        RecoveryPayload,
        RecoverySendCore,
        RECOVERY_RESOURCES,
        &[FunctionIdentity::RecoveryNew],
        RECOVERY_METHODS,
        &[FunctionIdentity::RecoveryCompleteSend],
        RECOVERY_METHODS,
        RECOVERY_METHODS
    ),
    lifecycle!(
        StatsFinality,
        StatsSealingTransaction,
        STATS_RESOURCES,
        &[FunctionIdentity::StatsClaim],
        STATS_METHODS,
        &[
            FunctionIdentity::StatsFinishSealing,
            FunctionIdentity::StatsAbandon
        ],
        STATS_METHODS,
        STATS_METHODS
    ),
    lifecycle!(
        ShutdownPublication,
        ShutdownPublicationCore,
        SHUTDOWN_RESOURCES,
        &[],
        SHUTDOWN_METHODS,
        &[FunctionIdentity::WorkerTerminationComplete],
        SHUTDOWN_METHODS,
        SHUTDOWN_METHODS
    ),
    lifecycle!(
        ThreadOutcomePublication,
        ThreadOutcomeCore,
        OUTCOME_RESOURCES,
        &[],
        &[
            FunctionIdentity::WorkerTerminationBegin,
            FunctionIdentity::WorkerTerminationComplete
        ],
        &[FunctionIdentity::WorkerTerminationComplete],
        &[FunctionIdentity::WorkerTerminationBegin],
        &[
            FunctionIdentity::WorkerTerminationBegin,
            FunctionIdentity::WorkerTerminationComplete
        ]
    ),
    lifecycle!(
        FlowReaderDrain,
        FlowTopologyCoordinator,
        FLOW_GATE_RESOURCES,
        &[FunctionIdentity::FlowCloseAndDrain],
        &[
            FunctionIdentity::FlowCloseAndDrain,
            FunctionIdentity::FlowReaderRelease
        ],
        &[FunctionIdentity::FlowCloseAndDrain],
        &[
            FunctionIdentity::FlowCloseAndDrain,
            FunctionIdentity::FlowReaderRelease
        ],
        &[
            FunctionIdentity::FlowCloseAndDrain,
            FunctionIdentity::FlowReaderRelease
        ]
    ),
    lifecycle!(
        MaintenancePublication,
        FlowRuntimeState,
        MAINTENANCE_RESOURCES,
        &[FunctionIdentity::MaintenancePublish],
        &[FunctionIdentity::MaintenancePublish],
        &[FunctionIdentity::MaintenancePublish],
        &[
            FunctionIdentity::MaintenancePublish,
            FunctionIdentity::MaintenanceRead
        ],
        &[
            FunctionIdentity::MaintenancePublish,
            FunctionIdentity::MaintenanceRead
        ]
    ),
    lifecycle!(
        PacingPublication,
        GlobalSyncPacer,
        PACING_RESOURCES,
        &[FunctionIdentity::PacingPublish],
        &[FunctionIdentity::PacingPublish],
        &[FunctionIdentity::PacingPublish],
        PACING_METHODS,
        PACING_METHODS
    ),
    lifecycle!(
        SocketIoDrain,
        ManagedSocketInner,
        SOCKET_GATE_RESOURCES,
        &[FunctionIdentity::SocketCloseAndDrain],
        &[
            FunctionIdentity::SocketCloseAndDrain,
            FunctionIdentity::SocketIoRelease
        ],
        &[FunctionIdentity::SocketCloseAndDrain],
        &[
            FunctionIdentity::SocketCloseAndDrain,
            FunctionIdentity::SocketIoRelease
        ],
        &[
            FunctionIdentity::SocketCloseAndDrain,
            FunctionIdentity::SocketIoRelease
        ]
    ),
    lifecycle!(
        FlowClaimOwnership,
        FlowClaimOwnershipCore,
        FLOW_CLAIM_RESOURCES,
        &[FunctionIdentity::FlowClaimReserve],
        FLOW_CLAIM_METHODS,
        &[FunctionIdentity::FlowClaimRelease],
        FLOW_CLAIM_METHODS,
        FLOW_CLAIM_METHODS
    ),
    lifecycle!(
        AuditSlotPublication,
        AuditSlotPublicationCore,
        AUDIT_SLOT_RESOURCES,
        &[FunctionIdentity::AuditSlotRegister],
        AUDIT_SLOT_METHODS,
        &[
            FunctionIdentity::AuditSlotSeal,
            FunctionIdentity::AuditSlotAbandon
        ],
        AUDIT_SLOT_METHODS,
        AUDIT_SLOT_METHODS
    ),
    lifecycle!(
        SingleConsumerTransfer,
        SingleConsumerBootstrap,
        SINGLE_CONSUMER_RESOURCES,
        &[],
        &[FunctionIdentity::SingleConsumerTransfer],
        &[FunctionIdentity::SingleConsumerTransfer],
        &[FunctionIdentity::SingleConsumerTransfer],
        &[FunctionIdentity::SingleConsumerTransfer]
    ),
    lifecycle!(
        AssociationStateCohesion,
        AssociationAuthorityState,
        ASSOCIATION_RESOURCES,
        &[],
        &[FunctionIdentity::AssociationPublish],
        &[FunctionIdentity::AssociationPublish],
        &[FunctionIdentity::AssociationPublish],
        &[FunctionIdentity::AssociationPublish]
    ),
    lifecycle!(
        FlowTopologyTypestate,
        FlowTopologyTransaction,
        FLOW_TOPOLOGY_TYPESTATE_RESOURCES,
        &[FunctionIdentity::FlowTopologyApplySockets],
        FLOW_TOPOLOGY_TYPESTATE_METHODS,
        &[FunctionIdentity::FlowTopologyPublish],
        FLOW_TOPOLOGY_TYPESTATE_METHODS,
        FLOW_TOPOLOGY_TYPESTATE_METHODS
    ),
    lifecycle!(
        SocketRetirementTypestate,
        SocketRetirementTransaction,
        SOCKET_RETIREMENT_RESOURCES,
        &[FunctionIdentity::SocketRetireDescriptor],
        SOCKET_RETIREMENT_METHODS,
        &[FunctionIdentity::SocketPublishRetirement],
        SOCKET_RETIREMENT_METHODS,
        SOCKET_RETIREMENT_METHODS
    ),
    lifecycle!(
        WorkerStateTransaction,
        WorkerStateTransaction,
        WORKER_STATE_RESOURCES,
        &[FunctionIdentity::WorkerStateRun],
        WORKER_STATE_METHODS,
        &[FunctionIdentity::WorkerStateRun],
        WORKER_STATE_METHODS,
        WORKER_STATE_METHODS
    ),
    lifecycle!(
        DiagnosticCapture,
        DiagnosticCaptureTransaction,
        DIAGNOSTIC_CAPTURE_RESOURCES,
        &[FunctionIdentity::DiagnosticCaptureRun],
        &[FunctionIdentity::DiagnosticCaptureRun],
        &[FunctionIdentity::DiagnosticCaptureRun],
        &[FunctionIdentity::DiagnosticCaptureRun],
        &[FunctionIdentity::DiagnosticCaptureRun]
    ),
    lifecycle!(
        FifoReservation,
        FifoReservationCore,
        RESERVATION_RESOURCES,
        &[FunctionIdentity::ReservationAllocate],
        &[
            FunctionIdentity::ReservationCancel,
            FunctionIdentity::ReservationRelease,
            FunctionIdentity::ReservationDrop
        ],
        &[
            FunctionIdentity::ReservationRelease,
            FunctionIdentity::ReservationDrop
        ],
        &[
            FunctionIdentity::ReservationAllocate,
            FunctionIdentity::ReservationCancel,
            FunctionIdentity::ReservationRelease,
            FunctionIdentity::ReservationDrop
        ],
        &[
            FunctionIdentity::ReservationAllocate,
            FunctionIdentity::ReservationCancel,
            FunctionIdentity::ReservationRelease,
            FunctionIdentity::ReservationDrop
        ]
    ),
    lifecycle!(
        DescriptorCacheOwnership,
        DescriptorCacheCore,
        DESCRIPTOR_CACHE_RESOURCES,
        &[FunctionIdentity::DescriptorCacheRegister],
        DESCRIPTOR_CACHE_METHODS,
        &[
            FunctionIdentity::DescriptorCacheAcknowledge,
            FunctionIdentity::DescriptorCacheUnregister
        ],
        DESCRIPTOR_CACHE_METHODS,
        DESCRIPTOR_CACHE_METHODS
    ),
    lifecycle!(
        DescriptorRevocation,
        ManagedSocketInner,
        DESCRIPTOR_RESOURCES,
        &[FunctionIdentity::DescriptorRequestRevocation],
        &[FunctionIdentity::DescriptorAcknowledgeRevocation],
        &[FunctionIdentity::DescriptorAcknowledgeRevocation],
        &[
            FunctionIdentity::DescriptorRequestRevocation,
            FunctionIdentity::DescriptorAcknowledgeRevocation
        ],
        &[
            FunctionIdentity::DescriptorRequestRevocation,
            FunctionIdentity::DescriptorAcknowledgeRevocation
        ]
    ),
    lifecycle!(
        ReresolvePublication,
        ReresolvePublicationCore,
        RERESOLVE_RESOURCES,
        &[FunctionIdentity::ReresolveNew],
        RERESOLVE_METHODS,
        &[FunctionIdentity::ReresolvePublishFlow],
        RERESOLVE_METHODS,
        RERESOLVE_METHODS
    ),
];
