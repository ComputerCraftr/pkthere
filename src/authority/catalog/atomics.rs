use super::super::{
    AtomicProtocolId, AtomicProtocolRecord, AtomicRole, AtomicTransition, AuthorityId,
    FunctionIdentity, InvariantId, MemoryOrdering, TypeIdentity,
};

const LOAD_STORE_ORDERINGS: &[MemoryOrdering] = &[
    MemoryOrdering::Relaxed,
    MemoryOrdering::Acquire,
    MemoryOrdering::Release,
];
const CAS_ORDERINGS: &[MemoryOrdering] = &[
    MemoryOrdering::Relaxed,
    MemoryOrdering::Acquire,
    MemoryOrdering::Release,
    MemoryOrdering::AcqRel,
];
const DIAGNOSTIC_ORDERINGS: &[MemoryOrdering] = CAS_ORDERINGS;

const FLOW_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "open(epoch)",
        to: "closed(epoch)",
        linearization: FunctionIdentity::FlowCloseAndDrain,
    },
    AtomicTransition {
        from: "active(epoch)",
        to: "inactive",
        linearization: FunctionIdentity::FlowReaderRelease,
    },
];

const SOCKET_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "open(epoch)",
        to: "closed(epoch)",
        linearization: FunctionIdentity::SocketCloseAndDrain,
    },
    AtomicTransition {
        from: "active(epoch)",
        to: "inactive",
        linearization: FunctionIdentity::SocketIoRelease,
    },
];

const DESCRIPTOR_CACHE_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "unregistered",
        to: "registered",
        linearization: FunctionIdentity::DescriptorCacheRegister,
    },
    AtomicTransition {
        from: "registered",
        to: "unregistered after cached descriptor drop",
        linearization: FunctionIdentity::DescriptorCacheUnregister,
    },
];

const MAINTENANCE_REPAIR_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "unowned",
        to: "repair-owned",
        linearization: FunctionIdentity::MaintenancePublish,
    },
    AtomicTransition {
        from: "repair-owned",
        to: "unowned after epoch/deadline publication",
        linearization: FunctionIdentity::MaintenancePublish,
    },
];

const RESERVATION_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "queued(ticket)",
        to: "owned(ticket)",
        linearization: FunctionIdentity::ReservationAllocate,
    },
    AtomicTransition {
        from: "owned(ticket)",
        to: "released(ticket)",
        linearization: FunctionIdentity::ReservationRelease,
    },
    AtomicTransition {
        from: "queued(ticket)",
        to: "cancelled(ticket)",
        linearization: FunctionIdentity::ReservationCancel,
    },
];

const FLOW_CLAIM_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "vacant",
        to: "reserved(generation)",
        linearization: FunctionIdentity::FlowClaimReserve,
    },
    AtomicTransition {
        from: "reserved(generation)",
        to: "committed(generation)",
        linearization: FunctionIdentity::FlowClaimCommit,
    },
    AtomicTransition {
        from: "committed(generation)",
        to: "taken(generation)",
        linearization: FunctionIdentity::FlowClaimTake,
    },
    AtomicTransition {
        from: "owned(generation)",
        to: "vacant",
        linearization: FunctionIdentity::FlowClaimRelease,
    },
];

const AUDIT_SLOT_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "unclaimed",
        to: "registered after identity installation",
        linearization: FunctionIdentity::AuditSlotRegister,
    },
    AtomicTransition {
        from: "registered",
        to: "running",
        linearization: FunctionIdentity::AuditSlotBegin,
    },
    AtomicTransition {
        from: "running",
        to: "terminal after record installation",
        linearization: FunctionIdentity::AuditSlotSeal,
    },
    AtomicTransition {
        from: "registered",
        to: "abandoned",
        linearization: FunctionIdentity::AuditSlotAbandon,
    },
];

const SEND_TRANSITIONS: &[AtomicTransition] = &[
    AtomicTransition {
        from: "vacant",
        to: "reserved",
        linearization: FunctionIdentity::SendReserve,
    },
    AtomicTransition {
        from: "reserved",
        to: "in_flight",
        linearization: FunctionIdentity::SendArm,
    },
    AtomicTransition {
        from: "in_flight",
        to: "sent_or_failed",
        linearization: FunctionIdentity::SendCompleteSuccess,
    },
    AtomicTransition {
        from: "active_or_exhausted",
        to: "superseded_or_retired",
        linearization: FunctionIdentity::SendRequestRetirement,
    },
];

const GROUP_TRANSITIONS: &[AtomicTransition] = &[AtomicTransition {
    from: "gates_closed",
    to: "CAS-owned publishing then published_or_poisoned",
    linearization: FunctionIdentity::GroupPublishCommitted,
}];

const RECEIVER_TRANSITIONS: &[AtomicTransition] = &[AtomicTransition {
    from: "generation(n)",
    to: "generation(n+1)",
    linearization: FunctionIdentity::ReceiverPublishReplacement,
}];

const OBSERVATION_TRANSITIONS: &[AtomicTransition] = &[AtomicTransition {
    from: "polling(generation)",
    to: "observed_or_empty",
    linearization: FunctionIdentity::ObservationFinishReceive,
}];

const STATS_TRANSITIONS: &[AtomicTransition] = &[AtomicTransition {
    from: "running",
    to: "sealing_or_abandoned",
    linearization: FunctionIdentity::StatsBeginSealing,
}];

const PACING_TRANSITIONS: &[AtomicTransition] = &[AtomicTransition {
    from: "never-paced or interval-due tick",
    to: "uniquely claimed current tick",
    linearization: FunctionIdentity::PacingPublish,
}];

const SHUTDOWN_TRANSITIONS: &[AtomicTransition] = &[AtomicTransition {
    from: "running_or_graceful",
    to: "fatal_published",
    linearization: FunctionIdentity::ShutdownPublishFatal,
}];

macro_rules! protocol {
    ($id:ident, $owner:ident, $authorities:expr, $role:ident, $encoding:literal, $writers:expr, $readers:expr, $transitions:expr, $orderings:expr, $linearization:expr, $invariants:expr) => {
        AtomicProtocolRecord {
            id: AtomicProtocolId::$id,
            owner: TypeIdentity::$owner,
            allowed_authorities: $authorities,
            role: AtomicRole::$role,
            state_encoding: $encoding,
            allowed_writers: $writers,
            allowed_readers: $readers,
            allowed_transitions: $transitions,
            allowed_orderings: $orderings,
            linearization_points: $linearization,
            loom_invariants: $invariants,
        }
    };
}

pub(crate) const ATOMIC_PROTOCOL_RECORDS: &[AtomicProtocolRecord] = &[
    protocol!(
        FlowGateSnapshot,
        FlowTopologyCoordinator,
        &[AuthorityId::FlowRead, AuthorityId::FlowWrite],
        Publication,
        "open/closed epoch plus lane epochs",
        &[
            FunctionIdentity::FlowCloseAndDrain,
            FunctionIdentity::FlowReaderRelease
        ],
        &[FunctionIdentity::FlowCloseAndDrain],
        FLOW_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::FlowCloseAndDrain,
            FunctionIdentity::FlowReaderRelease
        ],
        &[InvariantId::FlowReaderDrain]
    ),
    protocol!(
        ReservationOwnership,
        FifoReservationCore,
        &[
            AuthorityId::FlowReservation,
            AuthorityId::FlowWrite,
            AuthorityId::ManagerTransaction
        ],
        OwnershipClaim,
        "next, serving, owner tickets, cancellation states, corruption, and wake generation",
        &[
            FunctionIdentity::ReservationAllocate,
            FunctionIdentity::ReservationCancel,
            FunctionIdentity::ReservationRelease,
            FunctionIdentity::ReservationDrop
        ],
        &[
            FunctionIdentity::ReservationAllocate,
            FunctionIdentity::ReservationRelease
        ],
        RESERVATION_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::ReservationAllocate,
            FunctionIdentity::ReservationCancel,
            FunctionIdentity::ReservationRelease
        ],
        &[InvariantId::FifoReservation]
    ),
    protocol!(
        FlowClaimOwnership,
        FlowClaimOwnershipCore,
        &[AuthorityId::FlowClaim],
        OwnershipClaim,
        "vacant or generation-bound reserved/committed/taken ownership",
        &[
            FunctionIdentity::FlowClaimReserve,
            FunctionIdentity::FlowClaimCommit,
            FunctionIdentity::FlowClaimTake,
            FunctionIdentity::FlowClaimRelease
        ],
        &[
            FunctionIdentity::FlowClaimTake,
            FunctionIdentity::FlowClaimRelease
        ],
        FLOW_CLAIM_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::FlowClaimReserve,
            FunctionIdentity::FlowClaimCommit,
            FunctionIdentity::FlowClaimTake,
            FunctionIdentity::FlowClaimRelease
        ],
        &[InvariantId::FlowClaimOwnership]
    ),
    protocol!(
        ManagerPublication,
        GroupPublicationCore,
        &[AuthorityId::ManagerState],
        LifecycleState,
        "phase, component completion, manager count",
        &[
            FunctionIdentity::GroupSocketTransitionsApplied,
            FunctionIdentity::GroupManagerStatePrepared,
            FunctionIdentity::GroupSessionCommitted,
            FunctionIdentity::GroupPublishCommitted,
            FunctionIdentity::GroupPoison
        ],
        &[FunctionIdentity::GroupPublishCommitted],
        GROUP_TRANSITIONS,
        CAS_ORDERINGS,
        &[FunctionIdentity::GroupPublishCommitted],
        &[InvariantId::GroupPublication]
    ),
    protocol!(
        SocketGateAssociation,
        ManagedSocketInner,
        &[
            AuthorityId::SocketTopology,
            AuthorityId::SocketAssociation,
            AuthorityId::SocketIo
        ],
        Publication,
        "open/closed topology epoch and association epoch",
        &[
            FunctionIdentity::SocketCloseAndDrain,
            FunctionIdentity::SocketIoRelease
        ],
        &[FunctionIdentity::SocketCloseAndDrain],
        SOCKET_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::SocketCloseAndDrain,
            FunctionIdentity::SocketIoRelease
        ],
        &[InvariantId::SocketIoDrain]
    ),
    protocol!(
        DescriptorCacheOwnership,
        DescriptorCacheCore,
        &[AuthorityId::SocketTopology],
        OwnershipClaim,
        "one registration claim per worker/socket lane",
        &[
            FunctionIdentity::DescriptorCacheRegister,
            FunctionIdentity::DescriptorCacheUnregister
        ],
        &[FunctionIdentity::DescriptorRequestRevocation],
        DESCRIPTOR_CACHE_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::DescriptorCacheRegister,
            FunctionIdentity::DescriptorCacheUnregister
        ],
        &[InvariantId::DescriptorCacheOwnership]
    ),
    protocol!(
        DescriptorGeneration,
        ManagedSocketInner,
        &[AuthorityId::SocketDescriptor, AuthorityId::SocketTopology],
        GenerationOrVersion,
        "published generation and per-worker acknowledgement",
        &[
            FunctionIdentity::DescriptorRequestRevocation,
            FunctionIdentity::DescriptorAcknowledgeRevocation
        ],
        &[FunctionIdentity::DescriptorAcknowledgeRevocation],
        &[],
        LOAD_STORE_ORDERINGS,
        &[
            FunctionIdentity::DescriptorRequestRevocation,
            FunctionIdentity::DescriptorAcknowledgeRevocation
        ],
        &[InvariantId::DescriptorRevocation]
    ),
    protocol!(
        ReceiverGeneration,
        ReceiverTransferCore,
        &[AuthorityId::ReceiverClaim],
        GenerationOrVersion,
        "receiver generation published after resource installation",
        &[
            FunctionIdentity::ReceiverPublishReplacement,
            FunctionIdentity::ReceiverOwnerExit
        ],
        &[
            FunctionIdentity::ReceiverClaim,
            FunctionIdentity::ReceiverTransferToOwner
        ],
        RECEIVER_TRANSITIONS,
        LOAD_STORE_ORDERINGS,
        &[FunctionIdentity::ReceiverPublishReplacement],
        &[InvariantId::ReceiverTransfer]
    ),
    protocol!(
        TransmitCompletion,
        SendCompletionCore,
        &[AuthorityId::ProtocolTransmit],
        LifecycleState,
        "sequence-indexed completion and retirement state",
        &[
            FunctionIdentity::SendReserve,
            FunctionIdentity::SendArm,
            FunctionIdentity::SendObserveControl,
            FunctionIdentity::SendCompleteSuccess,
            FunctionIdentity::SendCompleteFailure,
            FunctionIdentity::SendRequestRetirement,
            FunctionIdentity::SendCompleteRetirement
        ],
        &[
            FunctionIdentity::SendReserve,
            FunctionIdentity::SendObserveControl,
            FunctionIdentity::SendCompleteRetirement
        ],
        SEND_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::SendReserve,
            FunctionIdentity::SendArm,
            FunctionIdentity::SendObserveControl,
            FunctionIdentity::SendCompleteSuccess,
            FunctionIdentity::SendCompleteFailure,
            FunctionIdentity::SendRequestRetirement
        ],
        &[InvariantId::SendCompletion]
    ),
    protocol!(
        ReceiveReplay,
        ReceiveSession,
        &[AuthorityId::ProtocolReceive, AuthorityId::SessionControl],
        LifecycleState,
        "direction-local replay state",
        &[FunctionIdentity::ReplayAdmit, FunctionIdentity::ReplayReset],
        &[FunctionIdentity::ReplayAdmit],
        &[],
        CAS_ORDERINGS,
        &[FunctionIdentity::ReplayAdmit, FunctionIdentity::ReplayReset],
        &[InvariantId::SendCompletion]
    ),
    protocol!(
        ControlObservation,
        ObservationLifecycleCore,
        &[AuthorityId::ControlObservation],
        Publication,
        "empty/polling/observed generation and exact binding",
        &[
            FunctionIdentity::ObservationBegin,
            FunctionIdentity::ObservationFinishReceive,
            FunctionIdentity::ObservationClear
        ],
        &[FunctionIdentity::ObservationBlocksExact],
        OBSERVATION_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::ObservationBegin,
            FunctionIdentity::ObservationFinishReceive,
            FunctionIdentity::ObservationClear
        ],
        &[InvariantId::ControlObservation]
    ),
    protocol!(
        ActivityPublication,
        FlowTopologyCoordinator,
        &[AuthorityId::Activity],
        Publication,
        "single-writer sequence plus flow epoch and tick",
        &[FunctionIdentity::FlowReaderRelease],
        &[FunctionIdentity::FlowCloseAndDrain],
        &[],
        LOAD_STORE_ORDERINGS,
        &[FunctionIdentity::FlowReaderRelease],
        &[InvariantId::FlowReaderDrain]
    ),
    protocol!(
        MaintenanceDeadline,
        FlowRuntimeState,
        &[AuthorityId::Maintenance],
        Publication,
        "maintenance epoch and absolute deadline",
        &[FunctionIdentity::MaintenancePublish],
        &[FunctionIdentity::MaintenanceRead],
        &[],
        LOAD_STORE_ORDERINGS,
        &[FunctionIdentity::MaintenancePublish],
        &[InvariantId::MaintenancePublication]
    ),
    protocol!(
        MaintenanceRepairOwnership,
        FlowRuntimeState,
        &[AuthorityId::Maintenance],
        OwnershipClaim,
        "unowned or unique repair owner",
        &[FunctionIdentity::MaintenancePublish],
        &[FunctionIdentity::MaintenanceRead],
        MAINTENANCE_REPAIR_TRANSITIONS,
        CAS_ORDERINGS,
        &[FunctionIdentity::MaintenancePublish],
        &[InvariantId::MaintenancePublication]
    ),
    protocol!(
        WakeCoalescing,
        FlowTopologyCoordinator,
        &[
            AuthorityId::WakeGeneration,
            AuthorityId::WaitCoordination,
            AuthorityId::RuntimeSupervisor,
            AuthorityId::FlowWrite,
            AuthorityId::SocketTopology,
            AuthorityId::StatsPublication
        ],
        WakeCoalescing,
        "pending bit and checked wake generation",
        &[
            FunctionIdentity::FlowReaderRelease,
            FunctionIdentity::SocketIoRelease
        ],
        &[
            FunctionIdentity::FlowCloseAndDrain,
            FunctionIdentity::SocketCloseAndDrain
        ],
        &[],
        CAS_ORDERINGS,
        &[
            FunctionIdentity::FlowReaderRelease,
            FunctionIdentity::SocketIoRelease
        ],
        &[InvariantId::FlowReaderDrain, InvariantId::SocketIoDrain]
    ),
    protocol!(
        ShutdownPublication,
        ShutdownPublicationCore,
        &[AuthorityId::RuntimeSupervisor],
        Publication,
        "running/graceful/fatal owner and cause readiness",
        &[FunctionIdentity::ShutdownPublishFatal],
        &[FunctionIdentity::SupervisorEnforceDeadline],
        SHUTDOWN_TRANSITIONS,
        CAS_ORDERINGS,
        &[FunctionIdentity::ShutdownPublishFatal],
        &[InvariantId::ShutdownPublication]
    ),
    protocol!(
        ThreadOutcome,
        ThreadOutcomeCore,
        &[AuthorityId::RuntimeSupervisor],
        LifecycleState,
        "empty/cause-ready/terminal-ready",
        &[
            FunctionIdentity::WorkerTerminationBegin,
            FunctionIdentity::WorkerTerminationComplete
        ],
        &[FunctionIdentity::SupervisorEnforceDeadline],
        &[],
        CAS_ORDERINGS,
        &[
            FunctionIdentity::WorkerTerminationBegin,
            FunctionIdentity::WorkerTerminationComplete
        ],
        &[InvariantId::ThreadOutcomePublication]
    ),
    protocol!(
        AuditSlotPublication,
        AuditSlotPublicationCore,
        &[AuthorityId::RuntimeSupervisor],
        LifecycleState,
        "unclaimed/registered/running/terminal/abandoned with payload-before-state publication",
        &[
            FunctionIdentity::AuditSlotRegister,
            FunctionIdentity::AuditSlotBegin,
            FunctionIdentity::AuditSlotSeal,
            FunctionIdentity::AuditSlotAbandon
        ],
        &[FunctionIdentity::AuditSlotSeal],
        AUDIT_SLOT_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::AuditSlotRegister,
            FunctionIdentity::AuditSlotBegin,
            FunctionIdentity::AuditSlotSeal,
            FunctionIdentity::AuditSlotAbandon
        ],
        &[InvariantId::AuditSlotPublication]
    ),
    protocol!(
        StatsFinality,
        StatsFinalityCore,
        &[AuthorityId::StatsPublication],
        LifecycleState,
        "producer lifecycle, FIFO marker and notification generation",
        &[
            FunctionIdentity::StatsClaim,
            FunctionIdentity::StatsBeginSealing,
            FunctionIdentity::StatsQueuePublication,
            FunctionIdentity::StatsFinishSealing,
            FunctionIdentity::StatsAbandon
        ],
        &[
            FunctionIdentity::StatsAcceptNext,
            FunctionIdentity::StatsAcknowledge
        ],
        STATS_TRANSITIONS,
        CAS_ORDERINGS,
        &[
            FunctionIdentity::StatsBeginSealing,
            FunctionIdentity::StatsQueuePublication,
            FunctionIdentity::StatsAcknowledge
        ],
        &[InvariantId::StatsFinality]
    ),
    protocol!(
        IdentityGeneration,
        RuntimeSupervisor,
        &[
            AuthorityId::IdentityAllocation,
            AuthorityId::ResetBudget,
            AuthorityId::RuntimeSupervisor
        ],
        MonotonicCounter,
        "checked nonzero identity",
        &[FunctionIdentity::IdentityAllocate],
        &[FunctionIdentity::IdentityRead],
        &[],
        CAS_ORDERINGS,
        &[FunctionIdentity::IdentityAllocate],
        &[]
    ),
    protocol!(
        PacingDeadline,
        GlobalSyncPacer,
        &[AuthorityId::Pacing],
        Publication,
        "last-send monotonic deadline tick",
        &[FunctionIdentity::PacingPublish],
        &[FunctionIdentity::PacingRead],
        PACING_TRANSITIONS,
        &[MemoryOrdering::Relaxed],
        &[FunctionIdentity::PacingPublish],
        &[InvariantId::PacingPublication]
    ),
    protocol!(
        DiagnosticCounter,
        RuntimeSupervisor,
        &[AuthorityId::DiagnosticCounter, AuthorityId::Diagnostic],
        DiagnosticOnly,
        "saturating diagnostic counter",
        &[FunctionIdentity::DiagnosticIncrement],
        &[FunctionIdentity::DiagnosticRead],
        &[],
        DIAGNOSTIC_ORDERINGS,
        &[FunctionIdentity::DiagnosticIncrement],
        &[]
    ),
];
