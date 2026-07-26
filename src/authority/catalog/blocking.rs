use super::super::{
    BlockingClass, BlockingContract, EvidenceSource, InterruptMechanism, InvariantId, OperationId,
    TerminalResponse, TypeIdentity, WatchdogOwner,
};

macro_rules! contract {
    ($operation:ident, $class:ident, $deadline:ident, $watchdog:ident, $interrupt:ident, $terminal:ident, $evidence:expr) => {
        BlockingContract {
            operation: OperationId::$operation,
            blocking_class: BlockingClass::$class,
            deadline_owner: TypeIdentity::$deadline,
            watchdog_owner: WatchdogOwner::$watchdog,
            interrupt_mechanism: InterruptMechanism::$interrupt,
            terminal_response: TerminalResponse::$terminal,
            evidence_source: $evidence,
        }
    };
}

pub(crate) const BLOCKING_CONTRACTS: &[BlockingContract] = &[
    contract!(
        Poll,
        BoundedByDeadline,
        RuntimeSupervisor,
        RuntimeSupervisor,
        WakeDescriptor,
        ReturnTypedTimeout,
        EvidenceSource::PlatformReality
    ),
    contract!(
        TopologyDrain,
        BoundedByDeadline,
        FlowTopologyCoordinator,
        RuntimeSupervisor,
        ConditionVariableNotification,
        FatalGateClosed,
        EvidenceSource::ProductionCoreLoom(InvariantId::FlowReaderDrain)
    ),
    contract!(
        ThreadSleep,
        BoundedByDeadline,
        RuntimeSupervisor,
        RuntimeSupervisor,
        NoneRequired,
        ReturnTypedTimeout,
        EvidenceSource::DeterministicRegression(InvariantId::ShutdownPublication)
    ),
    contract!(
        CondvarWait,
        BoundedByDeadline,
        FifoReservationCore,
        RuntimeSupervisor,
        ConditionVariableNotification,
        ReturnTypedTimeout,
        EvidenceSource::ProductionCoreLoom(InvariantId::FifoReservation)
    ),
    contract!(
        ChannelReceive,
        BoundedByDeadline,
        RuntimeSupervisor,
        RuntimeSupervisor,
        ConditionVariableNotification,
        ReturnTypedTimeout,
        EvidenceSource::DeterministicRegression(InvariantId::ShutdownPublication)
    ),
    contract!(
        Allocator,
        KernelBoundedFallback,
        RuntimeSupervisor,
        ParentProcess,
        ProcessTermination,
        FatalProcessExit,
        EvidenceSource::PlatformReality
    ),
    contract!(
        Formatting,
        KernelBoundedFallback,
        RuntimeSupervisor,
        ParentProcess,
        ProcessTermination,
        FatalProcessExit,
        EvidenceSource::PlatformReality
    ),
    contract!(
        Logging,
        KernelBoundedFallback,
        RuntimeSupervisor,
        ParentProcess,
        ProcessTermination,
        FatalProcessExit,
        EvidenceSource::PlatformReality
    ),
    contract!(
        JsonSerialization,
        KernelBoundedFallback,
        RuntimeSupervisor,
        ParentProcess,
        ProcessTermination,
        FatalProcessExit,
        EvidenceSource::PlatformReality
    ),
    contract!(
        SocketDescriptorClose,
        KernelBoundedFallback,
        ManagedSocketInner,
        ParentProcess,
        ProcessTermination,
        FatalProcessExit,
        EvidenceSource::DeterministicRegression(InvariantId::DescriptorRevocation)
    ),
    contract!(
        ThreadJoin,
        BoundedByDeadline,
        RuntimeSupervisor,
        RuntimeSupervisor,
        NoneRequired,
        FatalProcessExit,
        EvidenceSource::DeterministicRegression(InvariantId::ShutdownPublication)
    ),
    contract!(
        StatsFlush,
        BoundedByDeadline,
        StatsFinalityCore,
        RuntimeSupervisor,
        ConditionVariableNotification,
        ReturnTypedTimeout,
        EvidenceSource::ProductionCoreLoom(InvariantId::StatsFinality)
    ),
    contract!(
        PipelineBarrier,
        BoundedByDeadline,
        RuntimeSupervisor,
        RuntimeSupervisor,
        ConditionVariableNotification,
        ReturnTypedTimeout,
        EvidenceSource::DeterministicRegression(InvariantId::SendCompletion)
    ),
];
