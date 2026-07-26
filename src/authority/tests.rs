use super::{
    AuditDirection, AuditedOperationScope, AuthorityCondvar, AuthorityId, AuthorityInstance,
    AuthorityMutex, AuthorityOnceLock, AuthorityScope, OperationId, WorkerAuditIdentity,
    WorkerAuditRegistry, acquisition_count_for_test, allocation_violation_count_for_test, audit,
    operation_count_for_test, shared_rmw_count_for_test, tags, validate_catalog,
    wait_count_for_test,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[test]
fn authority_catalog_is_complete_and_acyclic() {
    assert_eq!(validate_catalog(), Ok(()));
}

#[test]
fn audit_counts_wrapper_acquisitions_and_shared_rmws() {
    let acquisitions = acquisition_count_for_test(AuthorityId::Diagnostic);
    let rmws = shared_rmw_count_for_test(AuthorityId::Diagnostic);
    let counter_rmws = shared_rmw_count_for_test(AuthorityId::DiagnosticCounter);
    let mutex = AuthorityMutex::<tags::Diagnostic, _>::new(
        (),
        AuthorityInstance::singleton(AuthorityId::Diagnostic),
    );
    drop(mutex.lock().expect("diagnostic authority"));
    let counter = super::AuthorityAtomic::<tags::DiagnosticCounter, AtomicU64>::new_u64(
        0,
        super::AtomicProtocolId::DiagnosticCounter,
    );
    assert_eq!(
        counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        }),
        Ok(0)
    );
    assert_eq!(
        acquisition_count_for_test(AuthorityId::Diagnostic),
        acquisitions + 1
    );
    assert_eq!(shared_rmw_count_for_test(AuthorityId::Diagnostic), rmws);
    assert_eq!(
        shared_rmw_count_for_test(AuthorityId::DiagnosticCounter),
        counter_rmws + 1
    );
}

#[test]
fn once_publication_records_only_initialization_attempts() {
    let before = shared_rmw_count_for_test(AuthorityId::DiagnosticCounter);
    let publication = AuthorityOnceLock::<tags::DiagnosticCounter, u64>::new();
    assert_eq!(*publication.get_or_init(|| 17), 17);
    assert_eq!(*publication.get_or_init(|| 23), 17);
    assert_eq!(
        shared_rmw_count_for_test(AuthorityId::DiagnosticCounter),
        before + 1
    );
}

#[test]
fn stable_flow_and_worker_socket_lanes_use_only_lane_local_ownership_rmws() {
    let flow_rmws = shared_rmw_count_for_test(AuthorityId::FlowRead);
    let coordinator = crate::flow_state::FlowTopologyCoordinator::with_reader_lanes(1);
    drop(
        coordinator
            .try_read_lane(crate::flow_state::FlowReaderLane::new(0))
            .expect("claim the production flow reader lane"),
    );
    assert_eq!(
        shared_rmw_count_for_test(AuthorityId::FlowRead),
        flow_rmws + 2,
        "a flow read lease must perform only its lane-local claim and release CAS operations"
    );

    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("create worker-lane socket");
    raw.bind(&socket2::SockAddr::from(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    ))))
    .expect("bind worker-lane socket");
    let local = raw
        .local_addr()
        .expect("worker-lane local address")
        .as_socket()
        .expect("worker-lane socket address");
    let socket = crate::net::managed_socket::ManagedSocket::from_unconnected(
        raw,
        pkthere_socket_policy::PeerVerification::RequirePeerAddr,
        local,
    )
    .expect("construct production managed socket");
    socket
        .configure_worker_io_lanes(1)
        .expect("configure one production worker lane");
    socket
        .bind_authority_identity(pkthere_socket_policy::SocketRole::Listener, 0, 1, false)
        .expect("bind production socket authority identity");
    let mut descriptor_cache = crate::net::managed_socket::WorkerDescriptorCache::for_worker(0);
    descriptor_cache
        .reconcile(&socket)
        .expect("reconcile the worker-owned descriptor cache");
    drop(
        socket
            .acquire_send_lease(&mut descriptor_cache)
            .expect("warm the worker-owned descriptor cache"),
    );
    let socket_rmws = shared_rmw_count_for_test(AuthorityId::SocketIo);
    drop(
        socket
            .acquire_send_lease(&mut descriptor_cache)
            .expect("claim production worker send lane"),
    );
    assert_eq!(
        shared_rmw_count_for_test(AuthorityId::SocketIo),
        socket_rmws + 2,
        "a socket I/O lease must perform only its lane-local claim and release CAS operations"
    );
}

#[test]
fn control_observation_begin_and_clear_use_only_lane_local_ownership_rmws() {
    let state = crate::flow_state::FlowRuntimeState::with_session_pool_size_and_reader_lanes(1, 1);
    let before = shared_rmw_count_for_test(AuthorityId::ControlObservation);
    drop(
        state
            .reserve_control_observation(0, state.flow_epoch(), true)
            .expect("claim the production single-writer observation lane"),
    );
    assert_eq!(
        shared_rmw_count_for_test(AuthorityId::ControlObservation),
        before + 2,
        "an observation lease must perform only its lane-local claim and release CAS operations"
    );
}

#[test]
fn audit_rejects_same_instance_reacquisition() {
    let mutex = AuthorityMutex::<tags::WaitCoordination, _>::new(
        (),
        AuthorityInstance::singleton(AuthorityId::WaitCoordination),
    );
    let _first = mutex.lock().expect("first authority");
    assert!(mutex.lock().is_err());
    assert!(audit::failed());
}

#[test]
fn test_try_lock_validates_before_touching_the_raw_mutex() {
    std::thread::spawn(|| {
        let mutex = AuthorityMutex::<tags::WaitCoordination, _>::new(
            (),
            AuthorityInstance::singleton(AuthorityId::WaitCoordination),
        );
        let _first = mutex.lock().expect("first authority");
        assert!(matches!(
            mutex.try_lock(),
            Err(super::AuthorityTryLockError::Authority(_))
        ));
        assert!(
            audit::failed(),
            "the test-only probe must not bypass the authority stack"
        );
    })
    .join()
    .expect("join pre-lock validation test");
}

#[test]
fn diagnostic_reinitialization_validates_before_touching_the_raw_mutex() {
    let protocol = AuthorityScope::<tags::ProtocolTransmit>::enter(AuthorityInstance {
        id: AuthorityId::ProtocolTransmit,
        flow: 41,
        direction: 0,
        kind: 0,
        session: 9,
    })
    .expect("protocol authority");
    let diagnostic = AuthorityMutex::<tags::Diagnostic, _>::new(
        7_u8,
        AuthorityInstance {
            id: AuthorityId::Diagnostic,
            flow: 41,
            direction: 0,
            kind: 0,
            session: 0,
        },
    );
    assert!(matches!(
        diagnostic.try_lock_reinitializing(|| 0),
        Err(super::AuthorityTryLockError::Authority(
            super::AuthorityError::AcquisitionConflict { .. }
        ))
    ));
    drop(protocol);
}

trait HiddenOperationBoundary {
    fn invoke(&self) -> Result<(), super::AuthorityError>;
}

struct HiddenSocketSend;

impl HiddenOperationBoundary for HiddenSocketSend {
    fn invoke(&self) -> Result<(), super::AuthorityError> {
        hidden_helper_a()
    }
}

fn hidden_helper_a() -> Result<(), super::AuthorityError> {
    hidden_helper_b()
}

fn hidden_helper_b() -> Result<(), super::AuthorityError> {
    AuditedOperationScope::enter(OperationId::SocketSend).map(drop)
}

fn socket_io_scope() -> super::AuthorityScope<tags::SocketIo> {
    AuthorityScope::<tags::SocketIo>::enter(AuthorityInstance {
        id: AuthorityId::SocketIo,
        flow: 41,
        direction: 0,
        kind: 0,
        session: 0,
    })
    .expect("socket I/O authority")
}

#[test]
fn transitive_trait_helper_cannot_hide_a_forbidden_operation() {
    let manager = AuthorityMutex::<tags::ManagerState, _>::new(
        (),
        AuthorityInstance::singleton(AuthorityId::ManagerState),
    );
    let _manager = manager.lock().expect("manager authority");
    assert_eq!(
        HiddenSocketSend.invoke(),
        Err(super::AuthorityError::OperationConflict {
            operation: OperationId::SocketSend,
            held: AuthorityId::ManagerState,
        })
    );
}

#[test]
fn negative_smoke_logging_is_rejected_under_flow_and_manager_authorities() {
    let flow_read = AuthorityScope::<tags::FlowRead>::enter(AuthorityInstance {
        id: AuthorityId::FlowRead,
        flow: 73,
        direction: 0,
        kind: 0,
        session: 0,
    })
    .expect("flow read authority");
    assert_eq!(
        AuditedOperationScope::enter(OperationId::Logging).map(drop),
        Err(super::AuthorityError::OperationConflict {
            operation: OperationId::Logging,
            held: AuthorityId::FlowRead,
        })
    );
    drop(flow_read);

    let flow_reservation = AuthorityScope::<tags::FlowReservation>::enter(
        AuthorityInstance::singleton(AuthorityId::FlowReservation),
    )
    .expect("flow reservation authority");
    assert_eq!(
        AuditedOperationScope::enter(OperationId::Logging).map(drop),
        Err(super::AuthorityError::OperationConflict {
            operation: OperationId::Logging,
            held: AuthorityId::FlowReservation,
        })
    );
    drop(flow_reservation);

    let manager = AuthorityScope::<tags::ManagerTransaction>::enter(AuthorityInstance::singleton(
        AuthorityId::ManagerTransaction,
    ))
    .expect("manager transaction authority");
    assert_eq!(
        AuditedOperationScope::enter(OperationId::Logging).map(drop),
        Err(super::AuthorityError::OperationConflict {
            operation: OperationId::Logging,
            held: AuthorityId::ManagerTransaction,
        })
    );
    drop(manager);
    assert!(audit::failed());
}

#[test]
fn logging_macro_scope_ends_before_flow_authority_acquisition() {
    crate::log_debug!(true, "authority logging scope lifetime regression probe");
    let flow_read = AuthorityScope::<tags::FlowRead>::enter(AuthorityInstance {
        id: AuthorityId::FlowRead,
        flow: 74,
        direction: 0,
        kind: 0,
        session: 0,
    })
    .expect("logging operation must end before the next flow authority");
    drop(flow_read);
}

#[test]
fn packet_operation_requires_socket_io_authority() {
    assert_eq!(
        hidden_helper_a(),
        Err(super::AuthorityError::MissingOperationAuthority {
            operation: OperationId::SocketSend,
            required: AuthorityId::SocketIo,
        })
    );
}

#[test]
fn condition_wait_releases_and_reacquires_audited_authority() {
    let mutex = AuthorityMutex::<tags::WaitCoordination, _>::new(
        (),
        AuthorityInstance::singleton(AuthorityId::WaitCoordination),
    );
    let waits = wait_count_for_test(super::WaitId::FifoReservation);
    let condvar = AuthorityCondvar::<tags::WaitCoordination>::new(super::WaitId::FifoReservation);
    let guard = mutex.lock().expect("coordination guard");
    let (guard, timed_out) = condvar
        .wait_until(guard, Instant::now() + Duration::from_millis(1))
        .expect("bounded audited wait");
    assert!(timed_out);
    drop(guard);
    assert_eq!(
        wait_count_for_test(super::WaitId::FifoReservation),
        waits + 1
    );
}

#[test]
fn condition_wait_rechecks_after_a_spurious_notification() {
    let mutex = std::sync::Arc::new(AuthorityMutex::<tags::WaitCoordination, _>::new(
        false,
        AuthorityInstance::singleton(AuthorityId::WaitCoordination),
    ));
    let condvar = std::sync::Arc::new(AuthorityCondvar::<tags::WaitCoordination>::new(
        super::WaitId::FifoReservation,
    ));
    std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let waiter_mutex = std::sync::Arc::clone(&mutex);
        let waiter_condvar = std::sync::Arc::clone(&condvar);
        let waiter = scope.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut guard = waiter_mutex.lock().expect("wait predicate authority");
            let mut wake_count = 0_u8;
            ready_tx.send(()).expect("announce predicate wait");
            while !*guard {
                let waited = waiter_condvar
                    .wait_until(guard, deadline)
                    .expect("reacquire after notification");
                guard = waited.0;
                wake_count = wake_count.checked_add(1).expect("bounded wake count");
                assert!(!waited.1, "predicate was not allowed to reach its deadline");
            }
            wake_count
        });
        ready_rx.recv().expect("waiter reached predicate loop");
        condvar.notify_all();
        {
            let mut guard = mutex.lock().expect("publish wait predicate");
            *guard = true;
        }
        condvar.notify_all();
        assert!(waiter.join().expect("join predicate waiter") >= 1);
    });
}

#[test]
fn implicit_allocator_scope_rejects_an_authoritative_guard() {
    let mutex = AuthorityMutex::<tags::WaitCoordination, _>::new(
        (),
        AuthorityInstance::singleton(AuthorityId::WaitCoordination),
    );
    let _guard = mutex.lock().expect("coordination guard");
    assert!(AuditedOperationScope::enter(OperationId::Allocator).is_err());
}

#[test]
fn actual_allocator_boundary_observes_held_authority() {
    std::thread::spawn(|| {
        let before = allocation_violation_count_for_test();
        let mutex = AuthorityMutex::<tags::WaitCoordination, _>::new(
            (),
            AuthorityInstance::singleton(AuthorityId::WaitCoordination),
        );
        let _guard = mutex.lock().expect("coordination guard");
        let allocated = Box::new(std::hint::black_box(7_u64));
        std::hint::black_box(&allocated);
        assert!(audit::failed());
        assert_eq!(allocation_violation_count_for_test(), before + 1);
    })
    .join()
    .expect("allocator audit thread");
}

#[test]
fn operation_scopes_are_counted_at_the_transitive_boundary() {
    let before = operation_count_for_test(OperationId::SocketSend);
    let socket_io = socket_io_scope();
    hidden_helper_a().expect("socket operation with I/O authority");
    drop(socket_io);
    assert_eq!(
        operation_count_for_test(OperationId::SocketSend),
        before + 1
    );
}

#[test]
fn wake_socket_operations_do_not_claim_packet_io_authority() {
    let send_before = operation_count_for_test(OperationId::WakeSocketSend);
    let receive_before = operation_count_for_test(OperationId::WakeSocketReceive);
    drop(
        AuditedOperationScope::enter(OperationId::WakeSocketSend)
            .expect("wake send is not packet I/O"),
    );
    drop(
        AuditedOperationScope::enter(OperationId::WakeSocketReceive)
            .expect("wake receive is not packet I/O"),
    );
    assert_eq!(
        operation_count_for_test(OperationId::WakeSocketSend),
        send_before + 1
    );
    assert_eq!(
        operation_count_for_test(OperationId::WakeSocketReceive),
        receive_before + 1
    );
}

#[test]
fn audited_operation_scopes_require_lifo_release() {
    std::thread::spawn(|| {
        let mut outer = std::mem::ManuallyDrop::new(
            AuditedOperationScope::enter(OperationId::Formatting).expect("outer operation"),
        );
        let inner =
            AuditedOperationScope::enter(OperationId::JsonSerialization).expect("inner operation");
        // SAFETY: this deliberately violates the audited LIFO protocol in an
        // isolated test thread. ManuallyDrop prevents a second outer drop.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut outer);
        }
        assert!(
            audit::failed(),
            "out-of-order operation release must fail audit"
        );
        drop(inner);
    })
    .join()
    .expect("join operation-order audit thread");
}

#[test]
fn out_of_order_authority_release_does_not_leave_a_ghost_owner() {
    std::thread::spawn(|| {
        let flow_instance = AuthorityInstance {
            id: AuthorityId::FlowRead,
            flow: 93,
            direction: 0,
            kind: 0,
            session: 0,
        };
        let mut flow = std::mem::ManuallyDrop::new(
            AuthorityScope::<tags::FlowRead>::enter(flow_instance).expect("flow authority"),
        );
        let socket = AuthorityScope::<tags::SocketIo>::enter(AuthorityInstance {
            id: AuthorityId::SocketIo,
            flow: 93,
            direction: 0,
            kind: 0,
            session: 0,
        })
        .expect("socket authority");
        // SAFETY: this intentionally exercises the audit-only non-LIFO release
        // path. ManuallyDrop prevents a second release of the flow authority.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut flow);
        }
        assert!(
            audit::failed(),
            "the release-order violation must be retained"
        );
        drop(socket);

        let manager = AuthorityScope::<tags::ManagerTransaction>::enter(
            AuthorityInstance::singleton(AuthorityId::ManagerTransaction),
        )
        .expect("a physically released flow authority must not remain as a ghost owner");
        drop(manager);
    })
    .join()
    .expect("join authority release audit thread");
}

#[test]
fn wait_contract_rejects_a_missing_retained_authority() {
    let mutex = AuthorityMutex::<tags::WaitCoordination, _>::new(
        (),
        AuthorityInstance {
            id: AuthorityId::WaitCoordination,
            flow: 91,
            direction: 0,
            kind: 0,
            session: 0,
        },
    );
    let condvar = AuthorityCondvar::<tags::WaitCoordination>::new(super::WaitId::FlowReadersDrain);
    assert_eq!(
        condvar
            .wait_until(
                mutex.lock().expect("coordination guard"),
                Instant::now() + Duration::from_millis(1),
            )
            .map(drop),
        Err(super::AuthorityError::MissingRetainedWaitAuthority {
            wait: super::WaitId::FlowReadersDrain,
            required: AuthorityId::FlowWrite,
        })
    );
}

#[test]
fn canonical_send_order_accepts_flow_socket_protocol_and_rejects_inversion() {
    let flow = AuthorityScope::<tags::FlowRead>::enter(AuthorityInstance {
        id: AuthorityId::FlowRead,
        flow: 7,
        direction: 0,
        kind: 0,
        session: 0,
    })
    .expect("flow authority");
    let socket = AuthorityScope::<tags::SocketIo>::enter(AuthorityInstance {
        id: AuthorityId::SocketIo,
        flow: 7,
        direction: 0,
        kind: 0,
        session: 0,
    })
    .expect("socket authority after flow");
    let protocol = AuthorityScope::<tags::ProtocolTransmit>::enter(AuthorityInstance {
        id: AuthorityId::ProtocolTransmit,
        flow: 7,
        direction: 0,
        kind: 0,
        session: 11,
    })
    .expect("protocol authority after socket");
    drop(protocol);
    drop(socket);
    drop(flow);

    let protocol = AuthorityScope::<tags::ProtocolTransmit>::enter(AuthorityInstance {
        id: AuthorityId::ProtocolTransmit,
        flow: 7,
        direction: 0,
        kind: 0,
        session: 11,
    })
    .expect("standalone protocol authority");
    assert!(
        AuthorityScope::<tags::SocketIo>::enter(AuthorityInstance {
            id: AuthorityId::SocketIo,
            flow: 7,
            direction: 0,
            kind: 0,
            session: 0,
        })
        .is_err()
    );
    drop(protocol);
}

#[test]
fn negative_smoke_reversed_send_order_is_rejected_by_authority_graph() {
    let protocol_instance = AuthorityInstance {
        id: AuthorityId::ProtocolTransmit,
        flow: 71,
        direction: 0,
        kind: 0,
        session: 19,
    };
    let protocol = AuthorityScope::<tags::ProtocolTransmit>::enter(protocol_instance)
        .expect("standalone protocol authority");
    let socket_instance = AuthorityInstance {
        id: AuthorityId::SocketIo,
        flow: 71,
        direction: 0,
        kind: 0,
        session: 0,
    };
    assert!(matches!(
        AuthorityScope::<tags::SocketIo>::enter(socket_instance),
        Err(super::AuthorityError::AcquisitionConflict { held, requested, .. })
            if held == protocol_instance && requested == socket_instance
    ));
    assert!(
        audit::failed(),
        "reversed socket-after-protocol acquisition must trip the audit failure latch"
    );
    drop(protocol);
}

#[test]
fn one_thread_cannot_cohold_two_directional_protocol_instances() {
    let first = AuthorityScope::<tags::ProtocolTransmit>::enter(AuthorityInstance {
        id: AuthorityId::ProtocolTransmit,
        flow: 9,
        direction: 0,
        kind: 0,
        session: 3,
    })
    .expect("first protocol instance");
    assert!(
        AuthorityScope::<tags::ProtocolTransmit>::enter(AuthorityInstance {
            id: AuthorityId::ProtocolTransmit,
            flow: 9,
            direction: 1,
            kind: 0,
            session: 4,
        })
        .is_err()
    );
    drop(first);
}

#[test]
fn unwind_releases_the_exact_audit_instance_without_panicking() {
    std::thread::spawn(|| {
        let instance = AuthorityInstance {
            id: AuthorityId::ProtocolTransmit,
            flow: 12,
            direction: 0,
            kind: 0,
            session: 6,
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _scope = AuthorityScope::<tags::ProtocolTransmit>::enter(instance)
                .expect("protocol authority");
            panic!("exercise audited unwind cleanup");
        }));
        assert!(outcome.is_err());
        let scope = AuthorityScope::<tags::ProtocolTransmit>::enter(instance)
            .expect("audit instance must be available after unwind");
        drop(scope);
    })
    .join()
    .expect("audit unwind thread");
}

#[test]
fn every_registered_worker_seals_an_exact_directional_record() {
    let registry = Arc::new(WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = WorkerAuditIdentity {
        worker: 4,
        direction: AuditDirection::UpstreamToClient,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);
    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        audit::record_pipeline_stage(false, 2);
        audit::record_pipeline_stage(false, 6);
        audit::record_pipeline_stage(false, 7);
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");
    let records = registry.records().expect("terminal worker records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].identity, identity);
    assert_eq!(records[0].receive_stage_count(), 1);
    assert_eq!(records[0].send_stage_count(), 1);
    assert_eq!(records[0].completed_packet_count(), 1);
    assert_eq!(records[0].forbidden_authority_acquisition_count(), 0);
    assert_eq!(records[0].forbidden_shared_rmw_count(), 0);
}

fn validate_worker_records(registry: &WorkerAuditRegistry) -> Result<(), &'static str> {
    registry
        .records()?
        .iter()
        .try_for_each(|record| record.validate())
}

#[test]
fn non_main_worker_allocation_under_packet_authority_fails_aggregation() {
    let registry = Arc::new(WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = WorkerAuditIdentity {
        worker: 2,
        direction: AuditDirection::ClientToUpstream,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);
    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        let authority = AuthorityScope::<tags::FlowRead>::enter(AuthorityInstance {
            id: AuthorityId::FlowRead,
            flow: 2,
            direction: 0,
            kind: 0,
            session: 0,
        })
        .expect("flow read authority");
        let allocated = Vec::<u8>::with_capacity(16);
        drop(allocated);
        drop(authority);
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");
    assert_eq!(
        validate_worker_records(&registry),
        Err("worker audit record contains an authority violation")
    );
}

#[test]
fn non_main_worker_rejects_uncataloged_atomic_ordering() {
    let registry = Arc::new(WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = WorkerAuditIdentity {
        worker: 5,
        direction: AuditDirection::UpstreamToClient,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);
    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        let counter = super::AuthorityAtomic::<tags::DiagnosticCounter, AtomicU64>::new_u64(
            0,
            super::AtomicProtocolId::DiagnosticCounter,
        );
        let result = counter.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
        assert_eq!(result, Ok(0));
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");
    assert_eq!(
        validate_worker_records(&registry),
        Err("worker audit record contains an authority violation")
    );
}

#[test]
fn non_main_worker_rejects_atomic_protocol_from_another_authority() {
    let registry = Arc::new(WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = WorkerAuditIdentity {
        worker: 7,
        direction: AuditDirection::ClientToUpstream,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);
    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        let counter = super::AuthorityAtomic::<tags::DiagnosticCounter, AtomicU64>::new_u64(
            0,
            super::AtomicProtocolId::ShutdownPublication,
        );
        assert_eq!(counter.load(Ordering::Acquire), 0);
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");
    assert_eq!(
        validate_worker_records(&registry),
        Err("worker audit record contains an authority violation")
    );
}

#[test]
fn non_main_worker_payload_copy_under_packet_authority_fails_aggregation() {
    let registry = Arc::new(WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = WorkerAuditIdentity {
        worker: 6,
        direction: AuditDirection::ClientToUpstream,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);
    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        let authority = AuthorityScope::<tags::FlowRead>::enter(AuthorityInstance {
            id: AuthorityId::FlowRead,
            flow: 6,
            direction: 0,
            kind: 0,
            session: 0,
        })
        .expect("flow read authority");
        audit::record_payload_copy();
        drop(authority);
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");
    assert_eq!(
        validate_worker_records(&registry),
        Err("worker audit record contains an authority violation")
    );
}

#[test]
fn non_main_worker_refcount_upgrade_under_packet_authority_fails_exactly() {
    let registry = Arc::new(WorkerAuditRegistry::new(1).expect("worker audit registry"));
    let identity = WorkerAuditIdentity {
        worker: 7,
        direction: AuditDirection::UpstreamToClient,
    };
    registry.register(0, identity).expect("register worker");
    let worker_registry = Arc::clone(&registry);
    std::thread::spawn(move || {
        worker_registry.begin(0, identity).expect("begin worker");
        let authority = AuthorityScope::<tags::FlowRead>::enter(AuthorityInstance {
            id: AuthorityId::FlowRead,
            flow: 7,
            direction: 1,
            kind: 0,
            session: 0,
        })
        .expect("flow read authority");
        assert_eq!(
            AuditedOperationScope::enter(OperationId::RefcountUpgrade).map(drop),
            Err(super::AuthorityError::OperationConflict {
                operation: OperationId::RefcountUpgrade,
                held: AuthorityId::FlowRead,
            })
        );
        drop(authority);
        worker_registry.seal(0).expect("seal worker");
    })
    .join()
    .expect("worker audit thread");
    assert_eq!(
        validate_worker_records(&registry),
        Err("worker audit record contains an authority violation")
    );
}
