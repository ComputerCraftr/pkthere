use super::{
    AssociationOperation, AssociationStale, AssociationState, IoKind, ManagedSocket,
    ManagedSocketError, SockAddr, Socket, SocketIoLane, TOPOLOGY_IO_DRAIN_TIMEOUT,
    WorkerDescriptorCache, peer_absent_error,
};
use pkthere_socket_policy::PeerVerification;
use pkthere_socket_policy::SocketRole;
use socket2::{Domain, Protocol, Type};
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Barrier;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

#[test]
fn connect_success_verification_accepts_missing_peer_addr_evidence() {
    let backend = Arc::new(FakeBackend::default());
    let socket =
        fake_socket_with_verification(Arc::clone(&backend), PeerVerification::ConnectSuccess);
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    backend.state.lock().expect("fake state").report_peer = false;

    socket.connect_unconnected(peer).expect("opaque connect");
    assert_eq!(
        socket.association(),
        AssociationState::Connected { peer, epoch: 1 }
    );
}

#[test]
fn network_address_verification_accepts_raw_peer_with_zero_kernel_id() {
    let backend = Arc::new(FakeBackend::default());
    let requested = SocketAddr::from((Ipv4Addr::LOCALHOST, 4141));
    let socket = fake_socket_with_verification(
        Arc::clone(&backend),
        PeerVerification::RequirePeerNetworkAddress,
    );
    backend
        .state
        .lock()
        .expect("fake state")
        .reported_peer_override = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));

    socket
        .connect_unconnected(requested)
        .expect("RAW peer network address");
    assert_eq!(
        socket.association(),
        AssociationState::Connected {
            peer: requested,
            epoch: 1
        }
    );
}

#[test]
fn network_address_verification_rejects_a_different_kernel_peer_ip() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket_with_verification(
        Arc::clone(&backend),
        PeerVerification::RequirePeerNetworkAddress,
    );
    backend
        .state
        .lock()
        .expect("fake state")
        .reported_peer_override = Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));

    assert!(matches!(
        socket.connect_unconnected(SocketAddr::from((Ipv4Addr::LOCALHOST, 4141))),
        Err(ManagedSocketError::Syscall {
            operation: AssociationOperation::Connect,
            ..
        })
    ));
}

use super::test_support::{
    FakeBackend, FakeState, ProductionIoTestExt, fake_socket, fake_socket_with_verification,
    unconfigured_fake_socket,
};

#[test]
fn topology_reservation_batch_parks_ranked_instances_in_lifo_order() {
    let first = unconfigured_fake_socket(Arc::new(FakeBackend::default()));
    let second = unconfigured_fake_socket(Arc::new(FakeBackend::default()));
    first
        .configure_worker_io_lanes(1)
        .expect("configure first topology lanes");
    second
        .configure_worker_io_lanes(1)
        .expect("configure second topology lanes");
    first
        .bind_authority_identity(SocketRole::Listener, 0, 1, false)
        .expect("bind first topology identity");
    second
        .bind_authority_identity(SocketRole::Listener, 1, 1, false)
        .expect("bind second topology identity");
    let mut reservations = vec![
        Some(
            first
                .reserve_topology(AssociationOperation::PublishMetadata)
                .expect("reserve first topology"),
        ),
        Some(
            second
                .reserve_topology(AssociationOperation::PublishMetadata)
                .expect("reserve second topology"),
        ),
    ];

    super::park_topology_reservation_batch(&mut reservations)
        .expect("park complete topology batch");
    assert!(!crate::authority::is_held_for_test(
        crate::authority::AuthorityId::SocketTopology
    ));
    for reservation in reservations.into_iter().rev().flatten() {
        reservation.rollback().expect("rollback parked topology");
    }
}

#[test]
fn socket_authority_identity_rejects_rebinding_to_another_slot() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    assert!(matches!(
        socket.bind_authority_identity(SocketRole::Listener, 1, 1, false),
        Err(ManagedSocketError::AuthorityIdentityConflict {
            expected_flow: 2,
            observed_flow: 1,
            ..
        })
    ));
}

#[test]
fn unconnected_peer_inspection_accepts_platform_absence_errors() {
    for kind in [
        io::ErrorKind::NotConnected,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::AddrNotAvailable,
    ] {
        assert!(
            peer_absent_error(&io::Error::from(kind)),
            "{kind:?} must represent an absent kernel peer association"
        );
    }
}

#[cfg(windows)]
#[test]
fn windows_unconnected_peer_inspection_accepts_winsock_absence_codes() {
    use windows_sys::Win32::Networking::WinSock::{WSAEINVAL, WSAENOTCONN};

    for code in [WSAEINVAL, WSAENOTCONN] {
        assert!(
            peer_absent_error(&io::Error::from_raw_os_error(code)),
            "Winsock error {code} must represent an absent kernel peer association"
        );
    }
}

#[test]
fn connect_disconnect_and_reconnect_have_authoritative_ordering() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2002));

    socket.connect_unconnected(first).expect("connect");
    assert_eq!(
        socket.association(),
        AssociationState::Connected {
            peer: first,
            epoch: 1
        }
    );
    socket.reconnect_connected(second).expect("reconnect");
    assert_eq!(
        socket.association(),
        AssociationState::Connected {
            peer: second,
            epoch: 2
        }
    );
    socket.disconnect_connected().expect("disconnect");
    assert_eq!(
        socket.association(),
        AssociationState::Unconnected { epoch: 3 }
    );
    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "disconnect", "connect", "disconnect"]
    );
}

#[test]
fn socket_backend_syscalls_do_not_hold_the_flow_implementation_mutex() {
    let flow_state = Arc::new(crate::flow_state::FlowRuntimeState::new());
    let backend = Arc::new(FakeBackend {
        state: Mutex::new(FakeState::default()),
        flow_state: Some(Arc::clone(&flow_state)),
    });
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 2112));

    socket.connect_unconnected(peer).expect("connect");
    socket
        .send_packet(&[IoSlice::new(b"connected")], &SockAddr::from(peer))
        .expect("connected send");
    socket.disconnect_connected().expect("disconnect");
    socket
        .send_packet(&[IoSlice::new(b"unconnected")], &SockAddr::from(peer))
        .expect("unconnected send");

    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "send", "disconnect", "send_to"]
    );
}

#[test]
fn stable_worker_io_refreshes_the_unique_cache_only_once_per_generation() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 2116));
    let destination = SockAddr::from(peer);
    let mut descriptor_cache = WorkerDescriptorCache::for_worker(0);
    descriptor_cache
        .reconcile(&socket)
        .expect("pre-I/O descriptor-cache reconciliation");

    socket
        .acquire_send_lease(&mut descriptor_cache)
        .and_then(|lease| lease.send_packet(&[IoSlice::new(b"first")], &destination))
        .expect("first cached send");
    assert_eq!(
        socket.descriptor_reload_count(SocketIoLane::Worker(0)),
        1,
        "pre-I/O reconciliation must populate the uniquely owned cache"
    );
    socket
        .acquire_send_lease(&mut descriptor_cache)
        .and_then(|lease| lease.send_packet(&[IoSlice::new(b"second")], &destination))
        .expect("second cached send");
    assert_eq!(
        socket.descriptor_reload_count(SocketIoLane::Worker(0)),
        1,
        "stable worker-lane reuse must never upgrade or clone the descriptor"
    );
}

#[test]
fn unreconciled_worker_cache_cannot_publish_a_send_lane_or_reach_the_backend() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let mut cache = WorkerDescriptorCache::for_worker(0);

    let error = match socket.acquire_send_lease(&mut cache) {
        Ok(_) => panic!("an unreconciled cache yielded socket authority"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("must be reconciled before socket I/O"),
        "unexpected unreconciled-cache error: {error}"
    );
    assert!(
        !socket.io_lane_active_for_test(SocketIoLane::Worker(0)),
        "failed cache preparation must release its production I/O lane"
    );
    assert!(
        backend.state.lock().expect("fake state").calls.is_empty(),
        "an unreconciled cache must fail before any socket backend operation"
    );
}

#[test]
fn descriptor_cache_lane_rejects_a_second_strong_owner() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let mut first = WorkerDescriptorCache::for_worker(0);
    let mut duplicate = WorkerDescriptorCache::for_worker(0);

    first
        .reconcile(&socket)
        .expect("register first descriptor-cache owner");
    let error = duplicate
        .reconcile(&socket)
        .expect_err("duplicate descriptor-cache owner must be rejected");
    assert!(
        error
            .to_string()
            .contains("already has a distinct registered owner")
    );

    drop(first);
    duplicate
        .reconcile(&socket)
        .expect("released descriptor-cache lane can be reclaimed");
}

#[test]
fn descriptor_retirement_waits_for_the_unique_worker_cache_acknowledgement() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2117)));
    let mut descriptor_cache = WorkerDescriptorCache::for_worker(0);
    descriptor_cache
        .reconcile(&socket)
        .expect("pre-I/O descriptor-cache reconciliation");
    socket
        .acquire_send_lease(&mut descriptor_cache)
        .and_then(|lease| lease.send_packet(&[IoSlice::new(b"register")], &destination))
        .expect("register uniquely owned descriptor cache");

    let (release_cache_tx, release_cache_rx) = mpsc::channel();
    let cache_socket = socket.clone();
    let cache_worker = thread::spawn(move || {
        release_cache_rx
            .recv()
            .expect("release descriptor-cache acknowledgement");
        descriptor_cache
            .reconcile(&cache_socket)
            .expect_err("acknowledging revocation must not reconcile closed-gate I/O");
        descriptor_cache
            .reconcile(&cache_socket)
            .expect_err("closed topology must remain unavailable after acknowledgement");
        assert!(
            !descriptor_cache.core.has_descriptor(),
            "a worker loop after acknowledgement must not reacquire the retiring descriptor"
        );
    });

    let transition_socket = socket.clone();
    let (transition_tx, transition_rx) = mpsc::channel();
    let transition = thread::spawn(move || {
        let result = transition_socket
            .reserve_replacement()
            .and_then(super::TopologyReservation::into_retired_for_replacement)
            .and_then(super::RetiredTopologyReservation::commit);
        transition_tx
            .send(result)
            .expect("publish descriptor retirement");
    });

    let deadline = std::time::Instant::now() + TOPOLOGY_IO_DRAIN_TIMEOUT;
    while socket.descriptor_revocation_requested_for_test(SocketIoLane::Worker(0)) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "descriptor retirement did not request worker-cache revocation"
        );
        thread::yield_now();
    }
    assert!(
        matches!(transition_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "descriptor owner retired before the worker cache acknowledged revocation"
    );

    release_cache_tx
        .send(())
        .expect("allow descriptor-cache acknowledgement");
    cache_worker.join().expect("join descriptor-cache worker");
    transition_rx
        .recv_timeout(TOPOLOGY_IO_DRAIN_TIMEOUT)
        .expect("descriptor retirement completed after acknowledgement")
        .expect("commit retired topology");
    transition.join().expect("join descriptor retirement");
}

#[test]
fn staged_connect_rollback_observes_disconnect_and_retires_on_bind_change() {
    let backend = Arc::new(FakeBackend::default());
    backend.state.lock().expect("fake state").local =
        SocketAddr::from((Ipv4Addr::LOCALHOST, 31_001));
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 2113));
    let mut reservation = socket
        .reserve_replacement()
        .expect("reserve staged connection");
    reservation
        .connect_unconnected(peer)
        .expect("stage connection");
    {
        let mut state = backend.state.lock().expect("fake state");
        state.fail_disconnect = true;
        state.disconnect_mutates_on_error = true;
        state.disconnect_local_after = Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    }

    let error = reservation
        .rollback()
        .expect_err("irreversible rollback disconnect must fail closed");

    assert!(matches!(
        error,
        ManagedSocketError::DisconnectChangedUnexpectedly { .. }
    ));
    assert!(matches!(
        socket.association(),
        AssociationState::Retired { .. }
    ));
    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "disconnect"]
    );
}

#[test]
fn staged_reconnect_rollback_after_disconnect_is_fail_closed() {
    let backend = Arc::new(FakeBackend::default());
    backend.state.lock().expect("fake state").local =
        SocketAddr::from((Ipv4Addr::LOCALHOST, 31_002));
    let socket = fake_socket(Arc::clone(&backend));
    let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 2114));
    let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2115));
    socket
        .connect_unconnected(first)
        .expect("connect first peer");
    let mut reservation = socket
        .reserve_replacement()
        .expect("reserve staged reconnect");
    reservation
        .reconnect_connected(second)
        .expect("stage reconnect");
    let error = reservation
        .rollback()
        .expect_err("post-disconnect reconnect rollback must fail closed");

    assert!(matches!(
        error,
        ManagedSocketError::TopologyReservationLost {
            operation: AssociationOperation::Replace,
        }
    ));
    assert!(matches!(
        socket.association(),
        AssociationState::Retired { .. }
    ));
    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "disconnect", "connect"],
        "rollback after the irreversible point must retire without a second disconnect"
    );
}

#[test]
fn clones_share_one_association_state() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(backend);
    let clone = socket.clone();
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    socket.connect_unconnected(peer).expect("connect");
    assert_eq!(clone.association(), socket.association());
}

#[test]
fn retirement_advances_epoch_and_rejects_every_stale_clone() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(backend);
    let stale = socket.clone();
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002)));

    socket.retire().expect("retire managed socket");

    assert_eq!(socket.association(), AssociationState::Retired { epoch: 1 });
    let send_error = stale
        .send_packet(&[IoSlice::new(b"stale")], &destination)
        .expect_err("retired stale clone cannot send");
    assert_eq!(send_error.kind(), io::ErrorKind::BrokenPipe);
    assert!(matches!(
        stale.connect_unconnected(
            destination
                .as_socket()
                .expect("test destination is an internet address")
        ),
        Err(ManagedSocketError::Retired {
            operation: AssociationOperation::Connect,
            epoch: 1,
        })
    ));
}

#[test]
fn replacement_reservation_closes_io_and_rollback_advances_epoch() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002)));
    let initial_epoch = socket.topology_epoch();
    let reservation = socket
        .reserve_replacement()
        .expect("reserve replacement topology");

    let error = socket
        .send_packet(&[IoSlice::new(b"closed")], &destination)
        .expect_err("closed topology must reject a new send");
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    reservation.rollback().expect("rollback replacement");
    assert_eq!(socket.topology_epoch(), initial_epoch + 1);
    assert!(matches!(
        socket.association(),
        AssociationState::Unconnected {
            epoch
        } if epoch == initial_epoch + 1
    ));
}

#[test]
fn replacement_reservation_commits_terminal_retirement() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let stale = socket.clone();
    socket
        .reserve_replacement()
        .expect("reserve replacement topology")
        .into_retired_for_replacement()
        .expect("retire descriptor")
        .commit()
        .expect("commit retirement");

    assert!(matches!(
        stale.association(),
        AssociationState::Retired { .. }
    ));
    assert!(matches!(
        stale.reserve_replacement(),
        Err(ManagedSocketError::Retired {
            operation: AssociationOperation::Replace,
            ..
        })
    ));
}

#[test]
fn pre_retired_replacement_commits_without_a_second_descriptor_revocation() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let stale = socket.clone();
    let retired = socket
        .reserve_replacement()
        .expect("reserve replacement topology")
        .into_retired_for_replacement()
        .expect("retire descriptor exactly once");

    retired
        .commit()
        .expect("publish the already-retired topology");

    assert!(matches!(
        stale.association(),
        AssociationState::Retired { .. }
    ));
}

#[test]
fn replacement_failure_after_retirement_never_republishes_old_topology() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let stale = socket.clone();
    let reservation = socket
        .reserve_replacement()
        .expect("reserve replacement topology");
    reservation
        .into_retired_for_replacement()
        .expect("retire descriptor before replacement bind")
        .replacement_bound()
        .expect("record replacement bind phase")
        .commit()
        .expect("publish retired topology after replacement failure");
    assert!(matches!(
        stale.association(),
        AssociationState::Retired { .. }
    ));
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002)));
    assert_eq!(
        stale
            .send_packet(&[IoSlice::new(b"retired")], &destination)
            .expect_err("retired topology cannot be republished")
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn escaped_descriptor_reference_fails_before_owner_retirement() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let temporary_descriptor = socket
        .transition_descriptor(AssociationOperation::Replace)
        .expect("hold a temporary descriptor reference");
    let reservation = socket
        .reserve_replacement()
        .expect("reserve replacement topology");

    let error = reservation
        .into_retired_for_replacement()
        .expect_err("escaped strong descriptor reference must fail closed");

    assert!(matches!(
        error,
        ManagedSocketError::DescriptorOwnershipEscaped { strong_count: 2 }
    ));
    drop(temporary_descriptor);
    assert!(!matches!(
        socket.association(),
        AssociationState::Retired { .. }
    ));
}

#[test]
fn stable_gate_with_missing_descriptor_owner_is_a_fatal_invariant() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let descriptor = socket
        .inner
        .descriptor_owner
        .socket
        .lock()
        .expect("descriptor owner test lock")
        .take()
        .expect("stable descriptor owner");
    drop(descriptor);
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 20_002)));

    let error = socket
        .send_packet(&[IoSlice::new(b"missing-owner")], &destination)
        .expect_err("stable topology cannot lose its descriptor owner");

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ManagedSocketError>()),
        Some(ManagedSocketError::Retired { .. })
    ));
}

#[test]
fn topology_drain_timeout_poisons_socket_and_keeps_io_closed() {
    let socket = fake_socket(Arc::new(FakeBackend::default()));
    let initial_epoch = socket.topology_epoch();
    socket
        .inner
        .control_io_lane
        .active_epoch
        .store(1, Ordering::Release);
    let started = std::time::Instant::now();

    let error = socket
        .reserve_replacement()
        .expect_err("undrained I/O must fail the bounded reservation");

    assert!(matches!(
        error,
        ManagedSocketError::TopologyQuiescenceLost {
            operation: AssociationOperation::Replace,
            active_io: 1,
            epoch: 1,
        }
    ));
    assert!(started.elapsed() >= TOPOLOGY_IO_DRAIN_TIMEOUT);
    assert!(started.elapsed() < TOPOLOGY_IO_DRAIN_TIMEOUT + std::time::Duration::from_secs(1));
    assert!(socket.topology_poisoned_for_test());
    assert_eq!(socket.topology_epoch(), initial_epoch + 1);
    assert!(
        socket
            .acquire_io_lease(IoKind::Receive, SocketIoLane::Control, None)
            .is_err(),
        "quiescence failure must keep the data plane closed"
    );
    socket
        .inner
        .control_io_lane
        .active_epoch
        .store(0, Ordering::Release);
}

#[test]
fn occupied_io_lane_fails_before_a_syscall() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let lease = socket
        .acquire_io_lease(IoKind::Receive, SocketIoLane::Control, None)
        .expect("claim control I/O lane");
    let destination = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002)));

    let error = socket
        .send_packet(&[IoSlice::new(b"overflow")], &destination)
        .expect_err("an occupied lane must fail closed");

    drop(lease);
    assert!(
        error
            .to_string()
            .contains("active I/O lease count exhausted")
    );
    assert!(backend.state.lock().expect("fake state").calls.is_empty());
}

#[test]
fn failed_transition_poisons_socket_and_rejects_later_transitions() {
    let backend = Arc::new(FakeBackend::default());
    backend.state.lock().expect("fake state").fail_connect = true;
    let socket = fake_socket(backend);
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    assert!(matches!(
        socket.connect_unconnected(peer),
        Err(ManagedSocketError::Syscall { .. })
    ));
    assert!(matches!(
        socket.connect_unconnected(peer),
        Err(ManagedSocketError::Poisoned { .. })
    ));
}

#[test]
fn double_connect_returns_typed_error_before_a_second_syscall() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    socket.connect_unconnected(peer).expect("first connect");
    assert!(matches!(
        socket.connect_unconnected(peer),
        Err(ManagedSocketError::InvalidTransition {
            operation: AssociationOperation::Connect,
            ..
        })
    ));
    assert_eq!(backend.state.lock().expect("fake state").calls, ["connect"]);
}

#[test]
fn double_disconnect_returns_typed_error_before_a_second_syscall() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    socket.connect_unconnected(peer).expect("connect");
    socket.disconnect_connected().expect("first disconnect");
    assert!(matches!(
        socket.disconnect_connected(),
        Err(ManagedSocketError::InvalidTransition {
            operation: AssociationOperation::Disconnect,
            ..
        })
    ));
    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "disconnect"]
    );
}

#[test]
fn reconnect_failure_after_verified_disconnect_retires_the_descriptor() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    let second = SocketAddr::from((Ipv4Addr::LOCALHOST, 2002));
    socket.connect_unconnected(first).expect("connect");
    backend.state.lock().expect("fake state").fail_connect = true;

    assert!(matches!(
        socket.reconnect_connected(second),
        Err(ManagedSocketError::Syscall {
            operation: AssociationOperation::Reconnect,
            ..
        })
    ));
    assert_eq!(socket.association(), AssociationState::Retired { epoch: 2 });
    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "disconnect", "connect"]
    );
    assert!(matches!(
        socket.disconnect_connected(),
        Err(ManagedSocketError::Retired { .. })
    ));
}

#[test]
fn disconnect_noop_reopens_connected_state_at_a_fresh_epoch() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    socket.connect_unconnected(peer).expect("connect");
    backend.state.lock().expect("fake state").fail_disconnect = true;

    assert!(matches!(
        socket.disconnect_connected(),
        Err(ManagedSocketError::DisconnectUnchanged { .. })
    ));
    assert_eq!(
        socket.association(),
        AssociationState::Connected { peer, epoch: 2 }
    );
}

#[test]
fn disconnect_error_that_clears_peer_and_widens_bind_retires_socket() {
    let concrete = SocketAddr::from((Ipv4Addr::LOCALHOST, 31_001));
    let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 31_001));
    let backend = Arc::new(FakeBackend::default());
    {
        let mut state = backend.state.lock().expect("fake state");
        state.local = concrete;
        state.fail_disconnect = true;
        state.disconnect_mutates_on_error = true;
        state.disconnect_local_after = Some(wildcard);
    }
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 31_002));
    socket.connect_unconnected(peer).expect("connect");

    assert!(matches!(
        socket.disconnect_connected(),
        Err(ManagedSocketError::DisconnectChangedUnexpectedly {
            local,
            peer: None,
            ..
        }) if local == wildcard
    ));
    assert_eq!(socket.association(), AssociationState::Retired { epoch: 2 });
    assert!(matches!(
        socket.send_packet(&[IoSlice::new(b"stale")], &SockAddr::from(peer)),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe
    ));
}

#[test]
fn indeterminate_disconnect_postcondition_retires_socket() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 31_003));
    socket.connect_unconnected(peer).expect("connect");
    backend
        .state
        .lock()
        .expect("fake state")
        .fail_peer_inspection_after_disconnect = true;

    assert!(matches!(
        socket.disconnect_connected(),
        Err(ManagedSocketError::DisconnectIndeterminate { .. })
    ));
    assert_eq!(socket.association(), AssociationState::Retired { epoch: 2 });
}

#[test]
fn stale_logical_handles_do_not_retain_retired_bind() {
    for local in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        for _ in 0..256 {
            let domain = Domain::for_address(SocketAddr::new(local, 0));
            let raw =
                Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).expect("create bound socket");
            raw.bind(&SockAddr::from(SocketAddr::new(local, 0)))
                .expect("bind managed socket");
            let address = raw
                .local_addr()
                .expect("managed local address")
                .as_socket()
                .expect("INET managed address");
            let socket =
                ManagedSocket::from_unconnected(raw, PeerVerification::RequirePeerAddr, address)
                    .expect("adopt managed socket");
            let stale = socket.clone();

            socket
                .reserve_replacement()
                .expect("reserve retirement")
                .into_retired_for_replacement()
                .expect("retire descriptor")
                .commit()
                .expect("retire descriptor");

            let replacement = UdpSocket::bind(address).expect("rebind after retirement");
            assert_eq!(
                replacement.local_addr().expect("replacement address"),
                address
            );
            assert!(matches!(
                stale.send_packet(
                    &[IoSlice::new(b"retired")],
                    &SockAddr::from(SocketAddr::new(local, 9))
                ),
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe
            ));
        }
    }
}

#[test]
fn concurrent_connect_attempts_execute_one_syscall() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let barrier = Arc::new(Barrier::new(3));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    let threads = (0..2)
        .map(|_| {
            let socket = socket.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                socket.connect_unconnected(peer)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let outcomes = threads
        .into_iter()
        .map(|thread| thread.join().expect("join connect contender"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(ManagedSocketError::InvalidTransition {
                    operation: AssociationOperation::Connect,
                    ..
                })
            ))
            .count(),
        1
    );
    assert_eq!(backend.state.lock().expect("fake state").calls, ["connect"]);
}

#[test]
fn destination_required_returns_typed_stale_without_mutating_association() {
    let backend = Arc::new(FakeBackend::default());
    let socket = fake_socket(Arc::clone(&backend));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1001));
    socket.connect_unconnected(peer).expect("connect");
    backend
        .state
        .lock()
        .expect("fake state")
        .destination_required_on_send = true;

    let error = socket
        .send_packet(
            &[IoSlice::new(b"retry")],
            &SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 2002))),
        )
        .expect_err("socket wrapper must not mutate topology inline");

    assert_eq!(
        AssociationStale::from_io(&error).map(AssociationStale::expected_epoch),
        Some(1)
    );
    assert_eq!(
        socket.association(),
        AssociationState::Connected { peer, epoch: 1 }
    );
    assert_eq!(
        backend.state.lock().expect("fake state").calls,
        ["connect", "send"]
    );
}
