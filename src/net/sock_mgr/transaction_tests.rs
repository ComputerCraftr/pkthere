use super::tests::make_mgr_with_slot_and_worker_policy;
use super::tests::{
    establish_prepared_client_flow, listener_policy_connects_after_lock, make_mgr,
    make_mgr_with_slot, set_test_upstream_peer_ids,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::flow_state::FlowRuntimeState;
use crate::net::managed_socket::ReceiveBuffer;
use crate::net::managed_socket::test_support::ProductionIoTestExt;
use crate::net::managed_socket::{AssociationOperation, AssociationState};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::net::sock_mgr::ReceiverRole;
use crate::net::sock_mgr::{
    ClientFlowUpdate, ManagerError, RecoveryOutcome, SocketManager, StateVersion,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::worker_support::{ReceiveAuthority, SocketLeg};
use pkthere_socket_policy::{ReceiveSyscall, listener_worker_socket_policy};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Instant;

#[test]
fn concurrent_topology_checked_updates_publish_once_then_require_a_fresh_epoch() {
    let mgr = Arc::new(make_mgr());
    let initial = mgr.test_handle_snapshot().version;
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (source_id, reply_id) in [(41001, 42001), (41002, 42002)] {
        let mgr = Arc::clone(&mgr);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            let observed_epoch = mgr.test_handle_snapshot().upstream_sock.topology_epoch();
            barrier.wait();
            (
                source_id,
                reply_id,
                set_test_upstream_peer_ids(&mgr, observed_epoch, source_id, reply_id),
            )
        }));
    }
    barrier.wait();
    barrier.wait();
    let first = workers.remove(0).join().expect("first update thread");
    let second = workers.remove(0).join().expect("second update thread");

    let mut successful = None;
    let mut stale = None;
    for (source_id, reply_id, result) in [first, second] {
        match result {
            Ok(update) => successful = Some(update),
            Err(ManagerError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::WouldBlock =>
            {
                stale = Some((source_id, reply_id));
            }
            Err(error) => panic!("unexpected concurrent publication error: {error}"),
        }
    }
    let successful = successful.expect("one topology-checked update succeeds");
    let (source_id, reply_id) = stale.expect("one stale epoch is rejected");
    assert!(successful.handles.version > initial);

    let refreshed = mgr.test_handle_snapshot();
    let retry = set_test_upstream_peer_ids(
        &mgr,
        refreshed.upstream_sock.topology_epoch(),
        source_id,
        reply_id,
    )
    .expect("retry with refreshed topology epoch");
    assert!(retry.handles.version > successful.handles.version);
}

#[test]
fn stale_topology_epoch_rejects_peer_id_mutation_without_manager_publication() {
    let manager = make_mgr();
    let before = manager.test_handle_snapshot();
    let observed_epoch = before.upstream_sock.topology_epoch();
    let before_reply_id = before.upstream.upstream_remote_filter.id();

    before
        .upstream_sock
        .reserve_topology(AssociationOperation::PublishMetadata)
        .expect("reserve an intervening topology publication")
        .commit()
        .expect("advance topology epoch without changing manager metadata");

    let error = match set_test_upstream_peer_ids(&manager, observed_epoch, 41_001, 42_001) {
        Ok(_) => panic!("stale receive topology must not publish peer IDs"),
        Err(error) => error,
    };
    let ManagerError::Io { source, .. } = error else {
        panic!("stale topology must return a typed I/O retry");
    };
    assert_eq!(source.kind(), std::io::ErrorKind::WouldBlock);

    let after = manager.test_handle_snapshot();
    assert_eq!(after.version, before.version);
    assert_eq!(after.upstream.upstream_remote_filter.id(), before_reply_id);
    assert!(after.upstream_sock.topology_epoch() > observed_epoch);
}

#[test]
fn version_exhaustion_rejects_update_before_metadata_mutation() {
    let mgr = make_mgr().with_initial_version_for_test(StateVersion::MAX);
    let before = mgr.test_handle_snapshot();

    let error =
        match set_test_upstream_peer_ids(&mgr, before.upstream_sock.topology_epoch(), 51001, 52001)
        {
            Ok(_) => panic!("exhausted version must reject update"),
            Err(error) => error,
        };
    assert!(matches!(
        error,
        ManagerError::VersionExhausted {
            current: StateVersion::MAX
        }
    ));
    let after = mgr.test_handle_snapshot();
    assert_eq!(after.version, StateVersion::MAX);
    assert_eq!(
        after.upstream.upstream_remote_filter,
        before.upstream.upstream_remote_filter
    );
    assert_eq!(after.upstream.upstream_flow, before.upstream.upstream_flow);
}

#[test]
fn socket_topology_epoch_changes_without_manager_topology_publication() {
    let mgr = make_mgr();
    let handles = mgr.test_handle_snapshot();
    let topology_version = handles.version;
    let before_epoch = handles.client_sock.topology_epoch();

    handles
        .client_sock
        .reserve_topology(AssociationOperation::PublishMetadata)
        .expect("reserve socket topology")
        .commit()
        .expect("publish socket topology epoch");
    let after_epoch = handles.client_sock.topology_epoch();

    assert!(after_epoch > before_epoch);
    assert_eq!(mgr.test_handle_snapshot().version, topology_version);
    assert_eq!(mgr.test_handle_snapshot().version, topology_version);
}

#[test]
fn unconnected_udp_clear_replaces_descriptor_to_isolate_queued_datagrams() {
    let manager = make_mgr_with_slot_and_worker_policy(0, listener_worker_socket_policy(1, false));
    let flow_state = FlowRuntimeState::new();
    let client_socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind unconnected relock client");
    let client = client_socket
        .local_addr()
        .expect("read unconnected relock client address");
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let prepared = SocketManager::prepare_client_flow_group(
        &[&manager],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 0,
            client,
        },
    )
    .expect("prepare unconnected UDP flow");
    let established = {
        let mut transaction = flow_state.reserve_client_flow();
        establish_prepared_client_flow!(prepared, &mut transaction)
            .expect("establish unconnected UDP flow")
            .remove(0)
            .handles
    };
    assert!(!established.listener_connected());
    let bound = established.listener.listen_local_kernel_addr;
    client_socket
        .send_to(b"queued-before-unconnected-clear", bound)
        .expect("queue old-flow datagram");

    let cleared = {
        let mut transaction = flow_state.reserve_client_flow();
        SocketManager::clear_client_flow_group(&[&manager], &mut transaction)
            .expect("clear unconnected UDP flow by replacement")
    };
    assert_eq!(cleared.updates.len(), 1);
    let after = manager.test_handle_snapshot();
    assert_eq!(after.listener.listen_local_kernel_addr, bound);
    assert_eq!(
        after.listener.evidence_key.generation,
        established.listener.evidence_key.generation + 1
    );
    assert!(!after.listener_connected());
    assert_eq!(after.listener.flow, None);
    let mut stale_buffer = ReceiveBuffer::<1>::new();
    assert!(matches!(
        established
            .client_sock
            .receive(ReceiveSyscall::RecvFrom, &mut stale_buffer),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe
    ));
}

#[test]
fn shared_flow_connects_only_the_stable_lowest_slot_owner() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let connects_after_lock = listener_policy_connects_after_lock(&first);
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 53999));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let prepared = SocketManager::prepare_client_flow_group(
        &[&second, &first],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 1,
            client,
        },
    )
    .expect("prepare shared flow with one connected listener owner");
    let mut flow_transaction = flow_state.reserve_client_flow();
    let allocation_violations = [
        crate::authority::AuthorityId::FlowReservation,
        crate::authority::AuthorityId::FlowWrite,
        crate::authority::AuthorityId::ManagerTransaction,
        crate::authority::AuthorityId::ManagerState,
        crate::authority::AuthorityId::SocketTopology,
        crate::authority::AuthorityId::SocketAssociation,
    ]
    .map(crate::authority::allocation_violation_count_for_authority_for_test);

    let published = establish_prepared_client_flow!(prepared, &mut flow_transaction)
        .expect("establish shared flow with one connected listener owner");
    let allocation_violations_after = [
        crate::authority::AuthorityId::FlowReservation,
        crate::authority::AuthorityId::FlowWrite,
        crate::authority::AuthorityId::ManagerTransaction,
        crate::authority::AuthorityId::ManagerState,
        crate::authority::AuthorityId::SocketTopology,
        crate::authority::AuthorityId::SocketAssociation,
    ]
    .map(crate::authority::allocation_violation_count_for_authority_for_test);
    assert_eq!(
        allocation_violations_after, allocation_violations,
        "shared-flow publication may not allocate while transition authorities are held",
    );

    assert_eq!(published.len(), 2);
    let admission = flow_state.admission_snapshot(Instant::now());
    assert!(admission.locked);
    assert_eq!(admission.client_flow, Some(flow));
    let owner = first.test_handle_snapshot();
    assert_eq!(owner.listener_connected(), connects_after_lock);
    if connects_after_lock {
        assert!(matches!(
            owner.client_sock.association(),
            AssociationState::Connected { peer, .. } if peer == client
        ));
    } else {
        assert!(matches!(
            owner.client_sock.association(),
            AssociationState::Unconnected { .. }
        ));
    }
    assert!(!second.test_handle_snapshot().listener_connected());
    for manager in [&first, &second] {
        assert_eq!(manager.test_handle_snapshot().listener.flow, Some(flow));
    }
    assert!(flow_state.is_locked());
}

#[test]
fn shared_flow_rejects_a_missing_connected_listener_owner_before_transition() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54000));
    let prepared = SocketManager::prepare_client_flow_group(
        &[&first, &second],
        ClientFlowUpdate {
            flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 7,
            client,
        },
    );
    assert!(matches!(prepared, Err(ManagerError::Io { .. })));
    let flow_transaction = flow_state.reserve_client_flow();

    drop(flow_transaction);
    for (before, manager) in [(&first_before, &first), (&second_before, &second)] {
        let after = manager.test_handle_snapshot();
        assert_eq!(after.version, before.version);
        assert_eq!(after.listener.flow, None);
        assert!(!after.listener_connected());
    }
    assert!(!flow_state.is_locked());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn shared_connected_owner_clear_replaces_socket_on_the_same_bound_address() {
    let manager = make_mgr_with_slot_and_worker_policy(0, listener_worker_socket_policy(2, false));
    let mut receiver = manager
        .claim_receiver(ReceiverRole::Listener, 0)
        .expect("claim listener receiver");
    let flow_state = FlowRuntimeState::new();
    let client_socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind queue-isolation client");
    let client = client_socket
        .local_addr()
        .expect("read queue-isolation client address");
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let prepared = SocketManager::prepare_client_flow_group(
        &[&manager],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 0,
            client,
        },
    )
    .expect("prepare connected shared-flow owner");

    let established = {
        let mut transaction = flow_state.reserve_client_flow();
        establish_prepared_client_flow!(prepared, &mut transaction)
            .expect("establish connected shared-flow owner")
    };
    let connected = established
        .into_iter()
        .next()
        .expect("published connected owner")
        .handles;
    let bound_before = connected.listener.listen_local_kernel_addr;
    let evidence_before = connected.listener.evidence_key;
    let authority = ReceiveAuthority::capture(
        &connected,
        SocketLeg::ClientFacing,
        flow_state.flow_epoch(),
        receiver.generation(),
    );
    assert!(connected.listener_connected());
    client_socket
        .send_to(b"queued-before-clear", bound_before)
        .expect("queue pre-clear datagram without receiving it");

    let cleared = {
        let mut transaction = flow_state.reserve_client_flow();
        SocketManager::clear_client_flow_group(&[&manager], &mut transaction)
            .expect("replace connected shared-flow owner while clearing")
    };
    assert_eq!(cleared.updates.len(), 1);
    let after = manager.test_handle_snapshot();
    assert!(!after.listener_connected());
    assert_eq!(after.listener.listen_local_kernel_addr, bound_before);
    assert_eq!(
        after.listener.evidence_key.generation,
        evidence_before.generation + 1
    );
    assert_eq!(after.listener.flow, None);
    let mut stale_buffer = ReceiveBuffer::<1>::new();
    let stale_receive = connected
        .client_sock
        .receive(ReceiveSyscall::RecvFrom, &mut stale_buffer);
    let stale_error = match stale_receive {
        Ok(_) => panic!("retired listener descriptor remained receive-capable"),
        Err(error) => error,
    };
    assert_eq!(stale_error.kind(), std::io::ErrorKind::BrokenPipe);
    receiver
        .prepare_for_receive()
        .expect("claim replacement receiver and prepare its descriptor cache");
    assert_eq!(receiver.generation(), 2);
    assert!(
        !authority.matches(
            &after,
            SocketLeg::ClientFacing,
            flow_state.flow_epoch(),
            receiver.generation(),
        ),
        "listener replacement must invalidate pre-commit receive authority"
    );
}

#[test]
fn concurrent_group_lock_attempts_publish_once_without_reconnecting() {
    let managers = Arc::new(vec![
        Arc::new(make_mgr_with_slot(0)),
        Arc::new(make_mgr_with_slot(1)),
    ]);
    let flow_state = Arc::new(FlowRuntimeState::new());
    let barrier = Arc::new(Barrier::new(3));
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54001));
    let workers = (0..2)
        .map(|_| {
            let managers = Arc::clone(&managers);
            let flow_state = Arc::clone(&flow_state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
                let prepared = SocketManager::prepare_client_flow_group(
                    &manager_refs,
                    ClientFlowUpdate {
                        flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
                        listener_flow: SocketLegFlow::empty(),
                        admitting_listener_slot: 0,
                        client,
                    },
                )?;
                let mut transaction = flow_state.reserve_client_flow();
                establish_prepared_client_flow!(prepared, &mut transaction)
            })
        })
        .collect::<Vec<_>>();

    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("join lock contender"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert_eq!(
        managers[0].test_handle_snapshot().listener_connected(),
        listener_policy_connects_after_lock(&managers[0])
    );
    assert!(!managers[1].test_handle_snapshot().listener_connected());
    assert!(flow_state.is_locked());
}

#[test]
fn shared_flow_exhaustion_prevents_every_transition_and_publication() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1).with_initial_version_for_test(StateVersion::MAX);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54001));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let prepared = SocketManager::prepare_client_flow_group(
        &[&first, &second],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 0,
            client,
        },
    )
    .expect("prepare exhausted shared flow");
    let mut flow_transaction = flow_state.reserve_client_flow();

    let result = establish_prepared_client_flow!(prepared, &mut flow_transaction);

    assert!(matches!(
        result,
        Err(ManagerError::VersionExhausted {
            current: StateVersion::MAX
        })
    ));
    let first_after = first.test_handle_snapshot();
    let second_after = second.test_handle_snapshot();
    assert_eq!(first_after.version, first_before.version);
    assert_eq!(second_after.version, second_before.version);
    assert_eq!(first_after.listener.flow, None);
    assert_eq!(second_after.listener.flow, None);
    assert!(!first_after.listener_connected());
    assert!(!second_after.listener_connected());
    assert!(!flow_state.is_locked());
}

#[test]
fn shared_flow_gate_reservation_failure_at_every_index_rolls_back_all_prior_gates() {
    for failed_index in 0..3 {
        let managers = (0..3).map(make_mgr_with_slot).collect::<Vec<_>>();
        let before = managers
            .iter()
            .map(SocketManager::test_handle_snapshot)
            .collect::<Vec<_>>();
        let blocked_socket = managers[failed_index].test_handle_snapshot().client_sock;
        let (blocked_tx, blocked_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let blocker_thread = thread::spawn(move || {
            let blocker = blocked_socket
                .reserve_replacement()
                .expect("reserve the selected production topology gate");
            blocked_tx
                .send(())
                .expect("publish selected gate reservation");
            release_rx
                .recv()
                .expect("wait to release selected gate reservation");
            blocker
                .rollback()
                .expect("release the selected production topology gate");
        });
        blocked_rx
            .recv()
            .expect("wait for selected production topology gate");
        let flow_state = FlowRuntimeState::new();
        let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54_050 + failed_index as u16));
        let refs = managers.iter().collect::<Vec<_>>();
        let prepared = SocketManager::prepare_client_flow_group(
            &refs,
            ClientFlowUpdate {
                flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
                listener_flow: SocketLegFlow::empty(),
                admitting_listener_slot: 0,
                client,
            },
        )
        .expect("prepare shared flow with blocked topology");
        let mut transaction = flow_state.reserve_client_flow();

        let result = establish_prepared_client_flow!(prepared, &mut transaction);
        release_tx
            .send(())
            .expect("request selected gate reservation release");
        blocker_thread
            .join()
            .expect("join selected gate reservation owner");

        assert!(
            result.is_err(),
            "reservation index {failed_index} must fail"
        );
        assert!(!flow_state.is_locked());
        for (index, manager) in managers.iter().enumerate() {
            let after = manager.test_handle_snapshot();
            assert_eq!(after.version, before[index].version);
            assert_eq!(after.listener.flow, None);
            assert!(
                !after.listener_connected(),
                "slot {index} must remain unconnected after reservation rollback"
            );
        }
    }
}

#[test]
fn shared_flow_failure_publishes_only_required_recovery() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_transitioned = listener_policy_connects_after_lock(&first);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54003));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let prepared = SocketManager::prepare_client_flow_group(
        &[&first, &second],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 0,
            client,
        },
    )
    .expect("prepare shared flow failure");
    let mut flow_transaction = flow_state.reserve_client_flow();

    let transition =
        SocketManager::begin_client_flow_group_transition(prepared, &mut flow_transaction)
            .expect("prepare protocol-state publication rejection");
    let error = match transition.abort("injected protocol-state publication rejection".to_string())
    {
        Ok(_) => panic!("protocol-state publication must reject the transaction"),
        Err(error) => error,
    };

    let ManagerError::TransactionFailed { journal, .. } = error else {
        panic!("clean rollback must return a transaction journal");
    };
    assert_eq!(
        journal[0].recovery,
        if first_transitioned {
            RecoveryOutcome::Replaced
        } else {
            RecoveryOutcome::NotRequired
        }
    );
    assert_eq!(journal[0].forced_replacement, first_transitioned);
    assert_eq!(journal[0].recovery_version.is_some(), first_transitioned);
    assert_eq!(journal[1].recovery, RecoveryOutcome::NotRequired);
    if first_transitioned {
        assert!(first.test_handle_snapshot().version > first_before.version);
    } else {
        assert_eq!(first.test_handle_snapshot().version, first_before.version);
    }
    assert_eq!(second.test_handle_snapshot().version, second_before.version);
    assert!(!first.test_handle_snapshot().listener_connected());
    assert!(!second.test_handle_snapshot().listener_connected());
    assert!(!flow_state.is_locked());
}
