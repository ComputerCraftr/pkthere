use super::{make_mgr, make_mgr_with_slot};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::flow_state::FlowRuntimeState;
use crate::net::managed_socket::{AssociationOperation, AssociationState};
use crate::net::sock_mgr::state::SocketUpdateKind;
use crate::net::sock_mgr::{
    ClientFlowUpdate, ManagerError, RecoveryOutcome, SocketManager, StateVersion,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

#[test]
fn concurrent_changed_updates_allocate_distinct_manager_versions() {
    let mgr = Arc::new(make_mgr());
    let initial = mgr.current_version();
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for (source_id, reply_id) in [(41001, 42001), (41002, 42002)] {
        let mgr = Arc::clone(&mgr);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            mgr.set_upstream_peer_ids(source_id, reply_id)
                .expect("concurrent peer-ID update")
        }));
    }
    barrier.wait();
    let first = workers.remove(0).join().expect("first update thread");
    let second = workers.remove(0).join().expect("second update thread");

    assert_ne!(first.version, second.version);
    assert!(first.version > initial);
    assert!(second.version > initial);
    assert_eq!(first.version, first.handles.version);
    assert_eq!(second.version, second.handles.version);
}

#[test]
fn version_exhaustion_rejects_update_before_metadata_mutation() {
    let mgr = make_mgr();
    let before = mgr.refresh_handles();
    mgr.set_version_for_test(StateVersion::MAX);

    let error = match mgr.set_upstream_peer_ids(51001, 52001) {
        Ok(_) => panic!("exhausted version must reject update"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ManagerError::VersionExhausted {
            current: StateVersion::MAX
        }
    ));
    let after = mgr.refresh_handles();
    assert_eq!(after.version, StateVersion::MAX);
    assert_eq!(
        after.upstream.upstream_remote_filter,
        before.upstream.upstream_remote_filter
    );
    assert_eq!(after.upstream.upstream_flow, before.upstream.upstream_flow);
}

#[test]
fn association_epoch_changes_without_manager_topology_publication() {
    let mgr = make_mgr();
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53001);
    mgr.establish_client_flow(
        ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
        SocketLegFlow::empty(),
        true,
        client,
    )
    .expect("connect listener");
    let handles = mgr.refresh_handles();
    let topology_version = handles.version;
    let before_association = handles.client_sock.association();

    handles
        .client_sock
        .disconnect_connected()
        .expect("change only managed association");
    let after_association = handles.client_sock.association();

    assert_ne!(before_association, after_association);
    assert_eq!(mgr.current_version(), topology_version);
    assert_eq!(mgr.refresh_handles().version, topology_version);
}

#[test]
fn shared_flow_exhaustion_prevents_every_transition_and_publication() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    second.set_version_for_test(StateVersion::MAX);
    let first_before = first.refresh_handles();
    let second_before = second.refresh_handles();
    let flow_state = FlowRuntimeState::new();
    let flow_transaction = flow_state.client_lock_transaction();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54001));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));

    let result = SocketManager::establish_client_flow_group(
        &[&first, &second],
        &flow_transaction,
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            connect_socket: true,
            client,
        },
    );

    assert!(matches!(
        result,
        Err(ManagerError::VersionExhausted {
            current: StateVersion::MAX
        })
    ));
    let first_after = first.refresh_handles();
    let second_after = second.refresh_handles();
    assert_eq!(first_after.version, first_before.version);
    assert_eq!(second_after.version, second_before.version);
    assert_eq!(first_after.listener.flow, None);
    assert_eq!(second_after.listener.flow, None);
    assert!(!first_after.listener_connected());
    assert!(!second_after.listener_connected());
    assert!(!flow_state.is_locked());
}

#[test]
fn shared_flow_clean_rollback_publishes_nothing() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_before = first.refresh_handles();
    let second_before = second.refresh_handles();
    let flow_state = FlowRuntimeState::new();
    let flow_transaction = flow_state.client_lock_transaction();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54003));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));

    let error = match SocketManager::establish_client_flow_group_with_observers(
        &[&first, &second],
        &flow_transaction,
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            connect_socket: true,
            client,
        },
        |slot| {
            if slot == 1 {
                Err("injected pre-transition rejection".to_string())
            } else {
                Ok(())
            }
        },
        |_| {},
    ) {
        Ok(_) => panic!("second manager must reject before transition"),
        Err(error) => error,
    };

    let ManagerError::TransactionFailed { journal, .. } = error else {
        panic!("clean rollback must return a transaction journal");
    };
    assert_eq!(journal[0].recovery, RecoveryOutcome::Restored);
    assert_eq!(journal[0].recovery_version, None);
    assert_eq!(journal[1].recovery, RecoveryOutcome::NotRequired);
    assert_eq!(first.refresh_handles().version, first_before.version);
    assert_eq!(second.refresh_handles().version, second_before.version);
    assert!(!first.refresh_handles().listener_connected());
    assert!(!second.refresh_handles().listener_connected());
    assert!(!flow_state.is_locked());
}

#[test]
fn shared_flow_rollback_replacement_publishes_only_affected_manager_once() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_before = first.refresh_handles();
    let second_before = second.refresh_handles();
    let first_socket = first_before.client_sock.clone();
    let flow_state = FlowRuntimeState::new();
    let flow_transaction = flow_state.client_lock_transaction();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54004));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));

    let error = match SocketManager::establish_client_flow_group_with_observers(
        &[&first, &second],
        &flow_transaction,
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            connect_socket: true,
            client,
        },
        |slot| {
            if slot == 1 {
                first_socket.poison_association_for_test(AssociationOperation::Disconnect);
                Err("injected second-manager rejection".to_string())
            } else {
                Ok(())
            }
        },
        |_| {},
    ) {
        Ok(_) => panic!("rollback must replace invalidated first listener"),
        Err(error) => error,
    };

    let ManagerError::TransactionFailed { journal, .. } = error else {
        panic!("forced recovery must return a transaction journal");
    };
    assert_eq!(journal[0].recovery, RecoveryOutcome::Replaced);
    assert!(journal[0].forced_replacement);
    assert_eq!(
        journal[0]
            .recovery_version
            .expect("replacement publication")
            .get(),
        first_before.version.get() + 1
    );
    assert_eq!(journal[1].recovery, RecoveryOutcome::NotRequired);
    let first_after = first.refresh_handles();
    let second_after = second.refresh_handles();
    assert_eq!(first_after.version.get(), first_before.version.get() + 1);
    assert_eq!(second_after.version, second_before.version);
    assert_eq!(first_after.listener.evidence_key.generation, 2);
    assert_eq!(first_after.listener.flow, None);
    assert_eq!(second_after.listener.flow, None);
    assert!(!flow_state.is_locked());
}

#[test]
fn shared_flow_reader_blocks_until_all_managers_and_global_lock_are_published() {
    const BLOCKED_WAIT: Duration = Duration::from_millis(100);

    let managers = Arc::new(vec![
        Arc::new(make_mgr_with_slot(0)),
        Arc::new(make_mgr_with_slot(1)),
    ]);
    let flow_state = Arc::new(FlowRuntimeState::new());
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54002));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));
    let (transition_tx, transition_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let transaction_thread = {
        let managers = Arc::clone(&managers);
        let flow_state = Arc::clone(&flow_state);
        thread::spawn(move || {
            let flow_transaction = flow_state.client_lock_transaction();
            let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
            SocketManager::establish_client_flow_group_with_observer(
                &manager_refs,
                &flow_transaction,
                ClientFlowUpdate {
                    flow,
                    listener_flow: SocketLegFlow::empty(),
                    connect_socket: true,
                    client,
                },
                |slot| {
                    if slot == 0 {
                        transition_tx
                            .send(())
                            .expect("publish first transition observation");
                        release_rx.recv().expect("release shared transaction");
                    }
                },
            )
        })
    };

    transition_rx
        .recv()
        .expect("first manager transition reached");
    let (reader_tx, reader_rx) = mpsc::channel();
    let reader = {
        let manager = Arc::clone(&managers[0]);
        let flow_state = Arc::clone(&flow_state);
        thread::spawn(move || {
            let handles = manager.refresh_handles();
            reader_tx
                .send((handles, flow_state.is_locked()))
                .expect("publish reader snapshot");
        })
    };
    assert!(
        reader_rx.recv_timeout(BLOCKED_WAIT).is_err(),
        "reader observed a manager while the shared transaction was incomplete"
    );

    release_tx.send(()).expect("release transaction");
    let published = transaction_thread
        .join()
        .expect("join shared transaction")
        .expect("commit shared flow");
    reader.join().expect("join blocked reader");
    let (reader_handles, reader_locked) = reader_rx.recv().expect("reader snapshot");

    assert!(reader_locked);
    assert_eq!(reader_handles.listener.flow, Some(flow));
    for update in &published {
        assert_eq!(update.version, update.handles.version);
        assert_eq!(update.handles.listener.flow, Some(flow));
    }
    for manager in managers.iter() {
        assert_eq!(manager.refresh_handles().listener.flow, Some(flow));
    }
}

#[test]
fn shared_flow_clear_reader_blocks_until_all_managers_and_global_lock_are_cleared() {
    const BLOCKED_WAIT: Duration = Duration::from_millis(100);

    let managers = Arc::new(vec![
        Arc::new(make_mgr_with_slot(0)),
        Arc::new(make_mgr_with_slot(1)),
    ]);
    let flow_state = Arc::new(FlowRuntimeState::new());
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54006));
    {
        let transaction = flow_state.client_lock_transaction();
        let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
        SocketManager::establish_client_flow_group(
            &manager_refs,
            &transaction,
            ClientFlowUpdate {
                flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
                listener_flow: SocketLegFlow::empty(),
                connect_socket: true,
                client,
            },
        )
        .expect("establish shared flow before clear");
    }

    let (transition_tx, transition_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let clear_thread = {
        let managers = Arc::clone(&managers);
        let flow_state = Arc::clone(&flow_state);
        thread::spawn(move || {
            let transaction = flow_state.client_lock_transaction();
            let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
            SocketManager::clear_client_flow_group_with_observer(
                &manager_refs,
                &transaction,
                |slot| {
                    if slot == 0 {
                        transition_tx.send(()).expect("publish first clear");
                        release_rx.recv().expect("release grouped clear");
                    }
                },
            )
        })
    };

    transition_rx
        .recv()
        .expect("first clear transition reached");
    assert!(flow_state.is_locked());
    let (reader_tx, reader_rx) = mpsc::channel();
    let reader = {
        let manager = Arc::clone(&managers[0]);
        thread::spawn(move || {
            reader_tx
                .send(manager.refresh_handles())
                .expect("publish clear reader snapshot");
        })
    };
    assert!(
        reader_rx.recv_timeout(BLOCKED_WAIT).is_err(),
        "reader observed topology between grouped clear transitions"
    );

    release_tx.send(()).expect("release grouped clear");
    let cleared = clear_thread
        .join()
        .expect("join grouped clear")
        .expect("complete grouped clear");
    reader.join().expect("join grouped clear reader");
    let observed = reader_rx.recv().expect("cleared reader handles");

    assert_eq!(cleared.updates.len(), 2);
    assert_eq!(observed.listener.flow, None);
    assert!(!observed.listener_connected());
    assert!(!flow_state.is_locked());
    for manager in managers.iter() {
        let handles = manager.refresh_handles();
        assert_eq!(handles.listener.flow, None);
        assert!(!handles.listener_connected());
    }
}

#[test]
fn shared_flow_clear_exhaustion_prevents_every_transition_and_publication() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54007));
    {
        let transaction = flow_state.client_lock_transaction();
        SocketManager::establish_client_flow_group(
            &[&first, &second],
            &transaction,
            ClientFlowUpdate {
                flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
                listener_flow: SocketLegFlow::empty(),
                connect_socket: true,
                client,
            },
        )
        .expect("establish shared flow before exhaustion");
    }
    second.set_version_for_test(StateVersion::MAX);
    let first_before = first.refresh_handles();
    let second_before = second.refresh_handles();

    let transaction = flow_state.client_lock_transaction();
    let result = SocketManager::clear_client_flow_group(&[&first, &second], &transaction);
    drop(transaction);

    assert!(matches!(
        result,
        Err(ManagerError::VersionExhausted {
            current: StateVersion::MAX
        })
    ));
    let first_after = first.refresh_handles();
    let second_after = second.refresh_handles();
    assert_eq!(first_after.version, first_before.version);
    assert_eq!(second_after.version, second_before.version);
    assert_eq!(first_after.listener.flow, first_before.listener.flow);
    assert_eq!(second_after.listener.flow, second_before.listener.flow);
    assert_eq!(
        first_after.client_sock.association(),
        first_before.client_sock.association()
    );
    assert_eq!(
        second_after.client_sock.association(),
        second_before.client_sock.association()
    );
    assert!(flow_state.is_locked());
}

#[test]
fn grouped_reresolve_exhaustion_prevents_every_transition_and_publication() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    second.set_version_for_test(StateVersion::MAX);
    let first_before = first.refresh_handles();
    let second_before = second.refresh_handles();
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind replacement target");
    let target_addr = target.local_addr().expect("replacement target address");

    let result = SocketManager::reresolve_group_with_addresses(
        &[&second, &first],
        true,
        false,
        "group exhaustion",
        None,
        Some(target_addr),
        |_| {},
    );

    assert!(matches!(
        result,
        Err(ManagerError::VersionExhausted {
            current: StateVersion::MAX
        })
    ));
    let first_after = first.refresh_handles();
    let second_after = second.refresh_handles();
    assert_eq!(first_after.version, first_before.version);
    assert_eq!(second_after.version, second_before.version);
    assert_eq!(
        first_after.upstream_sock.association(),
        first_before.upstream_sock.association()
    );
    assert_eq!(
        second_after.upstream_sock.association(),
        second_before.upstream_sock.association()
    );
    assert_eq!(
        first_after.upstream.upstream_remote_filter,
        first_before.upstream.upstream_remote_filter
    );
    assert_eq!(
        second_after.upstream.upstream_remote_filter,
        second_before.upstream.upstream_remote_filter
    );
}

#[test]
fn grouped_reresolve_reader_blocks_until_every_manager_is_committed() {
    const BLOCKED_WAIT: Duration = Duration::from_millis(100);

    let managers = Arc::new(vec![
        Arc::new(make_mgr_with_slot(0)),
        Arc::new(make_mgr_with_slot(1)),
    ]);
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind replacement target");
    let target_addr = target.local_addr().expect("replacement target address");
    let (transition_tx, transition_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let transaction_thread = {
        let managers = Arc::clone(&managers);
        thread::spawn(move || {
            let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
            SocketManager::reresolve_group_with_observers(
                &manager_refs,
                true,
                false,
                "group reader",
                None,
                Some(target_addr),
                |_| {},
                |slot| {
                    if slot == 0 {
                        transition_tx
                            .send(())
                            .expect("publish first reconnect observation");
                        release_rx.recv().expect("release grouped re-resolution");
                    }
                },
                |_| {},
            )
        })
    };

    transition_rx.recv().expect("first reconnect reached");
    let (reader_tx, reader_rx) = mpsc::channel();
    let reader = {
        let manager = Arc::clone(&managers[0]);
        thread::spawn(move || {
            reader_tx
                .send(manager.refresh_handles())
                .expect("publish grouped reader snapshot");
        })
    };
    assert!(
        reader_rx.recv_timeout(BLOCKED_WAIT).is_err(),
        "reader observed topology between grouped reconnects"
    );

    release_tx.send(()).expect("release grouped transaction");
    let summaries = transaction_thread
        .join()
        .expect("join grouped transaction")
        .expect("commit grouped re-resolution");
    reader.join().expect("join grouped reader");
    let reader_handles = reader_rx.recv().expect("reader handles");

    assert_eq!(
        reader_handles
            .upstream
            .upstream_remote_filter
            .to_socket_addr(),
        target_addr
    );
    for summary in summaries {
        assert_eq!(
            summary
                .handles
                .upstream
                .upstream_remote_filter
                .to_socket_addr(),
            target_addr
        );
    }
}

#[test]
fn reconnect_failure_uses_prepared_replacement_and_publishes_once() {
    let manager = make_mgr_with_slot(7);
    let before = manager.refresh_handles();
    let old_socket = before.upstream_sock.clone();
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind replacement target");
    let target_addr = target.local_addr().expect("replacement target address");

    let summaries = SocketManager::reresolve_group_with_observers(
        &[&manager],
        true,
        false,
        "forced reconnect recovery",
        None,
        Some(target_addr),
        |slot| {
            assert_eq!(slot, 7);
            old_socket
                .disconnect_connected()
                .expect("invalidate planned reconnect");
        },
        |_| {},
        |_| {},
    )
    .expect("recover reconnect with prepared replacement");
    let summary = summaries
        .into_iter()
        .next()
        .expect("single recovery summary");

    assert_eq!(summary.upstream_update, SocketUpdateKind::Replaced);
    assert_eq!(summary.handles.version.get(), before.version.get() + 1);
    assert_eq!(summary.handles.upstream.evidence_key.generation, 2);
    assert_eq!(
        summary
            .handles
            .upstream
            .upstream_remote_filter
            .to_socket_addr(),
        target_addr
    );
    assert!(summary.handles.upstream_connected());
    assert!(matches!(
        old_socket.association(),
        AssociationState::Unconnected { .. }
    ));
}
