use super::manager::fail_listener_clear_transaction;
use super::tests::{
    establish_prepared_client_flow, listener_policy_connects_after_lock, make_mgr_with_slot,
};
use crate::cli::SupportedProtocol;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::flow_state::FlowRuntimeState;
use crate::net::managed_socket::test_support::ProductionIoTestExt;
use crate::net::managed_socket::{AssociationOperation, AssociationState};
use crate::net::sock_mgr::state::SocketUpdateKind;
use crate::net::sock_mgr::{
    ClientFlowUpdate, ManagerError, ReceiverRole, RecoveryOutcome, SocketManager, StateVersion,
    TransactionJournalEntry, TransactionLeg,
};
use crate::worker_support::CachedClientState;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn shared_flow_prepublication_failure_rolls_back_without_publishing_lock_or_metadata() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_transitioned = listener_policy_connects_after_lock(&first);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54007));
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
    .expect("prepare prepublication failure");
    let mut flow_transaction = flow_state.reserve_client_flow();

    let transition =
        SocketManager::begin_client_flow_group_transition(prepared, &mut flow_transaction)
            .expect("prepare prepublication failure");
    let result = transition.abort("injected protocol-state initialization failure".to_string());

    let journal = match result {
        Err(ManagerError::TransactionFailed { journal, .. }) => journal,
        Ok(_) => panic!("protocol-state initialization failure must reject the transaction"),
        Err(error) => panic!("unexpected prepublication failure: {error}"),
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
    if first_transitioned {
        assert!(first.test_handle_snapshot().version > first_before.version);
    } else {
        assert_eq!(first.test_handle_snapshot().version, first_before.version);
    }
    assert_eq!(second.test_handle_snapshot().version, second_before.version);
    assert_eq!(first.test_handle_snapshot().listener.flow, None);
    assert_eq!(second.test_handle_snapshot().listener.flow, None);
    assert!(!first.test_handle_snapshot().listener_connected());
    assert!(!second.test_handle_snapshot().listener_connected());
    assert!(!flow_state.is_locked());
}

#[test]
fn shared_flow_topology_reservation_rejects_competing_socket_mutation() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_transitioned = listener_policy_connects_after_lock(&first);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();
    let first_socket = first_before.client_sock.clone();
    let flow_state = FlowRuntimeState::new();
    let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 54004));
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client));

    let mutation_rejected = AtomicBool::new(false);
    let prepared = SocketManager::prepare_client_flow_group(
        &[&first, &second],
        ClientFlowUpdate {
            flow,
            listener_flow: SocketLegFlow::empty(),
            admitting_listener_slot: 0,
            client,
        },
    )
    .expect("prepare topology reservation rejection");
    let mut flow_transaction = flow_state.reserve_client_flow();
    let transition =
        SocketManager::begin_client_flow_group_transition(prepared, &mut flow_transaction)
            .expect("prepare topology reservation rejection");
    mutation_rejected.store(
        first_socket.reserve_replacement().is_err(),
        Ordering::Release,
    );
    let error = match transition.abort("injected protocol-state publication rejection".to_string())
    {
        Ok(_) => panic!("protocol-state publication rejection must roll back the transaction"),
        Err(error) => error,
    };

    let ManagerError::TransactionFailed { journal, .. } = error else {
        panic!("clean rollback must return a transaction journal");
    };
    assert!(mutation_rejected.load(Ordering::Acquire));
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
    let first_after = first.test_handle_snapshot();
    let second_after = second.test_handle_snapshot();
    if first_transitioned {
        assert!(first_after.version > first_before.version);
    } else {
        assert_eq!(first_after.version, first_before.version);
    }
    assert_eq!(second_after.version, second_before.version);
    assert_eq!(
        first_after.listener.evidence_key.generation,
        if first_transitioned { 2 } else { 1 }
    );
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
            let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
            let prepared = SocketManager::prepare_client_flow_group(
                &manager_refs,
                ClientFlowUpdate {
                    flow,
                    listener_flow: SocketLegFlow::empty(),
                    admitting_listener_slot: 0,
                    client,
                },
            )
            .expect("prepare observed shared transaction");
            let mut flow_transaction = flow_state.reserve_client_flow();
            let transition =
                SocketManager::begin_client_flow_group_transition(prepared, &mut flow_transaction)
                    .expect("begin observed shared transaction");
            transition_tx
                .send(())
                .expect("publish pre-publication observation");
            release_rx.recv().expect("release shared transaction");
            transition.publish(None)
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
            let handles = manager.test_handle_snapshot();
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
        assert!(update.handles.version > StateVersion::INITIAL);
        assert_eq!(update.handles.listener.flow, Some(flow));
    }
    for manager in managers.iter() {
        assert_eq!(manager.test_handle_snapshot().listener.flow, Some(flow));
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
        let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
        let prepared = SocketManager::prepare_client_flow_group(
            &manager_refs,
            ClientFlowUpdate {
                flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
                listener_flow: SocketLegFlow::empty(),
                admitting_listener_slot: 0,
                client,
            },
        )
        .expect("prepare shared flow before clear");
        let mut transaction = flow_state.reserve_client_flow();
        establish_prepared_client_flow!(prepared, &mut transaction)
            .expect("establish shared flow before clear");
    }

    let reader_handles = managers[0].test_handle_snapshot();
    let reader_cfg =
        crate::worker_support::cache_test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
    let reader_cache = CachedClientState::new(true, 1, &reader_cfg, &reader_handles, false)
        .expect("initialize grouped-clear descriptor cache before transition");
    let first_socket = managers[0].test_handle_snapshot().client_sock.clone();
    let observed_epoch = first_socket.topology_epoch();
    let blocking_io = first_socket
        .acquire_topology_authority(
            observed_epoch,
            crate::net::managed_socket::SocketIoLane::Control,
        )
        .expect("hold one bounded I/O authority during grouped clear");
    let gate_probe_socket = first_socket.clone();
    let (probe_ready_tx, probe_ready_rx) = mpsc::channel();
    let (probe_start_tx, probe_start_rx) = mpsc::channel();
    let gate_probe = thread::spawn(move || {
        let mut descriptor_cache = crate::net::managed_socket::WorkerDescriptorCache::for_worker(0);
        descriptor_cache
            .reconcile(&gate_probe_socket)
            .expect("reconcile gate-probe descriptor cache before grouped clear");
        probe_ready_tx
            .send(())
            .expect("publish prepared gate probe");
        probe_start_rx
            .recv()
            .expect("start grouped-clear gate probe");
        let transition_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match gate_probe_socket.acquire_send_lease(&mut descriptor_cache) {
                Ok(authority) => drop(authority),
                Err(_) => break,
            }
            assert!(
                Instant::now() < transition_deadline,
                "grouped clear did not close the listener topology gate"
            );
            thread::yield_now();
        }
    });
    probe_ready_rx
        .recv()
        .expect("gate probe prepared before clear transaction");
    let clear_thread = {
        let managers = Arc::clone(&managers);
        let flow_state = Arc::clone(&flow_state);
        thread::spawn(move || {
            let mut transaction = flow_state.reserve_client_flow();
            let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
            SocketManager::clear_client_flow_group(&manager_refs, &mut transaction)
        })
    };
    probe_start_tx
        .send(())
        .expect("start grouped-clear gate probe");
    gate_probe.join().expect("join topology gate probe");
    assert!(flow_state.is_locked());
    let (reader_tx, reader_rx) = mpsc::channel();
    let reader = {
        let manager = Arc::clone(&managers[0]);
        let flow_state = Arc::clone(&flow_state);
        thread::spawn(move || {
            let mut handles = reader_handles;
            let mut cache = reader_cache;
            cache
                .service_descriptor_revocation()
                .expect("acknowledge grouped-clear descriptor revocation");
            let deadline = Instant::now() + Duration::from_secs(1);
            let flow_read = loop {
                match flow_state.try_watchdog_topology_read() {
                    Ok(read) => break read,
                    Err(crate::flow_state::FlowTopologyError::Busy) => {
                        assert!(
                            Instant::now() < deadline,
                            "coherent grouped-clear reader did not regain flow authority"
                        );
                        thread::yield_now();
                    }
                    Err(error) => panic!("coherent grouped-clear reader failed: {error}"),
                }
            };
            let flow_read = match cache
                .ensure_worker_state(&manager, &mut handles, flow_read, None)
                .expect("refresh grouped-clear handles under one production transaction")
            {
                crate::worker_support::WorkerStateOutcome::Reconciled(read) => read,
                crate::worker_support::WorkerStateOutcome::Current(_) => {
                    panic!("grouped clear did not require a worker handle refresh")
                }
            };
            assert!(flow_read.is_current());
            reader_tx
                .send(handles)
                .expect("publish clear reader snapshot");
        })
    };
    assert!(
        reader_rx.recv_timeout(BLOCKED_WAIT).is_err(),
        "reader observed topology between grouped clear transitions"
    );

    drop(blocking_io);
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
        let handles = manager.test_handle_snapshot();
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
        let prepared = SocketManager::prepare_client_flow_group(
            &[&first, &second],
            ClientFlowUpdate {
                flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
                listener_flow: SocketLegFlow::empty(),
                admitting_listener_slot: 0,
                client,
            },
        )
        .expect("prepare shared flow before exhaustion");
        let mut transaction = flow_state.reserve_client_flow();
        establish_prepared_client_flow!(prepared, &mut transaction)
            .expect("establish shared flow before exhaustion");
    }
    let second = second.with_initial_version_for_test(StateVersion::MAX);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();

    let mut transaction = flow_state.reserve_client_flow();
    let result = SocketManager::clear_client_flow_group(&[&first, &second], &mut transaction);
    drop(transaction);

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
fn failed_group_clear_finalizes_retired_slots_without_impossible_rollback() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1);
    let first_socket = first.test_handle_snapshot().client_sock.clone();
    let second_socket = second.test_handle_snapshot().client_sock.clone();
    let mut topology = vec![
        Some(
            first_socket
                .reserve_topology(AssociationOperation::PublishMetadata)
                .expect("reserve first topology"),
        ),
        Some(
            second_socket
                .reserve_topology(AssociationOperation::PublishMetadata)
                .expect("reserve second topology"),
        ),
    ];
    let mut retired_topology = vec![
        Some(
            topology[0]
                .take()
                .expect("first reservation")
                .into_retired_for_replacement()
                .expect("cross first irreversible replacement point"),
        ),
        None,
    ];
    let mut journal = vec![
        TransactionJournalEntry {
            socket_slot: 0,
            leg: TransactionLeg::Listener,
            transition_attempted: true,
            transition_completed: false,
            recovery: RecoveryOutcome::Failed,
            forced_replacement: false,
            recovery_version: None,
        },
        TransactionJournalEntry {
            socket_slot: 1,
            leg: TransactionLeg::Listener,
            transition_attempted: false,
            transition_completed: false,
            recovery: RecoveryOutcome::NotRequired,
            forced_replacement: false,
            recovery_version: None,
        },
    ];
    let mut replacements = vec![None, None];

    let error = fail_listener_clear_transaction(
        "injected bind failure".to_string(),
        &mut topology,
        &mut retired_topology,
        &mut journal,
        &mut replacements,
    )
    .expect_err("irreversible replacement failure must fail closed");

    assert!(
        !error
            .to_string()
            .contains("lost the managed socket topology reservation"),
        "phase-aware cleanup must not attempt rollback after descriptor retirement"
    );
    assert!(matches!(
        first_socket.association(),
        AssociationState::Retired { .. }
    ));
    assert!(matches!(
        second_socket.association(),
        AssociationState::Unconnected { .. }
    ));
    second_socket
        .reserve_topology(AssociationOperation::PublishMetadata)
        .expect("untouched topology reopens after cleanup")
        .rollback()
        .expect("untouched topology remains rollback-capable");
}

#[test]
fn grouped_reresolve_exhaustion_prevents_every_transition_and_publication() {
    let first = make_mgr_with_slot(0);
    let second = make_mgr_with_slot(1).with_initial_version_for_test(StateVersion::MAX);
    let first_before = first.test_handle_snapshot();
    let second_before = second.test_handle_snapshot();
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind replacement target");
    let target_addr = target.local_addr().expect("replacement target address");
    let allocations_before = crate::authority::allocation_violation_count_for_authority_for_test(
        crate::authority::AuthorityId::ManagerTransaction,
    );
    let result = SocketManager::begin_reresolve_group_with_addresses(
        &[&second, &first],
        true,
        false,
        None,
        Some(target_addr),
    )
    .and_then(|transition| transition.publish());
    let allocations_after = crate::authority::allocation_violation_count_for_authority_for_test(
        crate::authority::AuthorityId::ManagerTransaction,
    );

    assert!(matches!(
        result,
        Err(ManagerError::VersionExhausted {
            current: StateVersion::MAX
        })
    ));
    assert_eq!(
        allocations_after, allocations_before,
        "grouped re-resolution must initialize topology storage before manager ownership",
    );
    let first_after = first.test_handle_snapshot();
    let second_after = second.test_handle_snapshot();
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
    let versions_before = managers
        .iter()
        .map(|manager| manager.test_handle_snapshot().version)
        .collect::<Vec<_>>();
    let receiver_generations_before = managers
        .iter()
        .map(|manager| manager.receiver_generation(ReceiverRole::Upstream))
        .collect::<Vec<_>>();
    let (transition_tx, transition_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let transaction_thread = {
        let managers = Arc::clone(&managers);
        thread::spawn(move || {
            let manager_refs = managers.iter().map(Arc::as_ref).collect::<Vec<_>>();
            let transition = SocketManager::begin_reresolve_group_with_addresses(
                &manager_refs,
                true,
                false,
                None,
                Some(target_addr),
            )
            .expect("begin grouped re-resolution");
            transition_tx
                .send(())
                .expect("publish grouped pre-commit observation");
            release_rx.recv().expect("release grouped re-resolution");
            transition.publish()
        })
    };

    transition_rx.recv().expect("first reconnect reached");
    for (index, manager) in managers.iter().enumerate() {
        assert_eq!(
            manager.receiver_generation(ReceiverRole::Upstream),
            receiver_generations_before[index],
            "prepared re-resolution published receiver ownership before commit"
        );
    }
    let (reader_tx, reader_rx) = mpsc::channel();
    let reader = {
        let manager = Arc::clone(&managers[0]);
        thread::spawn(move || {
            reader_tx
                .send(manager.test_handle_snapshot())
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

    assert!(reader_handles.version > versions_before[0]);
    assert_eq!(
        reader_handles
            .upstream
            .upstream_remote_filter
            .to_socket_addr(),
        target_addr
    );
    for (index, summary) in summaries.into_iter().enumerate() {
        assert!(summary.handles.version > versions_before[index]);
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
fn grouped_reresolve_reservation_rejects_competing_upstream_disconnect() {
    let manager = make_mgr_with_slot(7);
    let before = manager.test_handle_snapshot();
    let old_socket = before.upstream_sock.clone();
    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind replacement target");
    let target_addr = target.local_addr().expect("replacement target address");

    let mutation_rejected = AtomicBool::new(false);
    let transition = SocketManager::begin_reresolve_group_with_addresses(
        &[&manager],
        true,
        false,
        None,
        Some(target_addr),
    )
    .expect("begin reserved reconnect");
    mutation_rejected.store(
        old_socket.disconnect_connected().is_err(),
        Ordering::Release,
    );
    let summaries = transition.publish().expect("complete reserved reconnect");
    let summary = summaries
        .into_iter()
        .next()
        .expect("single recovery summary");

    assert!(mutation_rejected.load(Ordering::Acquire));
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
        AssociationState::Retired { .. }
    ));
}
