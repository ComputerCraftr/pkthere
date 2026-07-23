use super::client::ClientWorkerContext;
use super::{CachedClientState, CachedSendRoute, PacketDisposition, PacketTraceId};
use crate::cli::WorkerFlowMode;
use crate::endpoint::LogicalEndpoint;
use crate::flow_state::PendingIcmpClientLock;
use crate::net::icmp_sequence::{IcmpSequenceCache, reset_sequence_state};
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::stats::StatsSink;
use std::fmt;
use std::io;

const C2U: bool = true;

#[derive(Clone, Copy)]
struct ClientFlowTransaction {
    flow: crate::flow_key::ClientFlowKey,
    listener_flow: crate::flow_key::SocketLegFlow,
    connect_socket: bool,
    client: std::net::SocketAddr,
}

trait ClientFlowTransactionParticipant: Sync {
    fn establish(&self, transaction: ClientFlowTransaction) -> io::Result<()>;
    fn rollback(&self) -> io::Result<()>;
}

impl ClientFlowTransactionParticipant for SocketManager {
    fn establish(&self, transaction: ClientFlowTransaction) -> io::Result<()> {
        self.establish_client_flow(
            transaction.flow,
            transaction.listener_flow,
            transaction.connect_socket,
            transaction.client,
        )
        .map(|_| ())
    }

    fn rollback(&self) -> io::Result<()> {
        self.clear_client_lock().map(|_| ())
    }
}

#[derive(Debug)]
pub(super) enum ClientLockTransactionError {
    RollbackFailed {
        establishment: io::Error,
        rollback_failures: Vec<io::Error>,
    },
}

impl fmt::Display for ClientLockTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RollbackFailed {
                establishment,
                rollback_failures,
            } => write!(
                formatter,
                "client-flow establishment failed ({establishment}); {} rollback operation(s) also failed: {}",
                rollback_failures.len(),
                rollback_failures
                    .iter()
                    .map(io::Error::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        }
    }
}

impl std::error::Error for ClientLockTransactionError {}

enum ClientFlowTransactionOutcome {
    Established,
    Rejected(io::Error),
}

fn establish_client_flow_transaction(
    managers: &[&dyn ClientFlowTransactionParticipant],
    transaction: ClientFlowTransaction,
) -> Result<ClientFlowTransactionOutcome, ClientLockTransactionError> {
    let mut established: Vec<&dyn ClientFlowTransactionParticipant> =
        Vec::with_capacity(managers.len());
    for manager in managers {
        if let Err(establishment) = manager.establish(transaction) {
            let rollback_failures = established
                .into_iter()
                .filter_map(|established_manager| established_manager.rollback().err())
                .collect::<Vec<_>>();
            if rollback_failures.is_empty() {
                return Ok(ClientFlowTransactionOutcome::Rejected(establishment));
            }
            return Err(ClientLockTransactionError::RollbackFailed {
                establishment,
                rollback_failures,
            });
        }
        established.push(*manager);
    }
    Ok(ClientFlowTransactionOutcome::Established)
}

fn pending_session_control_reply_route(
    candidate: PendingIcmpClientLock,
) -> Option<CachedSendRoute> {
    let inbound = candidate.listener_flow.inbound?;
    let outbound = candidate.listener_flow.outbound?;
    let destination = candidate.listener_flow.outbound_destination()?;
    Some(
        CachedClientState::build_pending_session_control_reply_route(
            destination,
            outbound.src.id(),
            outbound.src.ip(),
            inbound.dst.id(),
        ),
    )
}

pub(super) fn accept_pending_negotiation(
    context: &ClientWorkerContext<'_>,
    candidate: Option<PendingIcmpClientLock>,
    trace: PacketTraceId,
) -> Result<Option<CachedSendRoute>, ()> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if context
        .flow_state
        .set_pending_icmp_client_lock(candidate)
        .is_err()
    {
        log_debug_dir!(
            context.cfg.debug_logs.drops,
            context.worker_id,
            C2U,
            "dropping mismatched pre-lock ICMP reply-ID negotiation"
        );
        context.stats.drop_err(C2U);
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Err(());
    }
    Ok(pending_session_control_reply_route(candidate))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_client_lock(
    context: &ClientWorkerContext<'_>,
    handles: &mut SocketHandles,
    cache: &mut CachedClientState,
    client_side_cache: &mut IcmpSequenceCache,
    upstream_side_cache: &mut IcmpSequenceCache,
    was_locked: &mut bool,
    source: LogicalEndpoint,
    candidate: PendingIcmpClientLock,
    trace: PacketTraceId,
) -> Result<bool, ClientLockTransactionError> {
    let _transaction_guard = context.flow_state.client_lock_transaction();
    if context.flow_state.is_locked() {
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Ok(false);
    }
    let flow = candidate.flow_key;
    let listener_flow = candidate.listener_flow;
    if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
        && context
            .flow_claims
            .is_some_and(|claims| !claims.try_claim(flow, context.worker_pair_id))
    {
        super::log_packet_disposition(context.cfg, trace, PacketDisposition::DropFlowConflict);
        return Ok(false);
    }

    let client = listener_flow.inbound.map_or_else(
        || source.to_socket_addr(),
        |inbound| inbound.src.to_socket_addr(),
    );
    let connect_socket = context
        .sock_mgr
        .get_listener_worker_socket_policy()
        .connects_after_lock(handles.listener.policy);
    let managers: Vec<&dyn ClientFlowTransactionParticipant> =
        if context.cfg.worker_flow_mode == WorkerFlowMode::SharedFlow {
            context
                .all_sock_mgrs
                .iter()
                .map(|manager| {
                    AsRef::<SocketManager>::as_ref(manager) as &dyn ClientFlowTransactionParticipant
                })
                .collect::<Vec<_>>()
        } else {
            vec![context.sock_mgr as &dyn ClientFlowTransactionParticipant]
        };
    match establish_client_flow_transaction(
        &managers,
        ClientFlowTransaction {
            flow,
            listener_flow,
            connect_socket,
            client,
        },
    ) {
        Ok(ClientFlowTransactionOutcome::Established) => {}
        Ok(ClientFlowTransactionOutcome::Rejected(error)) => {
            if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
                && let Some(claims) = context.flow_claims
            {
                claims.release(flow, context.worker_pair_id);
            }
            log_warn_dir!(
                context.worker_id,
                C2U,
                "client socket transition rejected pending lock for {}: {}",
                source,
                error
            );
            return Ok(false);
        }
        Err(error) => {
            if context.cfg.worker_flow_mode == WorkerFlowMode::SingleFlow
                && let Some(claims) = context.flow_claims
            {
                claims.release(flow, context.worker_pair_id);
            }
            return Err(error);
        }
    }

    reset_sequence_state(
        context.cfg.debug_logs.packets,
        context.client_side_state,
        client_side_cache,
    );
    reset_sequence_state(
        context.cfg.debug_logs.packets,
        context.upstream_side_state,
        upstream_side_cache,
    );
    context.flow_state.set_locked(true);
    context.flow_state.clear_pending_icmp_client_lock();
    *was_locked = true;
    *handles = context.sock_mgr.refresh_handles();
    log_info!(
        "Locked to single client {} ({})",
        source,
        if handles.listener_connected() {
            "connected"
        } else {
            "not connected"
        }
    );
    log_debug_dir!(
        context.cfg.debug_logs.handles,
        context.worker_id,
        C2U,
        "publish lock: flow={:?} connected={} ver={}",
        flow,
        handles.listener_connected(),
        handles.version
    );
    if let Ok(new_handles) = context.sock_mgr.reresolve(
        context.cfg.reresolve_mode.allow_upstream(),
        false,
        "Re-resolved",
    ) {
        *handles = new_handles;
        cache.refresh_from_handles(handles);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        ClientFlowTransaction, ClientFlowTransactionOutcome, ClientFlowTransactionParticipant,
        ClientLockTransactionError, establish_client_flow_transaction,
    };
    use crate::endpoint::LogicalEndpoint;
    use crate::flow_key::{ClientFlowKey, SocketLegFlow};
    use crate::flow_state::FlowRuntimeState;
    use crate::runtime_support::FATAL_EXIT;
    use crate::worker_support::client::request_fatal_exit_after_client_lock_failure;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    const BLOCKED_OBSERVATION_WAIT: Duration = Duration::from_millis(100);

    struct FakeParticipant {
        reject_establish: bool,
        fail_rollback: bool,
        candidate_visible: AtomicBool,
        establish_entered: Option<Arc<Barrier>>,
        establish_release: Option<Arc<Barrier>>,
    }

    impl ClientFlowTransactionParticipant for FakeParticipant {
        fn establish(&self, _transaction: ClientFlowTransaction) -> io::Result<()> {
            if self.reject_establish {
                return Err(io::Error::other("injected establishment failure"));
            }
            self.candidate_visible.store(true, Ordering::Release);
            if let Some(entered) = &self.establish_entered {
                entered.wait();
            }
            if let Some(release) = &self.establish_release {
                release.wait();
            }
            Ok(())
        }

        fn rollback(&self) -> io::Result<()> {
            self.candidate_visible.store(false, Ordering::Release);
            if self.fail_rollback {
                Err(io::Error::other("injected rollback failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn shared_flow_rollback_failure_is_typed_and_clears_candidate_metadata() {
        let first = FakeParticipant {
            reject_establish: false,
            fail_rollback: true,
            candidate_visible: AtomicBool::new(false),
            establish_entered: None,
            establish_release: None,
        };
        let second = FakeParticipant {
            reject_establish: true,
            fail_rollback: false,
            candidate_visible: AtomicBool::new(false),
            establish_entered: None,
            establish_release: None,
        };
        let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 3003));
        let transaction = ClientFlowTransaction {
            flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
            listener_flow: SocketLegFlow::empty(),
            connect_socket: false,
            client,
        };

        let result = establish_client_flow_transaction(
            &[
                &first as &dyn ClientFlowTransactionParticipant,
                &second as &dyn ClientFlowTransactionParticipant,
            ],
            transaction,
        );

        assert!(matches!(
            result,
            Err(ClientLockTransactionError::RollbackFailed {
                rollback_failures,
                ..
            }) if rollback_failures.len() == 1
        ));
        assert!(!first.candidate_visible.load(Ordering::Acquire));
        assert!(!second.candidate_visible.load(Ordering::Acquire));
    }

    #[test]
    fn rejected_shared_flow_with_clean_rollback_is_recoverable() {
        let first = FakeParticipant {
            reject_establish: false,
            fail_rollback: false,
            candidate_visible: AtomicBool::new(false),
            establish_entered: None,
            establish_release: None,
        };
        let second = FakeParticipant {
            reject_establish: true,
            fail_rollback: false,
            candidate_visible: AtomicBool::new(false),
            establish_entered: None,
            establish_release: None,
        };
        let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 3004));
        let transaction = ClientFlowTransaction {
            flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
            listener_flow: SocketLegFlow::empty(),
            connect_socket: false,
            client,
        };

        assert!(matches!(
            establish_client_flow_transaction(
                &[
                    &first as &dyn ClientFlowTransactionParticipant,
                    &second as &dyn ClientFlowTransactionParticipant,
                ],
                transaction,
            ),
            Ok(ClientFlowTransactionOutcome::Rejected(_))
        ));
        assert!(!first.candidate_visible.load(Ordering::Acquire));
    }

    #[test]
    fn shared_flow_concurrent_rollback_failure_blocks_competitors_and_requests_fatal_exit() {
        let flow_state = Arc::new(FlowRuntimeState::new());
        let exit_code = Arc::new(AtomicU32::new(0));
        let establish_entered = Arc::new(Barrier::new(2));
        let establish_release = Arc::new(Barrier::new(2));
        let first = Arc::new(FakeParticipant {
            reject_establish: false,
            fail_rollback: true,
            candidate_visible: AtomicBool::new(false),
            establish_entered: Some(Arc::clone(&establish_entered)),
            establish_release: Some(Arc::clone(&establish_release)),
        });
        let second = Arc::new(FakeParticipant {
            reject_establish: true,
            fail_rollback: false,
            candidate_visible: AtomicBool::new(false),
            establish_entered: None,
            establish_release: None,
        });
        let client = SocketAddr::from((Ipv4Addr::LOCALHOST, 3005));
        let transaction = ClientFlowTransaction {
            flow: ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(client)),
            listener_flow: SocketLegFlow::empty(),
            connect_socket: false,
            client,
        };

        let transaction_thread = {
            let flow_state = Arc::clone(&flow_state);
            let exit_code = Arc::clone(&exit_code);
            let first = Arc::clone(&first);
            let second = Arc::clone(&second);
            thread::spawn(move || {
                let _transaction_guard = flow_state.client_lock_transaction();
                let result = establish_client_flow_transaction(
                    &[
                        first.as_ref() as &dyn ClientFlowTransactionParticipant,
                        second.as_ref() as &dyn ClientFlowTransactionParticipant,
                    ],
                    transaction,
                );
                if result.is_err() {
                    request_fatal_exit_after_client_lock_failure(&exit_code);
                }
                result
            })
        };

        establish_entered.wait();
        assert!(first.candidate_visible.load(Ordering::Acquire));
        assert!(!flow_state.is_locked());

        let (observed_tx, observed_rx) = mpsc::channel();
        let competing_worker = {
            let flow_state = Arc::clone(&flow_state);
            thread::spawn(move || {
                let _transaction_guard = flow_state.client_lock_transaction();
                observed_tx
                    .send(flow_state.is_locked())
                    .expect("publish competing-worker observation");
            })
        };
        assert!(
            observed_rx.recv_timeout(BLOCKED_OBSERVATION_WAIT).is_err(),
            "competing worker entered while the shared-flow transaction was incomplete"
        );

        establish_release.wait();
        let result = transaction_thread
            .join()
            .expect("join failing shared-flow transaction");
        assert!(matches!(
            result,
            Err(ClientLockTransactionError::RollbackFailed {
                rollback_failures,
                ..
            }) if rollback_failures.len() == 1
        ));
        competing_worker.join().expect("join competing worker");

        assert!(!observed_rx.recv().expect("competing-worker lock state"));
        assert!(!first.candidate_visible.load(Ordering::Acquire));
        assert!(!second.candidate_visible.load(Ordering::Acquire));
        assert!(!flow_state.is_locked());
        assert_eq!(exit_code.load(Ordering::Acquire), FATAL_EXIT);
    }
}
