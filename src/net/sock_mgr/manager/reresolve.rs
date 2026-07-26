use super::{ReresolveSummary, SocketManager};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::SocketLegFlow;
use crate::net::managed_socket::ManagedSocket;
use crate::net::packet_headers::select_packet_parser;
use crate::net::sock_mgr::evidence::socket_evidence_json;
use crate::net::sock_mgr::flow::upstream_leg_flow;
use crate::net::sock_mgr::state::{
    ClientListenState, ListenerMetadata, ReresolveAction, SocketUpdateKind, UpstreamMetadata,
    UpstreamState, decide_listener_endpoint_update, decide_upstream_endpoint_update,
};
use crate::net::sock_mgr::{
    ManagerError, RecoveryOutcome, SocketHandles, TransactionJournalEntry, TransactionLeg,
};
use crate::net::socket::{
    UpstreamSocketRequest, family_changed, make_socket, make_upstream_socket_for, resolve_first,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

struct PreparedListenerReplacement {
    socket: ManagedSocket,
    metadata: Arc<ListenerMetadata>,
    update: SocketUpdateKind,
}

enum ListenerReresolvePlan {
    Unchanged,
    Replace(PreparedListenerReplacement),
}

struct PreparedUpstreamReplacement {
    socket: ManagedSocket,
    metadata: Arc<UpstreamMetadata>,
    update: SocketUpdateKind,
}

enum UpstreamReresolvePlan {
    Unchanged,
    Metadata(Arc<UpstreamMetadata>),
    Reconnect {
        destination: LogicalEndpoint,
        fallback: PreparedUpstreamReplacement,
    },
    Replace(PreparedUpstreamReplacement),
}

struct AppliedUpstreamPlan {
    socket: Option<ManagedSocket>,
    metadata: Option<Arc<UpstreamMetadata>>,
    update: SocketUpdateKind,
    journal: TransactionJournalEntry,
}

impl SocketManager {
    fn prepare_listener_reresolve(
        &self,
        state: &ClientListenState,
        resolved: Option<SocketAddr>,
        preserve_logical_id: bool,
    ) -> io::Result<ListenerReresolvePlan> {
        let Some(resolved) = resolved else {
            return Ok(ListenerReresolvePlan::Unchanged);
        };
        let previous = state.listen_local_filter;
        let fresh = if preserve_logical_id {
            previous.with_resolved_ip(resolved)
        } else {
            LogicalEndpoint::from_socket_addr(resolved)
        };
        let (_, action) = decide_listener_endpoint_update(previous, fresh);
        if action == ReresolveAction::NoChange {
            return Ok(ListenerReresolvePlan::Unchanged);
        }

        let (socket, logical_local, kernel_addr, sock_type, policy) = make_socket(
            fresh.to_socket_addr(),
            self.listen_proto,
            1000,
            self.listen_worker_socket_policy,
            self.timeout_action,
            self.listen_debug_unconnected,
            self.upstream_icmp_kernel_echo_self_handshake,
        )?;
        let parser = select_packet_parser(
            self.listen_proto,
            socket2::Domain::for_address(kernel_addr),
            policy,
        )?;
        let update = if family_changed(previous.to_socket_addr(), logical_local.to_socket_addr()) {
            SocketUpdateKind::ReplacedCrossFamily
        } else {
            SocketUpdateKind::Replaced
        };
        Ok(ListenerReresolvePlan::Replace(
            PreparedListenerReplacement {
                socket,
                metadata: Arc::new(ListenerMetadata {
                    listen_local_filter: logical_local,
                    listen_local_kernel_addr: kernel_addr,
                    evidence_key: state.evidence_key.replacement(kernel_addr),
                    flow: None,
                    listener_flow: SocketLegFlow::empty(),
                    sock_type,
                    policy,
                    parser,
                }),
                update,
            },
        ))
    }

    fn prepare_upstream_replacement(
        &self,
        state: &UpstreamState,
        destination: LogicalEndpoint,
    ) -> io::Result<PreparedUpstreamReplacement> {
        let (socket, local_filter, remote_filter, kernel_addr, sock_type, policy) =
            make_upstream_socket_for(UpstreamSocketRequest {
                dest: destination,
                proto: self.upstream_proto,
                req_local_id: Self::upstream_socket_local_id_request(
                    self.upstream_proto,
                    self.upstream_source_id_request,
                    self.upstream_reply_id_request,
                ),
                timeout_act: self.timeout_action,
                debug_unconnected: self.upstream_debug_unconnected,
                force_raw_wildcard_icmp: self.force_raw_icmp_wildcard_upstream,
                allow_debug_kernel_echo_self_handshake: self
                    .upstream_icmp_kernel_echo_self_handshake,
                debug_handles: self.debug_handles,
            })?;
        let parser = select_packet_parser(
            self.upstream_proto,
            socket2::Domain::for_address(kernel_addr),
            policy,
        )?;
        let update = if family_changed(
            state.upstream_remote_filter.to_socket_addr(),
            remote_filter.to_socket_addr(),
        ) {
            SocketUpdateKind::ReplacedCrossFamily
        } else {
            SocketUpdateKind::Replaced
        };
        Ok(PreparedUpstreamReplacement {
            socket,
            metadata: Arc::new(UpstreamMetadata {
                upstream_remote_filter: remote_filter,
                upstream_local_filter: local_filter,
                upstream_local_kernel_addr: kernel_addr,
                evidence_key: state.evidence_key.replacement(kernel_addr),
                upstream_flow: upstream_leg_flow(
                    local_filter,
                    self.upstream_source_id_request,
                    remote_filter,
                ),
                sock_type,
                policy,
                parser,
            }),
            update,
        })
    }

    fn prepare_upstream_reresolve(
        &self,
        state: &UpstreamState,
        resolved: Option<SocketAddr>,
        preserve_logical_id: bool,
    ) -> io::Result<UpstreamReresolvePlan> {
        let Some(resolved) = resolved else {
            return Ok(UpstreamReresolvePlan::Unchanged);
        };
        let previous = state.upstream_remote_filter;
        let fresh = if preserve_logical_id {
            previous.with_resolved_ip(resolved)
        } else {
            LogicalEndpoint::from_socket_addr(resolved)
        };
        let (_, action) = decide_upstream_endpoint_update(
            previous,
            fresh,
            state.sock.is_connected(),
            state.policy,
        );
        match action {
            ReresolveAction::NoChange => Ok(UpstreamReresolvePlan::Unchanged),
            ReresolveAction::UpdateMetadataOnly => {
                let mut metadata = state.metadata.as_ref().clone();
                metadata.upstream_remote_filter = fresh;
                metadata.upstream_flow = upstream_leg_flow(
                    metadata.upstream_local_filter,
                    self.upstream_source_id_request,
                    fresh,
                );
                Ok(UpstreamReresolvePlan::Metadata(Arc::new(metadata)))
            }
            ReresolveAction::ReconnectInPlace => {
                let fallback = self.prepare_upstream_replacement(state, fresh)?;
                Ok(UpstreamReresolvePlan::Reconnect {
                    destination: fresh,
                    fallback,
                })
            }
            ReresolveAction::ReplaceSocket => Ok(UpstreamReresolvePlan::Replace(
                self.prepare_upstream_replacement(state, fresh)?,
            )),
        }
    }

    fn apply_upstream_reresolve(
        &self,
        state: &UpstreamState,
        plan: UpstreamReresolvePlan,
    ) -> AppliedUpstreamPlan {
        let mut journal = TransactionJournalEntry {
            socket_slot: self.socket_slot,
            leg: TransactionLeg::Upstream,
            transition_attempted: false,
            transition_completed: false,
            recovery: RecoveryOutcome::NotRequired,
            forced_replacement: false,
            recovery_version: None,
        };
        match plan {
            UpstreamReresolvePlan::Unchanged => AppliedUpstreamPlan {
                socket: None,
                metadata: None,
                update: SocketUpdateKind::Unchanged,
                journal,
            },
            UpstreamReresolvePlan::Metadata(metadata) => AppliedUpstreamPlan {
                socket: None,
                metadata: Some(metadata),
                update: SocketUpdateKind::MetadataUpdated,
                journal,
            },
            UpstreamReresolvePlan::Replace(replacement) => AppliedUpstreamPlan {
                socket: Some(replacement.socket),
                metadata: Some(replacement.metadata),
                update: replacement.update,
                journal,
            },
            UpstreamReresolvePlan::Reconnect {
                destination,
                fallback,
            } => {
                journal.transition_attempted = true;
                let reconnected = state
                    .sock
                    .reconnect_connected(destination.to_socket_addr())
                    .map_err(|error| error.to_string())
                    .and_then(|()| state.sock.local_addr().map_err(|error| error.to_string()));
                match reconnected {
                    Ok(local_addr) => {
                        let Some(kernel_addr) = local_addr.as_socket() else {
                            journal.transition_completed = true;
                            journal.recovery = RecoveryOutcome::Replaced;
                            journal.forced_replacement = true;
                            return AppliedUpstreamPlan {
                                socket: Some(fallback.socket),
                                metadata: Some(fallback.metadata),
                                update: fallback.update,
                                journal,
                            };
                        };
                        journal.transition_completed = true;
                        let mut metadata = state.metadata.as_ref().clone();
                        let requested_local_id = Self::upstream_socket_local_id_request(
                            self.upstream_proto,
                            self.upstream_source_id_request,
                            self.upstream_reply_id_request,
                        );
                        let local_filter = self.normalized_upstream_local_after_getsockname(
                            requested_local_id,
                            destination,
                            kernel_addr,
                            metadata.policy,
                        );
                        metadata.upstream_remote_filter = destination;
                        metadata.upstream_local_filter = local_filter;
                        metadata.upstream_local_kernel_addr = kernel_addr;
                        metadata.upstream_flow = upstream_leg_flow(
                            local_filter,
                            self.upstream_source_id_request,
                            destination,
                        );
                        AppliedUpstreamPlan {
                            socket: None,
                            metadata: Some(Arc::new(metadata)),
                            update: SocketUpdateKind::ReconnectedInPlace,
                            journal,
                        }
                    }
                    Err(error) => {
                        log_info!(
                            "upstream {} reconnect failed ({}); using prepared replacement",
                            destination,
                            error
                        );
                        journal.recovery = RecoveryOutcome::Replaced;
                        journal.forced_replacement = true;
                        AppliedUpstreamPlan {
                            socket: Some(fallback.socket),
                            metadata: Some(fallback.metadata),
                            update: fallback.update,
                            journal,
                        }
                    }
                }
            }
        }
    }

    /// Re-resolve both ends and publish any changes. When `allow_listen_rebind`
    /// is true, the listening socket may be swapped if the --here DNS changes.
    /// Returns handles and a flag indicating whether the listener changed.
    pub fn reresolve(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
    ) -> Result<SocketHandles, ManagerError> {
        self.reresolve_with_addresses(allow_upstream, allow_listen_rebind, context, None, None)
            .map(|summary| summary.handles)
    }

    pub(crate) fn reresolve_with_addresses(
        &self,
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
        listen_addr: Option<SocketAddr>,
        upstream_addr: Option<SocketAddr>,
    ) -> Result<ReresolveSummary, ManagerError> {
        let mut summaries = Self::reresolve_group_with_addresses(
            &[self],
            allow_upstream,
            allow_listen_rebind,
            context,
            listen_addr,
            upstream_addr,
            |_| {},
        )?;
        Ok(summaries
            .pop()
            .expect("single-manager re-resolution returns one summary"))
    }

    pub(crate) fn reresolve_group_with_addresses(
        managers: &[&Self],
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
        listen_addr: Option<SocketAddr>,
        upstream_addr: Option<SocketAddr>,
        commit_observer: impl FnOnce(&[ReresolveSummary]),
    ) -> Result<Vec<ReresolveSummary>, ManagerError> {
        Self::reresolve_group_with_observers(
            managers,
            allow_upstream,
            allow_listen_rebind,
            context,
            listen_addr,
            upstream_addr,
            |_| {},
            |_| {},
            commit_observer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reresolve_group_with_observers(
        managers: &[&Self],
        allow_upstream: bool,
        allow_listen_rebind: bool,
        context: &str,
        listen_addr: Option<SocketAddr>,
        upstream_addr: Option<SocketAddr>,
        mut before_transition: impl FnMut(u32),
        mut after_transition: impl FnMut(u32),
        commit_observer: impl FnOnce(&[ReresolveSummary]),
    ) -> Result<Vec<ReresolveSummary>, ManagerError> {
        let preserve_listener_id = listen_addr.is_none();
        let preserve_upstream_id = upstream_addr.is_none();
        let mut ordered = managers.to_vec();
        ordered.sort_unstable_by_key(|manager| manager.socket_slot);
        if ordered
            .windows(2)
            .any(|pair| pair[0].socket_slot == pair[1].socket_slot)
        {
            return Err(ManagerError::io(
                "prepare grouped re-resolution",
                io::Error::other("duplicate socket slot in re-resolution transaction"),
            ));
        }

        // Name resolution is external work and must finish before any manager
        // transaction lock is acquired.
        let resolved = ordered
            .iter()
            .map(|manager| {
                let listener = if allow_listen_rebind {
                    Some(match listen_addr {
                        Some(address) => address,
                        None => resolve_first(&manager.listen_target)
                            .map_err(|error| ManagerError::io("resolve listener", error))?,
                    })
                } else {
                    None
                };
                let upstream = if allow_upstream {
                    Some(match upstream_addr {
                        Some(address) => address,
                        None => resolve_first(&manager.upstream_target)
                            .map_err(|error| ManagerError::io("resolve upstream", error))?,
                    })
                } else {
                    None
                };
                Ok((listener, upstream))
            })
            .collect::<Result<Vec<_>, ManagerError>>()?;

        let transactions = ordered
            .iter()
            .map(|manager| manager.lock_transaction())
            .collect::<Vec<_>>();
        let mut listeners = ordered
            .iter()
            .map(|manager| manager.client_listen.lock().unwrap())
            .collect::<Vec<_>>();
        let mut upstreams = ordered
            .iter()
            .map(|manager| manager.upstream_state.lock().unwrap())
            .collect::<Vec<_>>();
        let old_state = listeners
            .iter()
            .zip(&upstreams)
            .map(|(listener, upstream)| {
                (listener.flow, listener.evidence_key, upstream.evidence_key)
            })
            .collect::<Vec<_>>();

        let changed = ordered
            .iter()
            .zip(&listeners)
            .zip(&upstreams)
            .zip(&resolved)
            .map(|(((manager, listener), upstream), (listen, up))| {
                let listener_changed = listen.is_some_and(|address| {
                    let fresh = if preserve_listener_id {
                        listener.listen_local_filter.with_resolved_ip(address)
                    } else {
                        LogicalEndpoint::from_socket_addr(address)
                    };
                    decide_listener_endpoint_update(listener.listen_local_filter, fresh).1
                        != ReresolveAction::NoChange
                });
                let upstream_changed = up.is_some_and(|address| {
                    let fresh = if preserve_upstream_id {
                        upstream.upstream_remote_filter.with_resolved_ip(address)
                    } else {
                        LogicalEndpoint::from_socket_addr(address)
                    };
                    decide_upstream_endpoint_update(
                        upstream.upstream_remote_filter,
                        fresh,
                        upstream.sock.is_connected(),
                        upstream.policy,
                    )
                    .1 != ReresolveAction::NoChange
                });
                let _ = manager;
                listener_changed || upstream_changed
            })
            .collect::<Vec<_>>();
        let mut capacities = ordered
            .iter()
            .zip(&transactions)
            .zip(&changed)
            .map(|((manager, transaction), changed)| {
                changed
                    .then(|| manager.precheck_version_capacity(transaction))
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // All constructors and parser selection complete before any live
        // reconnect. From this point onward each reconnect either succeeds or
        // installs its already prepared replacement.
        let listener_plans = ordered
            .iter()
            .zip(&listeners)
            .zip(&resolved)
            .map(|((manager, listener), (resolved_listener, _))| {
                manager
                    .prepare_listener_reresolve(listener, *resolved_listener, preserve_listener_id)
                    .map_err(|error| ManagerError::io("prepare listener re-resolution", error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let upstream_plans = ordered
            .iter()
            .zip(&upstreams)
            .zip(&resolved)
            .map(|((manager, upstream), (_, resolved_upstream))| {
                manager
                    .prepare_upstream_reresolve(upstream, *resolved_upstream, preserve_upstream_id)
                    .map_err(|error| ManagerError::io("prepare upstream re-resolution", error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut applied_upstreams = Vec::with_capacity(ordered.len());
        for ((manager, upstream), plan) in ordered.iter().zip(&upstreams).zip(upstream_plans) {
            if matches!(plan, UpstreamReresolvePlan::Reconnect { .. }) {
                before_transition(manager.socket_slot);
            }
            let applied = manager.apply_upstream_reresolve(upstream, plan);
            if applied.journal.transition_attempted {
                after_transition(manager.socket_slot);
            }
            applied_upstreams.push(applied);
        }

        let mut listener_updates = Vec::with_capacity(ordered.len());
        for ((manager, listener), plan) in ordered.iter().zip(&mut listeners).zip(listener_plans) {
            let update = match plan {
                ListenerReresolvePlan::Unchanged => SocketUpdateKind::Unchanged,
                ListenerReresolvePlan::Replace(replacement) => {
                    log_info!(
                        "{context}: listen {} (listener swapped)",
                        replacement.metadata.listen_local_filter
                    );
                    listener.sock = replacement.socket;
                    listener.metadata = replacement.metadata;
                    replacement.update
                }
            };
            if manager.debug_handles && update.changed() {
                log_debug!(
                    true,
                    "socket-evidence {}",
                    socket_evidence_json(
                        listener.evidence_key,
                        update.wire_name(),
                        &manager.listen_target,
                        listener.listen_local_kernel_addr,
                    )
                );
            }
            listener_updates.push(update);
        }

        for (index, (((manager, upstream), applied), expected_changed)) in ordered
            .iter()
            .zip(&mut upstreams)
            .zip(&mut applied_upstreams)
            .zip(&changed)
            .enumerate()
        {
            if let Some(socket) = applied.socket.take() {
                upstream.sock = socket;
            }
            if let Some(metadata) = applied.metadata.take() {
                upstream.metadata = metadata;
            }
            assert_eq!(
                listener_updates[index].changed() || applied.update.changed(),
                *expected_changed,
                "re-resolution plan changed while manager transactions were held"
            );
            if applied.update.changed() {
                log_info!(
                    "{context}: upstream {} ({})",
                    upstream.upstream_remote_filter,
                    applied.update.wire_name()
                );
            }
            if manager.debug_handles && applied.update.changed() {
                log_debug!(
                    true,
                    "socket-evidence {}",
                    socket_evidence_json(
                        upstream.evidence_key,
                        applied.update.wire_name(),
                        &manager.upstream_target,
                        upstream.upstream_local_kernel_addr,
                    )
                );
            }
        }

        let mut summaries = Vec::with_capacity(ordered.len());
        for index in 0..ordered.len() {
            let manager = ordered[index];
            let version = match capacities[index].take() {
                Some(capacity) => manager.publish_prechecked(&transactions[index], capacity),
                None => manager.current_version(),
            };
            if applied_upstreams[index].journal.recovery == RecoveryOutcome::Replaced {
                applied_upstreams[index].journal.recovery_version = Some(version);
            }
            if applied_upstreams[index].journal.transition_attempted {
                log_debug!(
                    manager.debug_handles,
                    "re-resolution transaction journal: {:?}",
                    applied_upstreams[index].journal
                );
            }
            let handles = SocketHandles {
                listener: Arc::clone(&listeners[index].metadata),
                client_sock: listeners[index].sock.clone(),
                upstream: Arc::clone(&upstreams[index].metadata),
                upstream_sock: upstreams[index].sock.clone(),
                version,
            };
            summaries.push(ReresolveSummary {
                socket_slot: manager.socket_slot,
                old_locked_flow: old_state[index].0,
                old_listener_key: old_state[index].1,
                new_listener_key: handles.listener.evidence_key,
                old_upstream_key: old_state[index].2,
                new_upstream_key: handles.upstream.evidence_key,
                handles,
                listener_update: listener_updates[index],
                upstream_update: applied_upstreams[index].update,
            });
        }
        commit_observer(&summaries);
        Ok(summaries)
    }
}
