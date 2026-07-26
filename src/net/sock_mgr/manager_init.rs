use super::manager::{socket_evidence_json, upstream_leg_flow};
use super::manager_types::SocketManager;
use super::receiver_slot::{ReceiverRegistry, ReceiverRole};
use super::state::{ClientListenState, ListenerMetadata, UpstreamMetadata, UpstreamState};
use super::transaction_lock::ManagerTransaction;
use super::version::VersionClock;
use super::{SharedUpstreamIdentity, SocketManagerInit};
use crate::cli::IcmpReplyIdRequest;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::SocketLegFlow;
use crate::net::packet_headers::select_packet_parser;
use crate::net::socket::{RealizedUpstreamSocket, UpstreamSocketRequest, make_upstream_socket_for};
use pkthere_socket_policy::{SocketEvidenceKey, SocketRole};
use std::io;
use std::sync::Arc;

impl SocketManager {
    pub fn new(init: SocketManagerInit) -> io::Result<Self> {
        let (effective_remote, effective_source_request, effective_reply_request) =
            effective_upstream_request(&init)?;
        let realized = make_upstream_socket_for(UpstreamSocketRequest {
            dest: effective_remote,
            proto: init.upstream_proto,
            req_local_id: Self::upstream_socket_local_id_request(
                init.upstream_proto,
                effective_source_request,
                effective_reply_request,
            ),
            timeout_act: init.timeout_act,
            debug_unconnected: init.upstream_debug_unconnected,
            force_raw_wildcard_icmp: init.force_raw_icmp_wildcard_upstream,
            allow_debug_kernel_echo_self_handshake: init.upstream_icmp_kernel_echo_self_handshake,
            worker_socket_policy: init.upstream_worker_socket_policy,
            authority_identity: Some((init.socket_slot, 1, false)),
        })?;
        Self::from_realized_upstream(init, realized)
    }

    /// Publish a descriptor realization through the same manager ownership,
    /// parser, identity, and receiver-registration path used at startup.
    /// Socket creation and socket publication are deliberately separate
    /// authorities: reality probes own the former, while the manager owns the
    /// latter.
    pub(crate) fn from_realized_upstream(
        init: SocketManagerInit,
        realized: RealizedUpstreamSocket,
    ) -> io::Result<Self> {
        let SocketManagerInit {
            socket_slot,
            worker_io_lanes,
            client_sock,
            listen_local_filter,
            listen_local_kernel_addr,
            listen_sock_type,
            listen_target,
            listen_proto,
            listen_policy,
            listen_worker_socket_policy,
            listen_debug_unconnected,
            upstream_remote_filter,
            upstream_target,
            upstream_source_id_request,
            upstream_reply_id_request,
            upstream_proto,
            upstream_debug_unconnected,
            upstream_icmp_kernel_echo_self_handshake,
            upstream_worker_socket_policy,
            shared_upstream_identity,
            force_raw_icmp_wildcard_upstream,
            timeout_act,
            debug_handles,
        } = init;
        let temporary_init = EffectiveUpstreamInput {
            upstream_remote_filter,
            upstream_source_id_request,
            upstream_reply_id_request,
            upstream_worker_socket_policy,
            shared_upstream_identity: shared_upstream_identity.as_ref(),
        };
        let (effective_upstream_remote, effective_source_request, _effective_reply_request) =
            temporary_init.resolve()?;
        let listen_parser = select_packet_parser(
            listen_proto,
            socket2::Domain::for_address(listen_local_kernel_addr),
            listen_policy,
        )?;
        let RealizedUpstreamSocket {
            socket: sock,
            local_filter: upstream_local,
            remote_filter: upstream_remote,
            local_kernel_addr: upstream_local_kernel_addr,
            socket_type: upstream_sock_type,
            policy: upstream_policy,
        } = realized;
        if upstream_remote.ip() != effective_upstream_remote.ip() {
            return Err(io::Error::other(
                "realized upstream descriptor belongs to a different remote address",
            ));
        }
        let upstream_flow =
            upstream_leg_flow(upstream_local, effective_source_request, upstream_remote);
        let realized_shared_identity = SharedUpstreamIdentity {
            source_id: upstream_flow
                .outbound
                .ok_or_else(|| io::Error::other("upstream flow omitted its outbound identity"))?
                .src
                .id(),
            reply_id: upstream_local.id(),
            remote_id: upstream_remote.id(),
        };
        if upstream_worker_socket_policy.shares_icmp_identity()
            && (realized_shared_identity.source_id == 0
                || realized_shared_identity.reply_id == 0
                || realized_shared_identity.remote_id == 0)
        {
            return Err(io::Error::other(
                "shared ICMP upstream identity must be fully realized and nonzero",
            ));
        }
        if let Some(identity) = shared_upstream_identity {
            if let Some(existing) = identity.get() {
                if *existing != realized_shared_identity {
                    return Err(io::Error::other(format!(
                        "upstream worker realized identity {realized_shared_identity:?} instead of shared identity {existing:?}"
                    )));
                }
            } else {
                identity.set(realized_shared_identity).map_err(|observed| {
                    io::Error::other(format!(
                        "shared upstream identity was concurrently initialized as {observed:?}"
                    ))
                })?;
            }
        }
        let stored_source_request = if upstream_worker_socket_policy.shares_icmp_identity() {
            IcmpReplyIdRequest::Fixed(realized_shared_identity.source_id)
        } else {
            upstream_source_id_request
        };
        let stored_reply_request = if upstream_worker_socket_policy.shares_icmp_identity() {
            IcmpReplyIdRequest::Fixed(realized_shared_identity.reply_id)
        } else {
            upstream_reply_id_request
        };
        let upstream_parser = select_packet_parser(
            upstream_proto,
            socket2::Domain::for_address(upstream_local_kernel_addr),
            upstream_policy,
        )?;
        let listen_evidence_key =
            SocketEvidenceKey::initial(SocketRole::Listener, socket_slot, listen_local_kernel_addr);
        let upstream_evidence_key = SocketEvidenceKey::initial(
            SocketRole::Upstream,
            socket_slot,
            upstream_local_kernel_addr,
        );
        client_sock
            .bind_authority_identity(
                SocketRole::Listener,
                socket_slot,
                listen_evidence_key.generation,
                false,
            )
            .map_err(io::Error::other)?;
        sock.bind_authority_identity(
            SocketRole::Upstream,
            socket_slot,
            upstream_evidence_key.generation,
            false,
        )
        .map_err(io::Error::other)?;
        client_sock
            .configure_worker_io_lanes(worker_io_lanes)
            .map_err(io::Error::other)?;
        sock.configure_worker_io_lanes(worker_io_lanes)
            .map_err(io::Error::other)?;
        if debug_handles {
            log_debug!(
                true,
                "socket-evidence {}",
                socket_evidence_json(
                    listen_evidence_key,
                    "create",
                    &listen_target,
                    listen_local_kernel_addr,
                )
            );
            log_debug!(
                true,
                "socket-evidence {}",
                socket_evidence_json(
                    upstream_evidence_key,
                    "create",
                    &upstream_target,
                    upstream_local_kernel_addr,
                )
            );
        }
        let manager = Self {
            transaction: ManagerTransaction::new(u64::from(socket_slot) + 1),
            socket_slot,
            worker_io_lanes,
            listener_receiver: ReceiverRegistry::new(
                ReceiverRole::Listener,
                socket_slot,
                &client_sock,
            ),
            client_listen: crate::authority::AuthorityMutex::new(
                ClientListenState {
                    sock: client_sock,
                    metadata: Arc::new(ListenerMetadata {
                        listen_local_filter,
                        listen_local_kernel_addr,
                        evidence_key: listen_evidence_key,
                        flow: None,
                        listener_flow: SocketLegFlow::empty(),
                        sock_type: listen_sock_type,
                        policy: listen_policy,
                        parser: listen_parser,
                    }),
                },
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::ManagerState,
                    flow: 0,
                    direction: 0,
                    kind: 0,
                    session: u64::from(socket_slot) + 1,
                },
            ),
            listen_target,
            listen_proto,
            listen_debug_unconnected,
            listen_worker_socket_policy,
            upstream_receiver: ReceiverRegistry::new(ReceiverRole::Upstream, socket_slot, &sock),
            upstream_state: crate::authority::AuthorityMutex::new(
                UpstreamState {
                    sock,
                    metadata: Arc::new(UpstreamMetadata {
                        upstream_remote_filter: upstream_remote,
                        upstream_local_filter: upstream_local,
                        upstream_local_kernel_addr,
                        evidence_key: upstream_evidence_key,
                        upstream_flow,
                        sock_type: upstream_sock_type,
                        policy: upstream_policy,
                        parser: upstream_parser,
                    }),
                },
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::ManagerState,
                    flow: 0,
                    direction: 1,
                    kind: 0,
                    session: u64::from(socket_slot) + 1,
                },
            ),
            upstream_target,
            upstream_source_id_request: stored_source_request,
            upstream_reply_id_request: stored_reply_request,
            upstream_proto,
            upstream_debug_unconnected,
            upstream_icmp_kernel_echo_self_handshake,
            upstream_worker_socket_policy,
            force_raw_icmp_wildcard_upstream,
            debug_handles,
            timeout_action: timeout_act,
            version: VersionClock::new(),
        };
        for authority in [
            manager.client_listen.prewarm(),
            manager.upstream_state.prewarm(),
        ] {
            authority.map_err(|error| {
                io::Error::other(format!("socket-manager authority prewarm failed: {error}"))
            })?;
        }
        Ok(manager)
    }
}

struct EffectiveUpstreamInput<'a> {
    upstream_remote_filter: LogicalEndpoint,
    upstream_source_id_request: IcmpReplyIdRequest,
    upstream_reply_id_request: IcmpReplyIdRequest,
    upstream_worker_socket_policy: pkthere_socket_policy::UpstreamWorkerSocketPolicy,
    shared_upstream_identity: Option<
        &'a Arc<
            crate::authority::AuthorityOnceLock<
                crate::authority::tags::IdentityAllocation,
                SharedUpstreamIdentity,
            >,
        >,
    >,
}

impl EffectiveUpstreamInput<'_> {
    fn resolve(self) -> io::Result<(LogicalEndpoint, IcmpReplyIdRequest, IcmpReplyIdRequest)> {
        if self.upstream_worker_socket_policy.shares_icmp_identity()
            && self.shared_upstream_identity.is_none()
        {
            return Err(io::Error::other(
                "shared ICMP upstream policy requires one shared identity authority",
            ));
        }
        let pinned = self
            .shared_upstream_identity
            .and_then(|identity| identity.get())
            .copied();
        Ok((
            pinned.map_or(self.upstream_remote_filter, |identity| {
                self.upstream_remote_filter.with_id(identity.remote_id)
            }),
            pinned.map_or(self.upstream_source_id_request, |identity| {
                IcmpReplyIdRequest::Fixed(identity.source_id)
            }),
            pinned.map_or(self.upstream_reply_id_request, |identity| {
                IcmpReplyIdRequest::Fixed(identity.reply_id)
            }),
        ))
    }
}

fn effective_upstream_request(
    init: &SocketManagerInit,
) -> io::Result<(LogicalEndpoint, IcmpReplyIdRequest, IcmpReplyIdRequest)> {
    EffectiveUpstreamInput {
        upstream_remote_filter: init.upstream_remote_filter,
        upstream_source_id_request: init.upstream_source_id_request,
        upstream_reply_id_request: init.upstream_reply_id_request,
        upstream_worker_socket_policy: init.upstream_worker_socket_policy,
        shared_upstream_identity: init.shared_upstream_identity.as_ref(),
    }
    .resolve()
}
