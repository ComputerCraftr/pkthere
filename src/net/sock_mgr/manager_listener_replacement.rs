use super::manager_types::SocketManager;
use crate::flow_key::SocketLegFlow;
use crate::net::managed_socket::{AssociationOperation, AssociationState, TopologyReservation};
use crate::net::packet_headers::select_packet_parser;
use crate::net::sock_mgr::manager::socket_evidence_json;
use crate::net::sock_mgr::state::{ClientListenState, ListenerMetadata};
use crate::net::socket::{make_socket, resolve_first};
use std::io;
use std::net::SocketAddr;

impl SocketManager {
    pub(super) fn replace_listener_after_transition_failure(
        &self,
        state: &mut ClientListenState,
    ) -> io::Result<()> {
        // Recreate the requested bind, not the realized kernel address. In
        // particular, a requested `:0` must obtain a fresh ephemeral port
        // while stale clones may still own the failed descriptor.
        let requested_bind = resolve_first(&self.listen_target)?;
        if matches!(state.sock.association(), AssociationState::Retired { .. }) {
            return self.build_listener_bound_to(state, requested_bind);
        }
        self.replace_listener_bound_to(state, requested_bind)
    }

    pub(super) fn build_listener_replacement_on_clear(
        &self,
        state: &mut ClientListenState,
    ) -> io::Result<TopologyReservation> {
        let bound_listener = state.listen_local_filter.to_socket_addr();
        self.build_listener_bound_to(state, bound_listener)?;
        state
            .sock
            .reserve_topology(AssociationOperation::Replace)
            .map_err(io::Error::other)
    }

    fn replace_listener_bound_to(
        &self,
        state: &mut ClientListenState,
        bind_addr: SocketAddr,
    ) -> io::Result<()> {
        // Close I/O admission before binding the same-port replacement. A
        // reuse-port socket becomes eligible for kernel delivery as soon as
        // bind succeeds, so preparing a bound socket before quiescence can
        // steal traffic from the still-authoritative descriptor.
        let reservation = state.sock.reserve_replacement().map_err(io::Error::other)?;
        reservation
            .into_retired_for_replacement()
            .and_then(crate::net::managed_socket::RetiredTopologyReservation::commit)
            .map_err(io::Error::other)?;
        self.build_listener_bound_to(state, bind_addr)?;
        state
            .sock
            .reserve_topology(AssociationOperation::Replace)
            .map_err(io::Error::other)?
            .commit_publication()
            .map_err(io::Error::other)
    }

    fn build_listener_bound_to(
        &self,
        state: &mut ClientListenState,
        bind_addr: SocketAddr,
    ) -> io::Result<()> {
        let replacement_evidence = state
            .evidence_key
            .replacement(bind_addr)
            .map_err(io::Error::other)?;
        let (replacement, logical_local, kernel_addr, socket_type, policy) = make_socket(
            bind_addr,
            self.listen_proto,
            self.listen_worker_socket_policy,
            self.timeout_action,
            self.listen_debug_unconnected,
            self.upstream_icmp_kernel_echo_self_handshake,
        )?;
        replacement
            .bind_authority_identity(
                pkthere_socket_policy::SocketRole::Listener,
                self.socket_slot,
                replacement_evidence.generation,
                true,
            )
            .map_err(io::Error::other)?;
        replacement
            .configure_worker_io_lanes(self.worker_io_lanes)
            .map_err(io::Error::other)?;
        let parser = select_packet_parser(
            self.listen_proto,
            socket2::Domain::for_address(kernel_addr),
            policy,
        )?;
        state.sock = replacement;
        state.listen_local_filter = logical_local;
        state.listen_local_kernel_addr = kernel_addr;
        state.evidence_key = replacement_evidence;
        state.sock_type = socket_type;
        state.policy = policy;
        state.parser = parser;
        state.flow = None;
        state.listener_flow = SocketLegFlow::empty();
        Ok(())
    }

    pub(crate) fn log_listener_replacement_evidence(
        &self,
        listener: &ListenerMetadata,
        operation: &'static str,
    ) {
        if self.debug_handles {
            log_debug!(
                true,
                "socket-evidence {}",
                socket_evidence_json(
                    listener.evidence_key,
                    operation,
                    &self.listen_target,
                    listener.listen_local_kernel_addr,
                )
            );
        }
    }
}
