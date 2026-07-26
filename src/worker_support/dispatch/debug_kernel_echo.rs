use super::{
    FlowRuntimeState, IcmpSequenceCache, PayloadEvent, RuntimeConfig, SharedIcmpSequenceState,
    SocketHandles, reflected_kernel_echo_negotiation_matches,
};

#[inline]
pub(super) fn debug_kernel_echo_self_handshake_ack(
    cfg: &RuntimeConfig,
    c2u: bool,
    event: &PayloadEvent<'_>,
    handles: &SocketHandles,
) -> bool {
    if !cfg.debug_behavior.icmp_kernel_echo_self_handshake
        || c2u
        || cfg.upstream_proto != crate::cli::SupportedProtocol::ICMP
        || handles
            .upstream
            .policy
            .icmp
            .is_some_and(|policy| policy.can_honor_disjoint_ids())
    {
        return false;
    }
    let PayloadEvent::SessionControl { icmp, .. } = event else {
        return false;
    };
    reflected_kernel_echo_negotiation_matches(icmp, handles.upstream.upstream_local_filter.id())
}

pub(crate) fn activate_upstream_receive_session(
    cfg: &RuntimeConfig,
    flow_state: &FlowRuntimeState,
    flow_transaction: Option<&crate::flow_state::ClientFlowReservation<'_>>,
    sequence_state: &SharedIcmpSequenceState,
    sequence_cache: &mut IcmpSequenceCache,
    transmit_session: crate::net::framing_shim::SessionId,
) -> std::io::Result<()> {
    let receive_session = if cfg.debug_behavior.icmp_kernel_echo_self_handshake {
        if let Some(flow_transaction) = flow_transaction {
            flow_state
                .use_reflected_upstream_session_for_debug_under(flow_transaction)
                .map_err(std::io::Error::other)?;
        } else {
            let flow_transaction = flow_state
                .try_reserve_client_flow()
                .map_err(std::io::Error::other)?;
            flow_state
                .use_reflected_upstream_session_for_debug_under(&flow_transaction)
                .map_err(std::io::Error::other)?;
        }
        transmit_session
    } else {
        transmit_session.response_session_id().ok_or_else(|| {
            std::io::Error::other(
                "negotiated transmit session does not reserve a response identity",
            )
        })?
    };
    crate::net::icmp_sequence::activate_receive_session(
        sequence_state,
        sequence_cache,
        receive_session,
    );
    Ok(())
}
