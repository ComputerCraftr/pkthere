use crate::cli::{IcmpReplyIdRequest, SupportedProtocol};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::flow_state::PendingIcmpClientLock;
use crate::net::payload::PayloadEvent;

#[inline]
fn lockable_icmp_meta<'event>(
    event: &'event PayloadEvent<'_>,
) -> Option<&'event crate::net::payload::IcmpPayloadMeta> {
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => Some(icmp),
        PayloadEvent::SessionControl { icmp, .. } => Some(icmp),
        PayloadEvent::UserPayload { icmp: None, .. } | PayloadEvent::CadencePacket { .. } => None,
    }
}

#[inline]
pub(super) fn event_advertised_reply_id(event: &PayloadEvent<'_>) -> Option<u16> {
    lockable_icmp_meta(event).and_then(|icmp| icmp.advertised_reply_id())
}

#[inline]
pub(super) fn build_client_lock_candidate(
    src: LogicalEndpoint,
    listen_local_recv: LogicalEndpoint,
    listener_source_id_request: IcmpReplyIdRequest,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> Option<PendingIcmpClientLock> {
    let flow_key = client_flow_key_from_event(src, listen_proto, event)?;
    let remote = match listen_proto {
        SupportedProtocol::UDP => src,
        SupportedProtocol::ICMP => src.with_id(
            lockable_icmp_meta(event)?
                .flow_identity()
                .remote_source_id(),
        ),
    };
    let inbound_local = match listen_proto {
        SupportedProtocol::UDP => listen_local_recv,
        SupportedProtocol::ICMP => {
            listen_local_recv.with_id(lockable_icmp_meta(event)?.inbound_header_ident())
        }
    };
    let outbound_local = match listen_proto {
        SupportedProtocol::UDP => listen_local_recv,
        SupportedProtocol::ICMP => {
            let icmp = lockable_icmp_meta(event)?;
            listen_local_recv.with_id(
                match listener_source_id_request.resolved_reply_id(icmp.inbound_header_ident()) {
                    Some(id) => id,
                    None => icmp.inbound_header_ident(),
                },
            )
        }
    };
    let control = event.icmp_meta().and_then(|icmp| icmp.control());
    let (session_key, reset_challenge, reset_evidence) = match control {
        Some(crate::net::framing_shim::IcmpTunnelControl::Negotiate(negotiation)) => {
            (Some(negotiation.session_key()), 0, None)
        }
        Some(crate::net::framing_shim::IcmpTunnelControl::ChallengeNegotiate(challenge)) => (
            Some(challenge.new_session()),
            challenge.challenge().get(),
            Some(challenge.rejected()),
        ),
        _ => (None, 0, None),
    };
    let candidate = PendingIcmpClientLock {
        flow_key,
        session_key,
        observed_control: control.and_then(crate::flow_state::PendingClientControl::from_control),
        reset_challenge,
        reset_evidence,
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(remote, inbound_local)),
            Some(FlowTuple::new(
                outbound_local,
                outbound_remote_for_event(remote, listen_proto, event),
            )),
        ),
    };
    #[cfg(test)]
    crate::allocation_test_support::record_lock_candidate_construction();
    Some(candidate)
}

#[inline]
fn outbound_remote_for_event(
    remote: LogicalEndpoint,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> LogicalEndpoint {
    if listen_proto != SupportedProtocol::ICMP {
        return remote;
    }
    match lockable_icmp_meta(event) {
        Some(icmp) => {
            let reply_id = icmp
                .advertised_reply_id()
                .unwrap_or(icmp.flow_identity().remote_source_id());
            remote.with_id(reply_id)
        }
        None => remote,
    }
}

#[inline]
fn client_flow_key_from_event(
    src: LogicalEndpoint,
    listen_proto: SupportedProtocol,
    event: &PayloadEvent<'_>,
) -> Option<ClientFlowKey> {
    match listen_proto {
        SupportedProtocol::UDP => Some(ClientFlowKey::Udp(src)),
        SupportedProtocol::ICMP => lockable_icmp_meta(event).map(|icmp| {
            ClientFlowKey::from_icmp_reply_id(src, icmp.flow_identity().remote_source_id())
        }),
    }
}
