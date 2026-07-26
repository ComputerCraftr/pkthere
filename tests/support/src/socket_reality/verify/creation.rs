use super::implementation::error;
use super::model::VerificationError;
use crate::socket_reality::case::{
    ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation, RealitySocketPath,
};
use pkthere_socket_policy::{
    IpHeaderMode, Ipv4HeaderAction, ReceiveCaptureScope, ResolvedSocketPolicy, SocketCaptureAction,
    SocketCreationPlan, SocketRole, listener_socket_creation_policy, listener_socket_setup_policy,
    listener_worker_socket_policy, socket_post_bind_policy, upstream_socket_creation_policy,
};
use socket2::Domain;

pub(super) fn verify_creation_policy(
    requested: RealityCase,
    behavior: ResolvedSocketPolicy,
) -> Result<SocketCreationPlan, VerificationError> {
    let production = production_creation_policy(requested);

    if behavior.creation_path != requested.socket_path {
        return Err(error(format!(
            "resolved socket behavior path {:?} does not match collected path {:?}",
            behavior.creation_path, requested.socket_path
        )));
    }

    let setup_path = requested.socket_path;
    let post_bind = if requested.policy_role == SocketRole::Listener {
        let setup =
            listener_socket_setup_policy(listener_worker_socket_policy(1, false), setup_path);
        if !setup.bind_requested_address {
            return Err(error(
                "production listener setup policy omitted the requested-address bind",
            ));
        }
        setup.post_bind
    } else {
        socket_post_bind_policy(setup_path)
    };
    let capture_enabled = post_bind.capture == SocketCaptureAction::WindowsReceiveAllIp;
    let header_included = post_bind.ipv4_header == Ipv4HeaderAction::ApplicationIncluded;
    if capture_enabled != header_included {
        return Err(error(
            "Windows protocol-zero capture policy must couple SIO_RCVALL and IP_HDRINCL",
        ));
    }
    if capture_enabled
        && (requested.socket_path != RealitySocketPath::WindowsProtocolZeroCapture
            || requested.domain != Domain::IPV4)
    {
        return Err(error(
            "Windows capture setup was selected outside the IPv4 protocol-zero path",
        ));
    }
    if header_included && behavior.send_policy.ip_header != IpHeaderMode::Ipv4HeaderIncluded {
        return Err(error(
            "socket creation requires IP_HDRINCL but send policy omits the IPv4 header",
        ));
    }
    let expected_capture_scope = if capture_enabled {
        ReceiveCaptureScope::InterfaceIpv4
    } else {
        ReceiveCaptureScope::ProtocolFiltered
    };
    if behavior.receive_capture_scope != expected_capture_scope {
        return Err(error(format!(
            "resolved receive capture scope {:?} does not match post-bind policy {:?}",
            behavior.receive_capture_scope, post_bind
        )));
    }
    Ok(production)
}

pub(super) fn production_creation_policy(case: RealityCase) -> SocketCreationPlan {
    if case.policy_role == SocketRole::Listener {
        return listener_socket_creation_policy(case.protocol, case.domain);
    }

    let (remote_id, local_id) = match case.operation {
        RealityOperation::IcmpDgramFixedId | RealityOperation::IcmpDgramSharedId => {
            (ICMP_DGRAM_FIXED_ID, ICMP_DGRAM_FIXED_ID)
        }
        RealityOperation::RawReceiveEvidence
        | RealityOperation::RawFourIdForwarding
        | RealityOperation::SocketDisconnect
            if case.socket_type == socket2::Type::RAW =>
        {
            (0x6111, 0x5222)
        }
        _ => (0, 0),
    };
    upstream_socket_creation_policy(case.protocol, case.domain, remote_id, local_id, false)
}
