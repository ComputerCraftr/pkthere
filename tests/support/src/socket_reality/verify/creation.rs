use super::implementation::error;
use super::model::VerificationError;
use crate::socket_reality::case::{
    ICMP_DGRAM_FIXED_ID, RealityCase, RealityOperation, RealitySocketPath,
};
use pkthere_socket_policy::{
    IpHeaderMode, ResolvedSocketPolicy, SocketCreationPolicy, SocketRole,
    listener_socket_creation_policy, listener_socket_setup_policy, listener_worker_socket_policy,
    socket_post_bind_policy, upstream_socket_creation_policy,
};
use socket2::Domain;

pub(super) fn verify_creation_policy(
    requested: RealityCase,
    behavior: ResolvedSocketPolicy,
) -> Result<SocketCreationPolicy, VerificationError> {
    let production = production_creation_policy(requested);
    let requested_spec = requested.socket_create_spec();

    if requested_spec != production.primary && !is_windows_regular_raw_capability_case(requested) {
        return Err(error(format!(
            "socket-reality path {:?} does not match production creation path {:?}",
            requested_spec, production.primary
        )));
    }

    let post_bind = if requested.policy_role == SocketRole::Listener {
        let setup = listener_socket_setup_policy(
            listener_worker_socket_policy(1, false),
            production.primary.path,
        );
        if !setup.bind_requested_address {
            return Err(error(
                "production listener setup policy omitted the requested-address bind",
            ));
        }
        setup.post_bind
    } else {
        socket_post_bind_policy(production.primary.path)
    };
    if post_bind.enable_windows_rcvall != post_bind.set_ipv4_header_included {
        return Err(error(
            "Windows protocol-zero capture policy must couple SIO_RCVALL and IP_HDRINCL",
        ));
    }
    if post_bind.enable_windows_rcvall
        && (production.primary.path != RealitySocketPath::WindowsProtocolZeroCapture
            || production.primary.domain != Domain::IPV4)
    {
        return Err(error(
            "Windows capture setup was selected outside the IPv4 protocol-zero path",
        ));
    }
    if post_bind.set_ipv4_header_included
        && behavior.send_policy.ip_header != IpHeaderMode::Ipv4HeaderIncluded
    {
        return Err(error(
            "socket creation requires IP_HDRINCL but send policy omits the IPv4 header",
        ));
    }
    Ok(production)
}

fn production_creation_policy(case: RealityCase) -> SocketCreationPolicy {
    if case.policy_role == SocketRole::Listener {
        return listener_socket_creation_policy(case.protocol, case.domain);
    }

    let (remote_id, local_id) = match case.operation {
        RealityOperation::IcmpDgramFixedId => (ICMP_DGRAM_FIXED_ID, ICMP_DGRAM_FIXED_ID),
        RealityOperation::RawReceiveEvidence | RealityOperation::RawFourIdForwarding => {
            (0x6111, 0x5222)
        }
        _ => (0, 0),
    };
    upstream_socket_creation_policy(case.protocol, case.domain, remote_id, local_id, false)
}

fn is_windows_regular_raw_capability_case(case: RealityCase) -> bool {
    cfg!(windows)
        && case.operation == RealityOperation::RawReceiveEvidence
        && case.domain == Domain::IPV4
        && case.socket_path == RealitySocketPath::RawIcmp
        && production_creation_policy(case).primary.path
            == RealitySocketPath::WindowsProtocolZeroCapture
}
