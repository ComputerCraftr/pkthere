use crate::cli::SupportedProtocol;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::packet_headers::{ParsedNetworkLayer, ParsedTransport};
use crate::net::payload::PayloadEvent;
use crate::worker_support::packet_admission::SocketLeg;
use socket2::Type;

pub(super) fn protocol_name(proto: SupportedProtocol) -> &'static str {
    match proto {
        SupportedProtocol::UDP => "UDP",
        SupportedProtocol::ICMP => "ICMP",
    }
}

pub(super) fn socket_type_name(sock_type: Type) -> &'static str {
    if sock_type == Type::DGRAM {
        "DGRAM"
    } else if sock_type == Type::RAW {
        "RAW"
    } else if sock_type == Type::STREAM {
        "STREAM"
    } else {
        "OTHER"
    }
}

pub(super) fn role_name(role: SocketLeg) -> &'static str {
    match role {
        SocketLeg::ClientFacing => "client",
        SocketLeg::UpstreamFacing => "upstream",
    }
}

pub(super) fn transport_name(transport: ParsedTransport) -> &'static str {
    match transport {
        ParsedTransport::NotParsed => "NotParsed",
        ParsedTransport::UdpDatagram => "UdpDatagram",
        ParsedTransport::Icmp => "Icmp",
        ParsedTransport::Udp => "Udp",
        ParsedTransport::UnrelatedProtocol => "UnrelatedProtocol",
        ParsedTransport::UnrelatedIcmp => "UnrelatedIcmp",
        ParsedTransport::MalformedIcmp => "MalformedIcmp",
    }
}

pub(super) fn network_layer_name(network: ParsedNetworkLayer) -> &'static str {
    match network {
        ParsedNetworkLayer::NotPresent => "NotPresent",
        ParsedNetworkLayer::Valid(_) => "Valid",
        ParsedNetworkLayer::Malformed(_) => "Malformed",
        ParsedNetworkLayer::UnexpectedVersion { .. } => "UnexpectedVersion",
        ParsedNetworkLayer::Unsupported { .. } => "Unsupported",
    }
}

pub(super) fn ip_version(network: ParsedNetworkLayer) -> Option<u8> {
    let version = match network {
        ParsedNetworkLayer::Valid(header) | ParsedNetworkLayer::Unsupported { header, .. } => {
            header.version
        }
        ParsedNetworkLayer::UnexpectedVersion {
            observed: Some(version),
            ..
        } => version,
        ParsedNetworkLayer::NotPresent
        | ParsedNetworkLayer::Malformed(_)
        | ParsedNetworkLayer::UnexpectedVersion { observed: None, .. } => return None,
    };
    match version {
        crate::net::packet_headers::IpVersion::V4 => Some(4),
        crate::net::packet_headers::IpVersion::V6 => Some(6),
    }
}

pub(super) fn payload_event_kind(event: &PayloadEvent<'_>) -> &'static str {
    match event {
        PayloadEvent::UserPayload { .. } => "user-payload",
        PayloadEvent::SessionControl { .. } => "session-control",
        PayloadEvent::CadencePacket { .. } => "cadence",
    }
}

pub(super) fn flow_endpoint_string(endpoint: LogicalEndpoint) -> String {
    endpoint.to_string()
}

pub(super) fn flow_tuple_string(flow: FlowTuple) -> String {
    format!(
        "{} -> {}",
        flow_endpoint_string(flow.src),
        flow_endpoint_string(flow.dst)
    )
}

pub(super) fn client_flow_key_string(flow_key: ClientFlowKey) -> String {
    flow_key.to_string()
}
