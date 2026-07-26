#![cfg(all(test, not(miri)))]

use crate::cli::RuntimeConfig;
use crate::flow_state::FlowAdmissionSnapshot;
use crate::net::framing_shim::{
    ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelFrameKind, SessionId, encode_icmp_tunnel_prefix_with_source,
};
use crate::net::packet_headers::ReceiveParserKernel;
use crate::net::sock_mgr::SocketHandles;
use crate::worker_support::packet_admission::{
    TransportAdmission, admit_packet_with_parsed, admit_transport_packet, client_receive_context,
    upstream_receive_context,
};
use pkthere_wire::packet_headers::ReceiveHeaderMode;
use std::net::{Ipv4Addr, SocketAddr};

pub(super) fn packet(
    destination_id: u16,
    source_id: u16,
    sequence: u16,
    session: SessionId,
    reply: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut shim_storage = [0_u8; ICMP_TUNNEL_SHIM_MAX_LEN];
    let prefix = encode_icmp_tunnel_prefix_with_source(
        IcmpTunnelFrameKind::UserPayload,
        destination_id,
        source_id,
        session,
        None,
        payload.len(),
        &mut shim_storage,
    )
    .expect("encode production ICMP-v3 pipeline prefix");
    let mut packet = Vec::with_capacity(8 + prefix.len() + payload.len());
    let mut header = [
        if reply { 0 } else { 8 },
        0,
        0,
        0,
        (destination_id >> 8) as u8,
        destination_id as u8,
        (sequence >> 8) as u8,
        sequence as u8,
    ];
    let checksum =
        pkthere_wire::checksum::checksum16_header_parts(&header, prefix, payload).to_be_bytes();
    header[2] = checksum[0];
    header[3] = checksum[1];
    packet.extend_from_slice(&header);
    packet.extend_from_slice(prefix);
    packet.extend_from_slice(payload);
    packet
}

pub(super) fn receive_packet(
    parser: ReceiveParserKernel,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    icmp: Vec<u8>,
) -> Vec<u8> {
    if parser.mode() != ReceiveHeaderMode::IpHeaderIncluded {
        return icmp;
    }
    let mut packet = crate::net::payload::build_test_ipv4_icmp_packet(source, destination, &icmp);
    super::packet_admission::test_support::set_test_ipv4_receive_length(&mut packet);
    packet
}

pub(super) fn assert_admitted(
    c2u: bool,
    cfg: &RuntimeConfig,
    handles: &SocketHandles,
    snapshot: &FlowAdmissionSnapshot,
    packet: &[u8],
    source: SocketAddr,
) {
    let context = if c2u {
        client_receive_context(cfg, handles, snapshot)
    } else {
        upstream_receive_context(cfg, handles, snapshot)
    };
    let network = context.socket.parser.parse_network(packet);
    let parsed = context.socket.parser.parse_transport(packet, network);
    let admitted = admit_packet_with_parsed(context, packet, Some(source), &parsed);
    let TransportAdmission::Accepted(transport) = admitted else {
        panic!("production ICMP pipeline fixture was rejected: {admitted:?}");
    };
    let wire = admit_transport_packet(c2u, cfg, context, transport);
    assert!(
        wire.is_ok(),
        "production ICMP pipeline framing was rejected: {wire:?}"
    );
}
