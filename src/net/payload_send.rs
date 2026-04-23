use super::PayloadEvent;
use crate::cli::SupportedProtocol;
use crate::net::framing_shim::{
    ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelFrameKind, ReplyIdNegotiation,
    encode_icmp_tunnel_prefix_with_source,
};
use crate::net::packet_headers::WireIcmpIdentity;
use crate::net::socket_errors::DEST_ADDR_REQUIRED;
pub(crate) use pkthere_socket_policy::{IcmpChecksumMode, IpHeaderMode, SocketSendPolicy};
use pkthere_wire::checksum::{checksum16_bytes, checksum16_header, checksum16_header_parts};
use socket2::{SockAddr, Socket};
use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::net::IpAddr;
#[cfg(test)]
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutboundPayloadEvent<'a> {
    pub(crate) payload: &'a PayloadEvent<'a>,
    pub(crate) icmp: Option<OutboundIcmpMeta>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundIcmpMeta {
    pub(crate) identity: WireIcmpIdentity,
    pub(crate) seq: u16,
    pub(crate) reply: bool,
    pub(crate) reply_id_negotiation: Option<ReplyIdNegotiation>,
}

pub(crate) fn outbound_payload_event<'a>(
    event: &'a PayloadEvent<'a>,
    icmp_header_id: u16,
    c2u: bool,
    icmp_seq: Option<u16>,
    source_id: u16,
    reply_id_negotiation: Option<ReplyIdNegotiation>,
) -> io::Result<OutboundPayloadEvent<'a>> {
    let dst_proto = event.dst_proto();
    let icmp = match dst_proto {
        SupportedProtocol::ICMP => Some(OutboundIcmpMeta {
            identity: WireIcmpIdentity {
                source_id: (!event.is_cadence_packet()).then_some(source_id),
                destination_id: icmp_header_id,
            },
            seq: icmp_seq.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing ICMP sequence for ICMP destination",
                )
            })?,
            reply: !c2u,
            reply_id_negotiation,
        }),
        _ => {
            if !event.is_user_payload() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot send non-user payload packet to non-ICMP destination",
                ));
            }
            None
        }
    };

    Ok(OutboundPayloadEvent {
        payload: event,
        icmp,
    })
}

pub(crate) fn send_payload(
    sock: &Socket,
    sock_connected: bool,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    event: &OutboundPayloadEvent<'_>,
) -> io::Result<bool> {
    let send_res = send_payload_once(sock, sock_connected, dest_sa, send_policy, source_ip, event);

    match send_res {
        Ok(_) => Ok(true),
        Err(e) if sock_connected && e.raw_os_error() == Some(DEST_ADDR_REQUIRED) => {
            match send_payload_once(sock, false, dest_sa, send_policy, source_ip, event) {
                Ok(_) => Ok(false),
                Err(retry_err) => Err(retry_err),
            }
        }
        Err(e) => Err(e),
    }
}

#[inline]
fn send_payload_once(
    sock: &Socket,
    sock_connected: bool,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    event: &OutboundPayloadEvent<'_>,
) -> io::Result<usize> {
    match event.icmp {
        Some(meta) => send_icmp_echo(
            sock,
            sock_connected,
            dest_sa,
            send_policy,
            source_ip,
            event.payload,
            &meta,
        ),
        None => match event.payload {
            PayloadEvent::UserPayload { bytes, .. } => {
                if sock_connected {
                    sock.send(bytes)
                } else {
                    sock.send_to(bytes, dest_sa)
                }
            }
            _ => unreachable!("non-ICMP sends must be user payload only"),
        },
    }
}

fn send_icmp_echo(
    sock: &Socket,
    sock_connected: bool,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    event: &PayloadEvent<'_>,
    meta: &OutboundIcmpMeta,
) -> io::Result<usize> {
    let mut hdr = [
        0,
        0,
        0,
        0,
        (meta.identity.destination_id >> 8) as u8,
        meta.identity.destination_id as u8,
        (meta.seq >> 8) as u8,
        meta.seq as u8,
    ];

    let mut shim_storage = [0u8; ICMP_TUNNEL_SHIM_MAX_LEN];
    let (prefix, payload): (&[u8], &[u8]) = match event {
        PayloadEvent::UserPayload { bytes, .. } => {
            let source_id = meta.identity.source_id.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "shimmed ICMP user payload requires a source ID",
                )
            })?;
            let prefix = encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::UserPayload,
                meta.identity.destination_id,
                source_id,
                meta.reply_id_negotiation,
                bytes.len(),
                &mut shim_storage,
            )?;
            (prefix, *bytes)
        }
        PayloadEvent::SessionControl { .. } => {
            let source_id = meta.identity.source_id.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ICMP session control requires a source ID",
                )
            })?;
            (
                encode_icmp_tunnel_prefix_with_source(
                    IcmpTunnelFrameKind::SessionControl,
                    meta.identity.destination_id,
                    source_id,
                    meta.reply_id_negotiation,
                    0,
                    &mut shim_storage,
                )?,
                &[],
            )
        }
        PayloadEvent::CadencePacket { .. } => (
            encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::Cadence,
                meta.identity.destination_id,
                0,
                None,
                0,
                &mut shim_storage,
            )?,
            &[],
        ),
    };

    hdr[0] = if dest_sa.is_ipv6() {
        128u8 | (meta.reply as u8)
    } else {
        8u8 * (!meta.reply as u8)
    };
    let cksum = match send_policy.icmp_checksum {
        IcmpChecksumMode::KernelComputed => 0u16,
        IcmpChecksumMode::ApplicationComputed => {
            if dest_sa.is_ipv6() {
                0u16
            } else if prefix.is_empty() {
                checksum16_header(&hdr, payload)
            } else {
                checksum16_header_parts(&hdr, prefix, payload)
            }
        }
    };

    let cksum_bytes = cksum.to_be_bytes();
    hdr[2] = cksum_bytes[0];
    hdr[3] = cksum_bytes[1];

    let mut iovecs = [
        IoSlice::new(&[]),
        IoSlice::new(&hdr),
        IoSlice::new(prefix),
        IoSlice::new(payload),
    ];
    let mut iovec_start = 1;

    let mut ip_hdr_storage: MaybeUninit<[u8; 20]> = MaybeUninit::uninit();

    match send_policy.ip_header {
        IpHeaderMode::PayloadOnly => {}
        IpHeaderMode::Ipv4HeaderIncluded => {
            let total_len = 20usize + hdr.len() + prefix.len() + payload.len();
            let src = match source_ip {
                Some(IpAddr::V4(ip)) if !ip.is_unspecified() => ip,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows RAW IPv4 header send requires concrete source IPv4 address",
                    ));
                }
            };
            let dst = dest_sa
                .as_socket_ipv4()
                .map(|addr| *addr.ip())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows RAW IPv4 header send requires IPv4 destination",
                    )
                })?;

            let len_bytes = (total_len as u16).to_be_bytes();
            let src_bytes = src.octets();
            let dst_bytes = dst.octets();

            let mut ip_hdr = [
                0x45,
                0,
                len_bytes[0],
                len_bytes[1],
                0,
                0,
                0,
                0,
                64,
                1,
                0,
                0,
                src_bytes[0],
                src_bytes[1],
                src_bytes[2],
                src_bytes[3],
                dst_bytes[0],
                dst_bytes[1],
                dst_bytes[2],
                dst_bytes[3],
            ];
            let checksum = checksum16_bytes(&ip_hdr).to_be_bytes();
            ip_hdr[10] = checksum[0];
            ip_hdr[11] = checksum[1];

            let ip_ref = ip_hdr_storage.write(ip_hdr);
            iovecs[0] = IoSlice::new(ip_ref);
            iovec_start = 0;
        }
    }

    let slices_to_send = &iovecs[iovec_start..];
    if sock_connected {
        sock.send_vectored(slices_to_send)
    } else {
        sock.send_to_vectored(slices_to_send, dest_sa)
    }
}

#[cfg(test)]
#[inline]
pub(crate) fn build_test_icmp_echo_packet(hdr: &[u8; 8], prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(hdr.len() + prefix.len() + payload.len());
    packet.extend_from_slice(hdr);
    packet.extend_from_slice(prefix);
    packet.extend_from_slice(payload);
    packet
}

#[cfg(test)]
pub(crate) fn build_test_ipv4_icmp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    icmp_packet: &[u8],
) -> Vec<u8> {
    let total_len = 20usize + icmp_packet.len();
    assert!(total_len <= u16::MAX as usize);

    let len_bytes = (total_len as u16).to_be_bytes();
    let src_bytes = src.octets();
    let dst_bytes = dst.octets();

    let mut ip = [
        0x45,
        0,
        len_bytes[0],
        len_bytes[1],
        0,
        0,
        0,
        0,
        64,
        1,
        0,
        0,
        src_bytes[0],
        src_bytes[1],
        src_bytes[2],
        src_bytes[3],
        dst_bytes[0],
        dst_bytes[1],
        dst_bytes[2],
        dst_bytes[3],
    ];
    let checksum = checksum16_bytes(&ip).to_be_bytes();
    ip[10] = checksum[0];
    ip[11] = checksum[1];

    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(icmp_packet);
    packet
}
