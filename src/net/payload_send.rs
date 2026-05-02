use super::PayloadEvent;
use crate::cli::SupportedProtocol;
use crate::net::checksum::{checksum16, checksum16_parts};
use crate::net::payload_support::{
    DEST_ADDR_REQUIRED, ICMP_SHIM_HAS_PAYLOAD, ICMP_SHIM_HAS_SOURCE_ID, ICMP_SHIM_IS_DATA,
};
use socket2::{SockAddr, Socket, Type};
use std::io;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutboundPayloadEvent<'a> {
    pub(crate) payload: &'a PayloadEvent<'a>,
    pub(crate) icmp: Option<OutboundIcmpMeta>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundIcmpMeta {
    pub(crate) header_id: u16,
    pub(crate) seq: u16,
    pub(crate) reply: bool,
    pub(crate) source_id_shim: Option<u16>,
}

pub(crate) fn outbound_payload_event<'a>(
    event: &'a PayloadEvent<'a>,
    icmp_header_id: u16,
    c2u: bool,
    icmp_seq: Option<u16>,
    source_id_for_shim: Option<u16>,
) -> io::Result<OutboundPayloadEvent<'a>> {
    let dst_proto = match event {
        PayloadEvent::UserPayload { data, .. } | PayloadEvent::SessionControl { data, .. } => {
            data.dst_proto
        }
        PayloadEvent::CadencePacket { .. } => SupportedProtocol::ICMP,
    };
    let icmp = match dst_proto {
        SupportedProtocol::ICMP => Some(OutboundIcmpMeta {
            header_id: icmp_header_id,
            seq: icmp_seq.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing ICMP sequence for ICMP destination",
                )
            })?,
            reply: !c2u,
            source_id_shim: source_id_for_shim,
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

    if !matches!(event, PayloadEvent::UserPayload { .. }) && icmp.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot send non-user payload packet to non-ICMP destination",
        ));
    }

    if let Some(meta) = icmp
        && !event.is_user_payload()
        && meta.source_id_shim.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot encode source ID shim on non-user ICMP packet",
        ));
    }

    Ok(OutboundPayloadEvent {
        payload: event,
        icmp,
    })
}

pub(crate) fn send_payload(
    sock: &Socket,
    sock_connected: bool,
    sock_type: Type,
    dest_sa: &SockAddr,
    event: &OutboundPayloadEvent<'_>,
) -> io::Result<bool> {
    let send_res = match event.icmp {
        Some(meta) => send_icmp_echo(
            sock,
            sock_connected,
            sock_type,
            dest_sa,
            event.payload,
            &meta,
        ),
        None => match event.payload {
            PayloadEvent::UserPayload { data, .. } => {
                if sock_connected {
                    sock.send(data.bytes)
                } else {
                    sock.send_to(data.bytes, dest_sa)
                }
            }
            _ => unreachable!("non-ICMP sends must be user payload only"),
        },
    };

    match send_res {
        Ok(_) => Ok(true),
        Err(e) if sock_connected && e.raw_os_error() == Some(DEST_ADDR_REQUIRED) => {
            let retry_res = match event.icmp {
                Some(meta) => send_icmp_echo(sock, false, sock_type, dest_sa, event.payload, &meta),
                None => match event.payload {
                    PayloadEvent::UserPayload { data, .. } => sock.send_to(data.bytes, dest_sa),
                    _ => unreachable!("non-ICMP sends must be user payload only"),
                },
            };
            match retry_res {
                Ok(_) => Ok(false),
                Err(retry_err) => Err(retry_err),
            }
        }
        Err(e) => Err(e),
    }
}

fn send_icmp_echo(
    sock: &Socket,
    sock_connected: bool,
    sock_type: Type,
    dest_sa: &SockAddr,
    event: &PayloadEvent<'_>,
    meta: &OutboundIcmpMeta,
) -> io::Result<usize> {
    let mut hdr = [0u8; 8];
    let idb = meta.header_id.to_be_bytes();
    let sqb = meta.seq.to_be_bytes();
    hdr[4] = idb[0];
    hdr[5] = idb[1];
    hdr[6] = sqb[0];
    hdr[7] = sqb[1];

    let mut shim_storage = [0u8; 3];
    let (prefix, payload): (&[u8], &[u8]) = match event {
        PayloadEvent::UserPayload { data, .. } => {
            let shim_len = if let Some(src_id) = meta.source_id_shim {
                let idb = src_id.to_be_bytes();
                shim_storage[0] = ICMP_SHIM_IS_DATA
                    | (((!data.bytes.is_empty()) as u8) * ICMP_SHIM_HAS_PAYLOAD)
                    | ICMP_SHIM_HAS_SOURCE_ID;
                shim_storage[1] = idb[0];
                shim_storage[2] = idb[1];
                3
            } else {
                shim_storage[0] =
                    ICMP_SHIM_IS_DATA | (((!data.bytes.is_empty()) as u8) * ICMP_SHIM_HAS_PAYLOAD);
                1
            };
            (&shim_storage[..shim_len], data.bytes)
        }
        PayloadEvent::SessionControl { .. } => {
            shim_storage[0] = 0;
            (&shim_storage[..1], &[])
        }
        PayloadEvent::CadencePacket { .. } => (&[], &[]),
    };

    let cksum = match (dest_sa, sock_type) {
        (sa, _) if sa.is_ipv6() => {
            hdr[0] = 128u8 | (meta.reply as u8);
            0u16
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        _ => {
            hdr[0] = 8u8 * (!meta.reply as u8);
            if prefix.is_empty() {
                checksum16(&hdr, payload)
            } else {
                checksum16_parts(&hdr, prefix, payload)
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        (_, ty) if ty == Type::DGRAM => {
            hdr[0] = 8u8 * (!meta.reply as u8);
            0u16
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        _ => {
            hdr[0] = 8u8 * (!meta.reply as u8);
            if prefix.is_empty() {
                checksum16(&hdr, payload)
            } else {
                checksum16_parts(&hdr, prefix, payload)
            }
        }
    }
    .to_be_bytes();

    hdr[2] = cksum[0];
    hdr[3] = cksum[1];
    let packet = build_icmp_echo_packet(&hdr, prefix, payload);
    if sock_connected {
        sock.send(&packet)
    } else {
        sock.send_to(&packet, dest_sa)
    }
}

#[inline]
fn build_icmp_echo_packet(hdr: &[u8; 8], prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(hdr.len() + prefix.len() + payload.len());
    packet.extend_from_slice(hdr);
    packet.extend_from_slice(prefix);
    packet.extend_from_slice(payload);
    packet
}

#[cfg(test)]
pub(crate) fn build_test_icmp_echo_packet(hdr: &[u8; 8], prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    build_icmp_echo_packet(hdr, prefix, payload)
}
