use super::PayloadEvent;
use crate::cli::SupportedProtocol;
use crate::net::framing_shim::{
    ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelControl, IcmpTunnelFrameKind, ReplyIdNegotiation,
    SessionId, encode_icmp_control_prefix_with_source, encode_icmp_tunnel_prefix_with_source,
};
use crate::net::managed_socket::{ManagedSendLease, ManagedSendResult, ManagedSocket};
use crate::net::packet_headers::WireIcmpIdentity;
pub(crate) use pkthere_socket_policy::{IcmpChecksumMode, IpHeaderMode, SocketSendPolicy};
use pkthere_wire::checksum::{checksum16_bytes, checksum16_header, checksum16_header_parts};
use socket2::SockAddr;
use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::net::IpAddr;
#[cfg(test)]
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutboundPayloadEvent<'a> {
    body: OutboundPayloadBody<'a>,
    pub(crate) icmp: Option<OutboundIcmpMeta>,
}

#[derive(Clone, Copy, Debug)]
enum OutboundPayloadBody<'a> {
    Event(&'a PayloadEvent<'a>),
    Control(IcmpTunnelControl),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundIcmpMeta {
    pub(crate) identity: WireIcmpIdentity,
    pub(crate) seq: u16,
    pub(crate) session_id: SessionId,
    pub(crate) reply: bool,
    pub(crate) reply_id_negotiation: Option<ReplyIdNegotiation>,
    pub(crate) control: Option<IcmpTunnelControl>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PreparedOutboundPayloadEvent<'a> {
    Icmp {
        event: &'a PayloadEvent<'a>,
        identity: WireIcmpIdentity,
        session_id: SessionId,
        reply: bool,
        reply_id_negotiation: Option<ReplyIdNegotiation>,
        control: Option<IcmpTunnelControl>,
    },
    Transport(OutboundPayloadEvent<'a>),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MissingPreparedIcmpSequence;

impl<'a> PreparedOutboundPayloadEvent<'a> {
    #[inline]
    pub(crate) fn finish(
        self,
        icmp_seq: Option<u16>,
    ) -> Result<OutboundPayloadEvent<'a>, MissingPreparedIcmpSequence> {
        match self {
            Self::Icmp {
                event,
                identity,
                session_id,
                reply,
                reply_id_negotiation,
                control,
            } => {
                let seq = icmp_seq.ok_or(MissingPreparedIcmpSequence)?;
                Ok(OutboundPayloadEvent {
                    body: OutboundPayloadBody::Event(event),
                    icmp: Some(OutboundIcmpMeta {
                        identity,
                        seq,
                        session_id,
                        reply,
                        reply_id_negotiation,
                        control,
                    }),
                })
            }
            Self::Transport(outbound) => Ok(outbound),
        }
    }
}

pub(crate) fn prepare_outbound_payload_event<'a>(
    event: &'a PayloadEvent<'a>,
    icmp_header_id: u16,
    c2u: bool,
    source_id: u16,
    session_id: Option<SessionId>,
    reply_id_negotiation: Option<ReplyIdNegotiation>,
) -> io::Result<PreparedOutboundPayloadEvent<'a>> {
    if event.dst_proto() != SupportedProtocol::ICMP {
        if !event.is_user_payload() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot send non-user payload packet to non-ICMP destination",
            ));
        }
        return Ok(PreparedOutboundPayloadEvent::Transport(
            OutboundPayloadEvent {
                body: OutboundPayloadBody::Event(event),
                icmp: None,
            },
        ));
    }

    let session_id = session_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing ICMP v3 session ID for ICMP destination",
        )
    })?;
    let control = match reply_id_negotiation {
        Some(negotiation) if negotiation.is_negotiate() => {
            Some(IcmpTunnelControl::Negotiate(negotiation))
        }
        Some(negotiation) => Some(IcmpTunnelControl::NegotiateAck(negotiation)),
        None => event.icmp_meta().and_then(|icmp| icmp.control()),
    };
    Ok(PreparedOutboundPayloadEvent::Icmp {
        event,
        identity: WireIcmpIdentity {
            source_id: Some(source_id),
            destination_id: icmp_header_id,
        },
        session_id,
        reply: !c2u,
        reply_id_negotiation,
        control,
    })
}

pub(crate) fn outbound_control_payload_event(
    control: IcmpTunnelControl,
    icmp_header_id: u16,
    c2u: bool,
    icmp_seq: u16,
    source_id: u16,
    session_id: SessionId,
) -> OutboundPayloadEvent<'static> {
    OutboundPayloadEvent {
        body: OutboundPayloadBody::Control(control),
        icmp: Some(OutboundIcmpMeta {
            identity: WireIcmpIdentity {
                source_id: Some(source_id),
                destination_id: icmp_header_id,
            },
            seq: icmp_seq,
            session_id,
            reply: !c2u,
            reply_id_negotiation: None,
            control: Some(control),
        }),
    }
}

pub(crate) fn outbound_payload_event<'a>(
    event: &'a PayloadEvent<'a>,
    icmp_header_id: u16,
    c2u: bool,
    icmp_seq: Option<u16>,
    source_id: u16,
    session_id: Option<SessionId>,
    reply_id_negotiation: Option<ReplyIdNegotiation>,
) -> io::Result<OutboundPayloadEvent<'a>> {
    let prepared = prepare_outbound_payload_event(
        event,
        icmp_header_id,
        c2u,
        source_id,
        session_id,
        reply_id_negotiation,
    )?;
    if matches!(prepared, PreparedOutboundPayloadEvent::Icmp { .. }) && icmp_seq.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing ICMP sequence for ICMP destination",
        ));
    }
    prepared.finish(icmp_seq).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing ICMP sequence for ICMP destination",
        )
    })
}

pub(crate) fn send_payload(
    sock: &ManagedSocket,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    event: &OutboundPayloadEvent<'_>,
) -> io::Result<ManagedSendResult> {
    let lease = sock.acquire_control_send_lease()?;
    send_payload_with_lease(&lease, dest_sa, send_policy, source_ip, event)
}

pub(crate) fn send_payload_with_lease(
    lease: &ManagedSendLease<'_>,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    event: &OutboundPayloadEvent<'_>,
) -> io::Result<ManagedSendResult> {
    send_payload_with_target(
        PayloadSendTarget::Lease(lease),
        dest_sa,
        send_policy,
        source_ip,
        event,
    )
}

#[derive(Clone, Copy)]
enum PayloadSendTarget<'a> {
    Lease(&'a ManagedSendLease<'a>),
}

impl PayloadSendTarget<'_> {
    fn send(
        self,
        buffers: &[IoSlice<'_>],
        destination: &SockAddr,
    ) -> io::Result<ManagedSendResult> {
        match self {
            Self::Lease(lease) => lease.send_packet(buffers, destination),
        }
    }
}

fn send_payload_with_target(
    target: PayloadSendTarget<'_>,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    event: &OutboundPayloadEvent<'_>,
) -> io::Result<ManagedSendResult> {
    match event.icmp {
        Some(meta) => send_icmp_echo(target, dest_sa, send_policy, source_ip, event.body, &meta),
        None => match event.body {
            OutboundPayloadBody::Event(PayloadEvent::UserPayload { bytes, .. }) => {
                target.send(&[IoSlice::new(bytes)], dest_sa)
            }
            OutboundPayloadBody::Event(
                PayloadEvent::SessionControl { .. } | PayloadEvent::CadencePacket { .. },
            )
            | OutboundPayloadBody::Control(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-ICMP sends must contain user payload",
            )),
        },
    }
}

fn send_icmp_echo(
    target: PayloadSendTarget<'_>,
    dest_sa: &SockAddr,
    send_policy: SocketSendPolicy,
    source_ip: Option<IpAddr>,
    body: OutboundPayloadBody<'_>,
    meta: &OutboundIcmpMeta,
) -> io::Result<ManagedSendResult> {
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
    let (prefix, payload): (&[u8], &[u8]) = match body {
        OutboundPayloadBody::Event(PayloadEvent::UserPayload { bytes, .. }) => {
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
                meta.session_id,
                meta.reply_id_negotiation,
                bytes.len(),
                &mut shim_storage,
            )?;
            (prefix, *bytes)
        }
        OutboundPayloadBody::Event(PayloadEvent::SessionControl { icmp, .. }) => {
            let source_id = meta.identity.source_id.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ICMP session control requires a source ID",
                )
            })?;
            let control = meta
                .control
                .or_else(|| icmp.control())
                .ok_or_else(|| io::Error::other("ICMP session control has no v3 control body"))?;
            if control.session_id() != meta.session_id {
                return Err(io::Error::other(
                    "ICMP v3 control session does not match outbound metadata",
                ));
            }
            (
                encode_icmp_control_prefix_with_source(
                    control,
                    meta.identity.destination_id,
                    source_id,
                    &mut shim_storage,
                )?,
                &[],
            )
        }
        OutboundPayloadBody::Control(control) => {
            let source_id = meta.identity.source_id.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ICMP session control requires a source ID",
                )
            })?;
            if control.session_id() != meta.session_id {
                return Err(io::Error::other(
                    "ICMP v3 control session does not match outbound metadata",
                ));
            }
            (
                encode_icmp_control_prefix_with_source(
                    control,
                    meta.identity.destination_id,
                    source_id,
                    &mut shim_storage,
                )?,
                &[],
            )
        }
        OutboundPayloadBody::Event(PayloadEvent::CadencePacket { .. }) => (
            encode_icmp_tunnel_prefix_with_source(
                IcmpTunnelFrameKind::Cadence,
                meta.identity.destination_id,
                meta.identity.source_id.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ICMP cadence construction requires a source ID",
                    )
                })?,
                meta.session_id,
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
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "application ICMP checksum policy requires an IPv4 packet",
                ));
            }
            if prefix.is_empty() {
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
                        "IPv4-header-included RAW send requires a concrete source IPv4 address",
                    ));
                }
            };
            let dst = dest_sa
                .as_socket_ipv4()
                .map(|addr| *addr.ip())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "IPv4-header-included RAW send requires an IPv4 destination",
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
    target.send(slices_to_send, dest_sa)
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
