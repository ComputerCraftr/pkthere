use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::checksum::{checksum16, checksum16_parts};
use crate::net::icmp_parse::{be16_16, parse_icmp_echo_header};
use crate::net::payload_support::{
    DEST_ADDR_REQUIRED, ICMP_SHIM_ALLOWED_BITS, ICMP_SHIM_HAS_PAYLOAD, ICMP_SHIM_HAS_SOURCE_ID,
    ICMP_SHIM_IS_DATA,
};
use crate::stats::StatsSink;
use socket2::{SockAddr, Socket, Type};

use std::io::{self, IoSlice};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadOrigin {
    Wire,
    SyntheticSyncKeepalive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpIdPolicy {
    Any,
    Exact(u16),
}

impl IcmpIdPolicy {
    #[inline]
    const fn accepts(self, ident: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => ident == expected,
        }
    }

    #[inline]
    const fn synthetic_ident(self) -> u16 {
        match self {
            Self::Any => 0,
            Self::Exact(ident) => ident,
        }
    }
}

#[derive(Debug)]
pub(crate) enum PayloadEvent<'a> {
    UserData(WirePayload<'a>),
    SyncKeepalive(WirePayload<'a>),
}

impl<'a> PayloadEvent<'a> {
    #[inline]
    pub(crate) const fn wire(&self) -> &WirePayload<'a> {
        match self {
            Self::UserData(wire) | Self::SyncKeepalive(wire) => wire,
        }
    }

    #[inline]
    pub(crate) const fn is_user_data(&self) -> bool {
        matches!(self, Self::UserData(_))
    }

    #[inline]
    pub(crate) const fn from_wire_parts(
        is_user_data: bool,
        src_ident: u16,
        src_seq: u16,
        dst_proto: SupportedProtocol,
        payload: &'a [u8],
        pub_len: usize,
        src_id_from_shim: Option<u16>,
    ) -> Self {
        let wire = WirePayload {
            src_is_icmp: true,
            src_ident,
            src_seq,
            dst_proto,
            payload,
            pub_len,
            src_id_from_shim,
        };
        if is_user_data {
            Self::UserData(wire)
        } else {
            Self::SyncKeepalive(wire)
        }
    }
}

#[derive(Debug)]
pub(crate) struct WirePayload<'a> {
    pub(crate) src_is_icmp: bool,
    pub(crate) src_ident: u16,
    pub(crate) src_seq: u16,
    pub(crate) dst_proto: SupportedProtocol,
    pub(crate) payload: &'a [u8],
    pub(crate) pub_len: usize,
    pub(crate) src_id_from_shim: Option<u16>,
}

impl<'a> WirePayload<'a> {
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.pub_len
    }
}

#[inline]
fn decode_icmp_tunnel_payload<'a>(payload: &'a [u8]) -> io::Result<PayloadEvent<'a>> {
    if payload.is_empty() {
        // Empty ICMP payload is used for PPS cadence in sync mode.
        // It's not a user packet or a keepalive; it's a "pps tick".
        // We represent this as a special keepalive variant.
        return Ok(PayloadEvent::SyncKeepalive(WirePayload {
            src_is_icmp: true,
            src_ident: 0,
            src_seq: 0,
            dst_proto: SupportedProtocol::ICMP,
            payload: &[],
            pub_len: 0,
            src_id_from_shim: None,
        }));
    }

    let shim = payload[0];
    if (shim & !ICMP_SHIM_ALLOWED_BITS) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP tunnel shim header",
        ));
    }

    let has_source_id = (shim & ICMP_SHIM_HAS_SOURCE_ID) != 0;
    if has_source_id && payload.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP tunnel shim has source ID flag but payload is too short",
        ));
    }

    let (src_id_from_shim, user_payload) = if has_source_id {
        let id = be16_16(payload[1], payload[2]);
        (Some(id), &payload[3..])
    } else {
        (None, &payload[1..])
    };

    let is_data = (shim & ICMP_SHIM_IS_DATA) != 0;
    let has_user_payload = (shim & ICMP_SHIM_HAS_PAYLOAD) != 0;

    // Normal tunnel packets MUST have a valid shim.
    // Zero-length user data has IS_DATA set but HAS_PAYLOAD unset.
    // Sync keepalives have both bits unset (legacy/sync convention).
    match (is_data, has_user_payload, user_payload.is_empty()) {
        (true, true, false) => Ok(PayloadEvent::UserData(WirePayload {
            src_is_icmp: true,
            src_ident: 0,
            src_seq: 0,
            dst_proto: SupportedProtocol::UDP,
            payload: user_payload,
            pub_len: user_payload.len(),
            src_id_from_shim,
        })),
        (true, false, true) => Ok(PayloadEvent::UserData(WirePayload {
            src_is_icmp: true,
            src_ident: 0,
            src_seq: 0,
            dst_proto: SupportedProtocol::UDP,
            payload: &[],
            pub_len: 0,
            src_id_from_shim,
        })),
        (false, false, true) => Ok(PayloadEvent::SyncKeepalive(WirePayload {
            src_is_icmp: true,
            src_ident: 0,
            src_seq: 0,
            dst_proto: SupportedProtocol::ICMP,
            payload: &[],
            pub_len: 0,
            src_id_from_shim,
        })),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP tunnel shim payload flags mismatch",
        )),
    }
}

#[inline]
pub(crate) fn validate_payload<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    buf: &'a [u8],
    icmp_id_policy: IcmpIdPolicy,
    origin: PayloadOrigin,
    is_locked: bool,
) -> io::Result<PayloadEvent<'a>> {
    let (src_proto, dst_proto) = if c2u {
        (cfg.listen_proto, cfg.upstream_proto)
    } else {
        (cfg.upstream_proto, cfg.listen_proto)
    };

    if origin == PayloadOrigin::SyntheticSyncKeepalive {
        if c2u && dst_proto == SupportedProtocol::ICMP && cfg.icmp_sync_pps > 0 {
            return Ok(PayloadEvent::SyncKeepalive(WirePayload {
                src_is_icmp: src_proto == SupportedProtocol::ICMP,
                src_ident: icmp_id_policy.synthetic_ident(),
                src_seq: 0,
                dst_proto,
                payload: &[],
                pub_len: 0,
                src_id_from_shim: None,
            }));
        } else {
            stats.drop_oversize(c2u);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic sync keepalive is only valid for ICMP sync sends",
            ));
        }
    }

    let (src_is_icmp, icmp_success, payload, src_ident_header, src_seq, src_is_req) =
        match src_proto {
            SupportedProtocol::ICMP => {
                let res = parse_icmp_echo_header(buf);
                (true, res.0, &res.1[res.2..res.3], res.4, res.5, res.6)
            }
            _ => (false, true, buf, 0u16, 0u16, c2u),
        };

    if !icmp_success {
        stats.drop_err(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP Echo header (missing or truncated)",
        ));
    }

    if c2u != src_is_req || (src_is_icmp && !icmp_id_policy.accepts(src_ident_header)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ICMP Echo direction or identity mismatch: got (req={}, id={}), expected (req={}, policy={:?})",
                src_is_req, src_ident_header, c2u, icmp_id_policy
            ),
        ));
    }

    let decoded_event = if src_is_icmp {
        let event = decode_icmp_tunnel_payload(payload)?;
        let base = event.wire();

        if base.src_id_from_shim.is_some() {
            if is_locked {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ICMP tunnel handshake attempted on already locked session",
                ));
            }
            if !src_is_req {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ICMP tunnel handshake attempted on Echo Reply",
                ));
            }
            if !event.is_user_data() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ICMP tunnel handshake attempted on Keepalive packet",
                ));
            }
        }

        PayloadEvent::from_wire_parts(
            event.is_user_data(),
            base.src_id_from_shim.unwrap_or(src_ident_header),
            src_seq,
            dst_proto,
            base.payload,
            base.pub_len,
            base.src_id_from_shim,
        )
    } else {
        PayloadEvent::UserData(WirePayload {
            src_is_icmp,
            src_ident: src_ident_header,
            src_seq,
            dst_proto,
            payload,
            pub_len: payload.len(),
            src_id_from_shim: None,
        })
    };
    let len = decoded_event.wire().len();
    if len > cfg.max_payload {
        stats.drop_oversize(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload length {} exceeds max {}", len, cfg.max_payload),
        ));
    }
    Ok(decoded_event)
}

pub(crate) fn send_payload(
    sock: &Socket,
    sock_connected: bool,
    sock_type: Type,
    dest_sa: &SockAddr,
    event: &PayloadEvent<'_>,
    icmp_header_id: u16,
    c2u: bool,
    icmp_seq: Option<u16>,
    source_id_for_shim: Option<u16>,
) -> io::Result<bool> {
    let wire = event.wire();
    let mut shim_storage = [0u8; 3];
    let shim_len = if let Some(src_id) = source_id_for_shim {
        let base = match event {
            PayloadEvent::UserData(wire) => {
                ICMP_SHIM_IS_DATA
                    | (((wire.len() != 0) as u8) * ICMP_SHIM_HAS_PAYLOAD)
                    | ICMP_SHIM_HAS_SOURCE_ID
            }
            PayloadEvent::SyncKeepalive(_) => ICMP_SHIM_HAS_SOURCE_ID,
        };
        let idb = src_id.to_be_bytes();
        shim_storage[0] = base;
        shim_storage[1] = idb[0];
        shim_storage[2] = idb[1];
        3
    } else {
        let base = match event {
            PayloadEvent::UserData(wire) => {
                ICMP_SHIM_IS_DATA | (((wire.len() != 0) as u8) * ICMP_SHIM_HAS_PAYLOAD)
            }
            PayloadEvent::SyncKeepalive(_) => 0u8,
        };
        shim_storage[0] = base;
        1
    };

    let send_res = match wire.dst_proto {
        SupportedProtocol::ICMP => send_icmp_echo(
            sock,
            sock_connected,
            sock_type,
            dest_sa,
            icmp_header_id,
            icmp_seq.expect("missing ICMP sequence for ICMP destination"),
            !c2u,
            Some(&shim_storage[..shim_len]),
            wire.payload,
        ),
        _ => {
            if !event.is_user_data() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot send keepalive/control packet to non-ICMP destination",
                ));
            }
            if sock_connected {
                sock.send(wire.payload)
            } else {
                sock.send_to(wire.payload, dest_sa)
            }
        }
    };

    match send_res {
        Ok(_) => Ok(true),
        Err(e) if sock_connected && e.raw_os_error() == Some(DEST_ADDR_REQUIRED) => {
            let retry_res = match wire.dst_proto {
                SupportedProtocol::ICMP => send_icmp_echo(
                    sock,
                    false,
                    sock_type,
                    dest_sa,
                    icmp_header_id,
                    icmp_seq.expect("missing ICMP sequence for ICMP destination"),
                    !c2u,
                    Some(&shim_storage[..shim_len]),
                    wire.payload,
                ),
                _ => sock.send_to(wire.payload, dest_sa),
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
    ident: u16,
    seq: u16,
    reply: bool,
    payload_prefix: Option<&[u8]>,
    payload: &[u8],
) -> io::Result<usize> {
    let mut hdr = [0u8; 8];

    let idb = ident.to_be_bytes();
    let sqb = seq.to_be_bytes();

    hdr[4] = idb[0];
    hdr[5] = idb[1];
    hdr[6] = sqb[0];
    hdr[7] = sqb[1];

    let cksum = match (dest_sa, sock_type) {
        (sa, _) if sa.is_ipv6() => {
            hdr[0] = 128u8 | (reply as u8);
            0u16
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        _ => {
            hdr[0] = 8u8 * (!reply as u8);
            match payload_prefix {
                Some(prefix) => checksum16_parts(&hdr, prefix, payload),
                None => checksum16(&hdr, payload),
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        (_, ty) if ty == Type::DGRAM => {
            hdr[0] = 8u8 * (!reply as u8);
            0u16
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        _ => {
            hdr[0] = 8u8 * (!reply as u8);
            match payload_prefix {
                Some(prefix) => checksum16_parts(&hdr, prefix, payload),
                None => checksum16(&hdr, payload),
            }
        }
    };

    hdr[2] = (cksum >> 8) as u8;
    hdr[3] = (cksum & 0xFF) as u8;

    let prefix = payload_prefix.unwrap_or(&[]);
    let iov = [
        IoSlice::new(&hdr),
        IoSlice::new(prefix),
        IoSlice::new(payload),
    ];
    if sock_connected {
        sock.send_vectored(&iov)
    } else {
        sock.send_to_vectored(&iov, dest_sa)
    }
}

#[cfg(test)]
#[inline]
fn test_icmp_echo_header(ident: u16, seq: u16) -> [u8; 8] {
    let mut hdr = [0u8; 8];
    let idb = ident.to_be_bytes();
    let sqb = seq.to_be_bytes();
    hdr[4] = idb[0];
    hdr[5] = idb[1];
    hdr[6] = sqb[0];
    hdr[7] = sqb[1];
    hdr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        DebugBehavior, DebugLogs, ListenMode, ReresolveMode, RuntimeConfig, SupportedProtocol,
        TimeoutAction, WorkerFlowMode,
    };
    use crate::net::params::CanonicalAddr;
    use crate::stats::Stats;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_config(
        listen_proto: SupportedProtocol,
        upstream_proto: SupportedProtocol,
    ) -> RuntimeConfig {
        RuntimeConfig {
            listen: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234)),
                1234,
            ),
            listen_proto,
            listen_mode: ListenMode::Fixed,
            listen_str: String::from("test-listen"),
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            upstream: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4321)),
                4321,
            ),
            upstream_local_id: 0,
            upstream_proto,
            upstream_str: String::from("test-upstream"),
            timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 10,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        }
    }

    #[test]
    fn explicit_icmp_header_id_is_serialized_verbatim() {
        let hdr = test_icmp_echo_header(4242, 9);
        let packet = [hdr.as_slice(), b"x"].concat();
        let (_, _raw, start, end, ident, seq, _is_req) = parse_icmp_echo_header(&packet);
        assert_eq!(ident, 4242);
        assert_eq!(seq, 9);
        assert_eq!(&packet[start..end], b"x");
    }

    #[test]
    fn parse_icmp_echo_header_accepts_ipv4_with_ip_header() {
        let icmp_payload = [0xDEu8, 0xAD, 0xBE];
        let mut buf = vec![0u8; 20 + 8 + icmp_payload.len()];
        buf[0] = 0x45;
        buf[8] = 64;
        buf[9] = 1;
        buf[20] = 8;
        buf[22] = 0;
        buf[23] = 0;
        buf[24] = 0x12;
        buf[25] = 0x34;
        buf[26] = 0x00;
        buf[27] = 0x02;
        buf[28..].copy_from_slice(&icmp_payload);

        let (ok, raw, start, end, ident, seq, is_req) = parse_icmp_echo_header(&buf);
        assert!(ok);
        assert_eq!(start, 28);
        assert_eq!(end, 28 + icmp_payload.len());
        assert_eq!(ident, 0x1234);
        assert_eq!(seq, 0x0002);
        assert!(is_req);
        assert_eq!(&raw[start..end], &icmp_payload);
    }

    #[test]
    fn parse_icmp_echo_header_accepts_ipv6_with_ip_header() {
        let icmp_payload = [0xCAu8, 0xFE, 0xBA, 0xBE];
        let mut buf = vec![0u8; 40 + 8 + icmp_payload.len()];
        buf[0] = 0x60;
        buf[6] = 58;
        buf[40] = 129;
        buf[44] = 0xBE;
        buf[45] = 0xEF;
        buf[46] = 0x00;
        buf[47] = 0x2A;
        buf[48..].copy_from_slice(&icmp_payload);

        let (ok, raw, start, end, ident, seq, is_req) = parse_icmp_echo_header(&buf);
        assert!(ok);
        assert_eq!(start, 48);
        assert_eq!(end, 48 + icmp_payload.len());
        assert_eq!(ident, 0xBEEF);
        assert_eq!(seq, 0x002A);
        assert!(!is_req);
        assert_eq!(&raw[start..end], &icmp_payload);
    }

    #[test]
    fn parse_icmp_echo_header_accepts_headerless_icmp() {
        let payload = [0xABu8, 0xCD];
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&[8, 0, 0, 0, 0x01, 0x02, 0x03, 0x04]);
        buf.extend_from_slice(&payload);

        let (ok, raw, start, end, ident, seq, is_req) = parse_icmp_echo_header(&buf);
        assert!(ok);
        assert_eq!(start, 8);
        assert_eq!(end, 8 + payload.len());
        assert_eq!(ident, 0x0102);
        assert_eq!(seq, 0x0304);
        assert!(is_req);
        assert_eq!(&raw[start..end], &payload);
    }

    #[test]
    fn parse_icmp_echo_header_rejects_truncated_input() {
        let buf = [0u8; 4];
        let (ok, _raw, start, end, _ident, _seq, _is_req) = parse_icmp_echo_header(&buf);

        assert!(!ok);
        assert_eq!(start, 0);
        assert_eq!(end, 0);
    }

    #[test]
    fn validate_payload_accepts_zero_len_udp_wire_and_synthetic_sync_keepalive() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let stats = Stats::new();

        let wire = validate_payload(
            true,
            &cfg,
            &stats,
            &[],
            IcmpIdPolicy::Exact(cfg.listen.id),
            PayloadOrigin::Wire,
            false,
        )
        .expect("wire zero-length UDP must be treated as user data");
        assert!(matches!(wire, PayloadEvent::UserData(_)));
        assert_eq!(wire.wire().len(), 0);

        let synthetic = validate_payload(
            true,
            &cfg,
            &stats,
            &[],
            IcmpIdPolicy::Exact(cfg.listen.id),
            PayloadOrigin::SyntheticSyncKeepalive,
            false,
        )
        .expect("synthetic sync keepalive should be accepted");
        assert!(matches!(synthetic, PayloadEvent::SyncKeepalive(_)));
        assert_eq!(synthetic.wire().len(), 0);
    }

    #[test]
    fn validate_payload_classifies_wire_zero_len_icmp_as_keepalive() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        // 0x00 is now keepalive
        let buf = [8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09, 0x00];

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(cfg.listen.id),
            PayloadOrigin::Wire,
            false,
        )
        .expect("wire ICMP keepalive header should decode");
        assert!(matches!(event, PayloadEvent::SyncKeepalive(_)));
        assert_eq!(event.wire().src_seq, 9);
    }

    fn encode_icmp_payload(shim: Option<u8>, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + shim.map_or(0, |_| 1) + payload.len());
        buf.extend_from_slice(&[8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09]);
        if let Some(shim) = shim {
            buf.push(shim);
        }
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn validate_payload_decodes_zero_len_icmp_user_datagram() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(cfg.listen.id),
            PayloadOrigin::Wire,
            false,
        )
        .expect("ICMP shim should decode zero-length user data");
        assert!(matches!(event, PayloadEvent::UserData(_)));
        assert_eq!(event.wire().len(), 0);
    }

    #[test]
    fn validate_payload_decodes_non_empty_icmp_user_datagram() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), b"abc");

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(cfg.listen.id),
            PayloadOrigin::Wire,
            false,
        )
        .expect("ICMP shim should decode non-empty user data");
        assert!(matches!(event, PayloadEvent::UserData(_)));
        assert_eq!(event.wire().payload, b"abc");
    }

    #[test]
    fn validate_payload_wildcard_icmp_policy_accepts_any_identifier() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let mut buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
        buf[4] = 0xAA;
        buf[5] = 0x55;

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Any,
            PayloadOrigin::Wire,
            false,
        )
        .expect("wildcard ICMP policy should accept arbitrary identifier");
        assert_eq!(event.wire().src_ident, 0xAA55);
    }

    #[test]
    fn validate_payload_exact_icmp_policy_rejects_other_identifiers() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let mut buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
        buf[4] = 0xAA;
        buf[5] = 0x55;

        // 1. Rejects non-matching ID
        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(0x1111),
            PayloadOrigin::Wire,
            false,
            )
;
        assert!(res.is_err(), "exact policy should reject mismatching ID");
        assert!(
            res.unwrap_err().to_string().contains("identity mismatch"),
            "error message should mention identity mismatch"
        );

        // 2. Accepts matching ID
        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(0xAA55),
            PayloadOrigin::Wire,
            false,
        )
        .expect("exact policy should accept matching identifier");
        assert_eq!(event.wire().src_ident, 0xAA55);
    }

    #[test]
    fn validate_payload_accepts_empty_icmp_as_sync_keepalive() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let empty_icmp = [8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09];
        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &empty_icmp,
            IcmpIdPolicy::Exact(0x04D2),
            PayloadOrigin::Wire,
            false,
        )
        .expect("empty ICMP should be accepted as sync keepalive");
        assert!(!event.is_user_data());
    }

    #[test]
    fn validate_payload_rejects_invalid_icmp_shim() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let bad_reserved = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | 0x01), &[]);
        // Keepalive (0x00) but has_payload (0x40) set
        let bad_keepalive_with_flag = encode_icmp_payload(Some(ICMP_SHIM_HAS_PAYLOAD), &[]);
        // Keepalive (0x00) but has actual data bytes
        let bad_keepalive_with_payload = encode_icmp_payload(Some(0x00), b"x");
        // Data (0x80) with has_payload bit (0x40) but no bytes
        let bad_data_missing_payload =
            encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), &[]);
        // Data (0x80) without has_payload bit but has bytes
        let bad_data_with_unexpected_payload = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), b"x");

        for bad in [
            bad_reserved,
            bad_keepalive_with_flag,
            bad_keepalive_with_payload,
            bad_data_missing_payload,
            bad_data_with_unexpected_payload,
        ] {
            assert!(
                validate_payload(
                    true,
                    &cfg,
                    &stats,
                    &bad,
                    IcmpIdPolicy::Exact(cfg.listen.id),
                    PayloadOrigin::Wire,
                    false,
                    )

                .is_err(),
                "shim {:02X} should be rejected",
                bad.get(8).cloned().unwrap_or(0xFF)
            );
        }
    }

    #[test]
    fn validate_payload_max_payload_zero_allows_empty_data() {
        let mut cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        cfg.max_payload = 0;
        let stats = Stats::new();

        // UDP: 0 bytes OK, 1 byte Fail
        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &[],
                IcmpIdPolicy::Exact(cfg.listen.id),
                PayloadOrigin::Wire,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &[0],
                IcmpIdPolicy::Exact(cfg.listen.id),
                PayloadOrigin::Wire,
                false,
            )
            .is_err()
        );

        // ICMP: 1 byte shim (no payload) OK, 2 bytes (shim + 1 byte payload) Fail
        let mut cfg_icmp = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        cfg_icmp.max_payload = 0;

        let ok_icmp = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
        let over_icmp = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), &[0]);

        assert!(
            validate_payload(
                true,
                &cfg_icmp,
                &stats,
                &ok_icmp,
                IcmpIdPolicy::Exact(cfg_icmp.listen.id),
                PayloadOrigin::Wire,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                true,
                &cfg_icmp,
                &stats,
                &over_icmp,
                IcmpIdPolicy::Exact(cfg_icmp.listen.id),
                PayloadOrigin::Wire,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn validate_payload_max_payload_excludes_icmp_shim_byte() {
        let mut cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        cfg.max_payload = 3;
        let stats = Stats::new();
        let ok = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), b"abc");
        let over = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), b"abcd");

        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &ok,
                IcmpIdPolicy::Exact(cfg.listen.id),
                PayloadOrigin::Wire,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &over,
                IcmpIdPolicy::Exact(cfg.listen.id),
                PayloadOrigin::Wire,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn validate_payload_strict_handshake_rejections() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();

        // 1. Valid handshake (Unlocked, Echo Request, UserData)
        let mut buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_SOURCE_ID), &[]);
        let id_bytes = 0x2002u16.to_be_bytes();
        buf.insert(9, id_bytes[0]);
        buf.insert(10, id_bytes[1]);
        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(0x04D2),
            PayloadOrigin::Wire,
            false,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap().wire().src_ident, 0x2002);

        // 2. Reject Locked session
        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(0x04D2),
            PayloadOrigin::Wire,
            true,
        );
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("already locked session"));

        // 3. Reject Echo Reply
        buf[0] = 0; // Type 0 = Echo Reply
        // Need c2u=true but buffer type=0 (Reply) to trigger !src_is_req
        let res = validate_payload(
            true, // Expected Request (type 8), but got Reply (type 0)
            &cfg,
            &stats,
            &buf,
            IcmpIdPolicy::Exact(0x04D2),
            PayloadOrigin::Wire,
            false,
        );
        assert!(res.is_err(), "should reject Source ID on Echo Reply");
        let err_msg = res.unwrap_err().to_string();
        // validate_payload currently prioritize Echo type mismatch error over shim handshake checks if c2u=true
        assert!(err_msg.contains("identity mismatch") || err_msg.contains("on Echo Reply"));

        // 4. Reject Keepalive
        // Handshake bit 0x20 is set, but IS_DATA (0x80) is NOT set.
        let buf_ka = encode_icmp_payload(Some(ICMP_SHIM_HAS_SOURCE_ID), &[]);
        let mut buf_ka_full = [0u8; 11];
        buf_ka_full[..8].copy_from_slice(&[8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09]);
        buf_ka_full[8] = ICMP_SHIM_HAS_SOURCE_ID;
        let id_bytes = 0x2002u16.to_be_bytes();
        buf_ka_full[9] = id_bytes[0];
        buf_ka_full[10] = id_bytes[1];

        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf_ka_full,
            IcmpIdPolicy::Exact(0x04D2),
            PayloadOrigin::Wire,
            false,
        );
        assert!(res.is_err(), "should reject Source ID on Keepalive");
        assert!(res.unwrap_err().to_string().contains("on Keepalive packet"));
    }
}
