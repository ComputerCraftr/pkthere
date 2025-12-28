use crate::cli::{Config, SupportedProtocol};
use crate::net::checksum::checksum16;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::stats::Stats;
use socket2::{SockAddr, Socket, Type};

use std::io::{self, IoSlice};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering as AtomOrdering};
use std::time::Instant;

#[cfg(unix)]
const DEST_ADDR_REQUIRED: i32 = libc::EDESTADDRREQ;
#[cfg(windows)]
const DEST_ADDR_REQUIRED: i32 = 10039; // WSAEDESTADDRREQ

static REQUEST_ICMP_SEQ: AtomicU16 = AtomicU16::new(0);
static REPLY_ICMP_SEQ: AtomicU16 = AtomicU16::new(0);

pub(crate) struct ValidatedPayload<'a> {
    src_is_icmp: bool,
    src_seq: u16,
    dst_proto: SupportedProtocol,
    payload: &'a [u8],
    pub len: usize,
}

#[inline(always)]
const fn be16_16(b0: u8, b1: u8) -> u16 {
    b1 as u16 | ((b0 as u16) << 8)
}

#[inline]
pub(crate) fn validate_payload<'a>(
    c2u: bool,
    cfg: &Config,
    stats: &Stats,
    buf: &'a [u8],
    recv_port_id: u16,
) -> io::Result<ValidatedPayload<'a>> {
    // Determine source/destination protocol for this direction once.
    let (src_proto, dst_proto) = if c2u {
        (cfg.listen_proto, cfg.upstream_proto)
    } else {
        (cfg.upstream_proto, cfg.listen_proto)
    };

    // If the source side was ICMP, strip the 8-byte Echo header before forwarding.
    let (src_is_icmp, icmp_success, payload, src_ident, src_seq, src_is_req) = match src_proto {
        SupportedProtocol::ICMP => {
            let res = parse_icmp_echo_header(buf);
            (true, res.0, &res.1[res.2..res.3], res.4, res.5, res.6)
        }
        _ => (false, true, buf, recv_port_id, 0u16, c2u),
    };

    if !icmp_success {
        // Parsed as ICMP but the Echo header is missing or truncated.
        stats.drop_err(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP Echo header (missing or truncated)",
        ));
    }

    if c2u != src_is_req || src_ident != recv_port_id {
        // If this is the client->upstream direction and we received an ICMP Echo *reply* or
        // upstream->client and we received an ICMP Echo *request*, drop it to avoid feedback loops.
        // Also, ignore all packets with the wrong identity field.
        // This is a validation failure, not an I/O error on the socket.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP Echo direction or identity mismatch",
        ));
    }

    let len = payload.len();
    if len == 0 || len > cfg.max_payload {
        // Payload is well-formed but does not fit within configured bounds.
        stats.drop_oversize(c2u);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload length {} is zero or exceeds max {}",
                len, cfg.max_payload
            ),
        ));
    }

    Ok(ValidatedPayload {
        src_is_icmp,
        src_seq,
        dst_proto,
        payload,
        len,
    })
}

pub(crate) fn send_payload(
    c2u: bool,
    validated: &ValidatedPayload<'_>,
    sock: &Socket,
    sock_connected: bool,
    sock_type: Type,
    dest_sa: &SockAddr,
    dest_port_id: u16,
) -> io::Result<bool> {
    // Update ICMP reply sequence when we receive a request
    if validated.src_is_icmp && c2u {
        REPLY_ICMP_SEQ.store(validated.src_seq, AtomOrdering::Relaxed);
    }

    // Send according to destination protocol and connection state
    let send_res = match validated.dst_proto {
        SupportedProtocol::ICMP => send_icmp_echo(
            sock,
            sock_connected,
            sock_type,
            dest_sa,
            dest_port_id,
            !c2u,
            validated.payload,
        ),
        _ => {
            if sock_connected {
                sock.send(validated.payload)
            } else {
                sock.send_to(validated.payload, dest_sa)
            }
        }
    };

    match send_res {
        Ok(_) => Ok(true),
        Err(e) if sock_connected && e.raw_os_error() == Some(DEST_ADDR_REQUIRED) => {
            // Try sending one more time
            let retry_res = match validated.dst_proto {
                SupportedProtocol::ICMP => send_icmp_echo(
                    sock,
                    false,
                    sock_type,
                    dest_sa,
                    dest_port_id,
                    !c2u,
                    validated.payload,
                ),
                _ => sock.send_to(validated.payload, dest_sa),
            };

            match retry_res {
                // Propagate DEST_ADDR_REQUIRED and dest_addr_okay=false to the handler to update socket connection status
                Ok(_) => Ok(false),
                Err(retry_err) => Err(retry_err),
            }
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn handle_payload_result(
    c2u: bool,
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &Stats,
    last_seen_ns: &AtomicU64,
    validated: &ValidatedPayload<'_>,
    send_res: &io::Result<bool>,
    sock_connected: bool,
    dest_sa: &SockAddr,
    disconnect_ctx: Option<(&mut SocketHandles, &SocketManager)>,
) {
    match send_res {
        Ok(res) => {
            last_seen_ns.store(Stats::dur_ns(t_start, t_recv), AtomOrdering::Relaxed);
            if cfg.stats_interval_mins != 0 {
                let t_send = Instant::now();
                stats.send_add(c2u, validated.len as u64, t_recv, t_send);
            }

            if !*res {
                if let Some((handles, sock_mgr)) = disconnect_ctx {
                    if handles.client_connected {
                        let prev_ver = handles.version;
                        log_warn_dir!(
                            worker_id,
                            c2u,
                            "send_payload error (EDESTADDRREQ); disconnecting client socket"
                        );
                        handles.client_connected = false;
                        handles.version = match sock_mgr.set_client_sock_disconnected(
                            handles.client_addr,
                            false,
                            prev_ver,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                log_warn_dir!(worker_id, c2u, "udp_disconnect failed: {}", e);
                                prev_ver
                            }
                        };
                        log_debug_dir!(
                            cfg.debug_log_handles,
                            worker_id,
                            c2u,
                            "publish disconnect: addr={:?} ver {}->{}",
                            handles.client_addr,
                            prev_ver,
                            handles.version
                        );
                    }
                }
            }
        }
        Err(e) => {
            log_debug_dir!(
                cfg.debug_log_drops,
                worker_id,
                c2u,
                "send_payload error ({} on dest_sa '{:?}'): {}",
                if sock_connected && e.raw_os_error() != Some(DEST_ADDR_REQUIRED) {
                    "send"
                } else {
                    "send_to"
                },
                dest_sa.as_socket(),
                e
            );
            stats.drop_err(c2u);
        }
    };
}

/// Some OSes (notably Linux for IPv4 raw sockets) deliver the full IP header
/// followed by the ICMP message. Others deliver only the ICMP message.
///
/// This helper normalizes those cases by:
///   * detecting an IPv4/IPv6 header using only header-structure fields
///   * advancing `off` to the start of the ICMP Echo header *only* when a full
///     IP header and 8-byte Echo header fit in the buffer
///   * treating the buffer as starting at the ICMP header when no valid IP
///     header is detected
///   * validating ICMP(v6) Echo type/code (v4: 8/0; v6: 128/129 with code 0)
///   * stripping the 8-byte ICMP Echo header and returning the remaining payload
///
/// The return tuple is `(ok, payload, payload_begin, payload_end, ident, seq, is_request)` where:
///   * `ok` is `true` iff a complete ICMP(v6) Echo {request, reply} header with
///     code 0 was found and validated.
///   * `payload` is the payload buffer.
///   * `payload_begin..payload_end` is the slice after the Echo header when `ok == true`,
///     or an empty slice otherwise.
///   * `ident` is the Echo identifier field (undefined when `ok == false`).
///   * `seq` is the Echo sequence field (undefined when `ok == false`).
///   * `is_request` is `true` for Echo Request and `false` for Echo Reply
///     (undefined when `ok == false`).
///
/// The mask-based arithmetic (`is_v4`, `is_v6`, `room_v4`, `room_v6`,
/// `have_hdr`, `success`) is intentional: this function runs on the ICMP
/// hot path and has been shaped to minimize unpredictable branches and bounds
/// checks. If you change it, re-benchmark under load before simplifying the
/// control flow.
#[inline]
const fn parse_icmp_echo_header(payload: &[u8]) -> (bool, &[u8], usize, usize, u16, u16, bool) {
    const ZERO_ARRAY: [u8; 1] = [0];
    let n = payload.len();

    // Probe bytes: read 0,6,9 only when available; otherwise treat as zeroes.
    let has0 = (n >= 1) as usize;
    let buf = if has0 != 0 { payload } else { &ZERO_ARRAY };
    let has9 = (n >= 10) as usize; // need index 6+9
    let b9 = buf[9 * has9];
    let b6 = buf[6 * has9];
    let b0 = buf[0];

    // Version nibble and IPv4 IHL (header length in bytes, from 4-byte words)
    let ver = (b0 >> 4) as usize;
    let ihl = ((b0 as usize) & 0x0F) << 2;

    // Boolean masks as 0/1 integers
    let is_v4 = (ver == 4) as usize;
    let is_v6 = (ver == 6) as usize;

    // Sanity / length masks (0 or 1).
    // With a sane IHL (>=20), `room_v4` implies n >= ihl + 8 >= 28 total bytes
    // (IPv4 header + 8-byte ICMP Echo header).
    let sane_ihl = (ihl >= 20) as usize;
    let proto_icmp = (b9 == 1) as usize; // IPv4 protocol == ICMP
    let room_v4 = (n >= ihl + 8) as usize; // requires sane_ihl to be useful

    // For IPv6, `room_v6` (n >= 48) ensures a 40-byte IPv6 header plus 8-byte ICMPv6 Echo fits.
    let next_icmp6 = (b6 == 58) as usize; // IPv6 Next Header == ICMPv6
    let room_v6 = (n >= 48) as usize; // 40 (IPv6) + 8 (ICMPv6)

    // Compute offsets multiplied by masks (either ihl or 40, else 0).
    // If no header path matches, both masks are 0 and `off` stays 0
    // (treat buffer as starting at the ICMP header).
    let off_v4 = ihl * (is_v4 & sane_ihl & proto_icmp & room_v4);
    let off_v6 = 40usize * (is_v6 & next_icmp6 & room_v6);

    // Since ver is either 4 or 6 (or neither), these are mutually exclusive; 'or' is safe.
    let off = off_v4 | off_v6;

    // Consolidated validation: `have_hdr` gates all ICMP header reads.
    // When `have_hdr == 0`, indices collapse to 0 and we read buf[0] (harmless).
    // When `have_hdr == 1`, we know an 8-byte Echo header fits at `off`.
    let have_hdr = (n >= off + 8) as usize;
    let icmp_code = buf[(off + 1) * have_hdr];
    let icmp_type = buf[off * have_hdr];

    // `success` gates all further ICMP-field indexing and the payload slice bounds.
    let success_bool = have_hdr == 1 && icmp_code == 0 && matches!(icmp_type, 8 | 0 | 128 | 129);
    let success = success_bool as usize;

    // Identifier is bytes 4..6 of the ICMP Echo header (for both v4 and v6 Echo).
    let ident_b1 = buf[(off + 5) * success];
    let ident_b0 = buf[(off + 4) * success];
    let ident = be16_16(ident_b0, ident_b1);

    // Sequence is bytes 6..8 of the ICMP Echo header (for both v4 and v6 Echo).
    let seq_b1 = buf[(off + 7) * success];
    let seq_b0 = buf[(off + 6) * success];
    let seq = be16_16(seq_b0, seq_b1);

    let is_request = matches!(icmp_type, 8 | 128);

    // On failure, `success == 0` collapses the slice to 0..0 (empty) rather than indexing at `off`.
    (
        success_bool,
        &buf,
        (off + 8) * success,
        n * success,
        ident,
        seq,
        is_request,
    )
}

/// Send an ICMP Echo Request or Reply (IPv4 or IPv6).
fn send_icmp_echo(
    sock: &Socket,
    sock_connected: bool,
    sock_type: Type,
    dest_sa: &SockAddr,
    ident: u16,
    reply: bool,
    payload: &[u8],
) -> io::Result<usize> {
    let seq = if reply {
        REPLY_ICMP_SEQ.load(AtomOrdering::Relaxed)
    } else {
        REQUEST_ICMP_SEQ.fetch_add(1, AtomOrdering::Relaxed)
    };
    let mut hdr = [0u8; 8];

    let idb = ident.to_be_bytes();
    let sqb = seq.to_be_bytes();

    // hdr[1] = 0; hdr[2..4] = 0 (placeholder for checksum)
    hdr[4] = idb[0];
    hdr[5] = idb[1];
    hdr[6] = sqb[0];
    hdr[7] = sqb[1];

    // Dest family picks ICMP type and whether we should compute the checksum
    let cksum = match (dest_sa, sock_type) {
        // ICMPv6 Echo: type=128(req)/129(rep), code=0; checksum always handled in-kernel.
        (sa, _) if sa.is_ipv6() => {
            hdr[0] = 128u8 | (reply as u8);
            0u16
        }
        // ICMPv4 Echo: type=8(req)/0(rep), code=0.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        _ => {
            hdr[0] = 8u8 * (!reply as u8);
            checksum16(&hdr, payload)
        }
        // RAW sockets require a manual checksum; datagram sockets get it from the Linux kernel.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        (_, ty) if ty == Type::RAW => {
            hdr[0] = 8u8 * (!reply as u8);
            checksum16(&hdr, payload)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        _ => {
            hdr[0] = 8u8 * (!reply as u8);
            0u16
        }
    };

    hdr[2] = (cksum >> 8) as u8;
    hdr[3] = (cksum & 0xFF) as u8;

    let iov = [IoSlice::new(&hdr), IoSlice::new(payload)];
    if sock_connected {
        sock.send_vectored(&iov)
    } else {
        sock.send_to_vectored(&iov, dest_sa)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_icmp_echo_header_accepts_ipv4_with_ip_header() {
        let icmp_payload = [0xDEu8, 0xAD, 0xBE];
        let mut buf = vec![0u8; 20 + 8 + icmp_payload.len()];

        // IPv4 header (version 4, IHL 5, protocol ICMP)
        buf[0] = 0x45;
        buf[8] = 64;
        buf[9] = 1;

        // ICMP Echo Request header
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

        // IPv6 header (version 6, Next Header ICMPv6)
        buf[0] = 0x60;
        buf[6] = 58;

        // ICMPv6 Echo Reply header
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
}
