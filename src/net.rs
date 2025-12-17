use crate::cli::{Config, SupportedProtocol};
use crate::stats::Stats;
use bytemuck::{must_cast_ref, pod_align_to, pod_read_unaligned};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use wide::u32x16;

use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering as AtomOrdering};
use std::time::{Duration, Instant};

#[cfg(unix)]
const DEST_ADDR_REQUIRED: i32 = libc::EDESTADDRREQ;
#[cfg(windows)]
const DEST_ADDR_REQUIRED: i32 = 10039; // WSAEDESTADDRREQ

const WORD_LO_U32: u32 = 0x0000_FFFF;
const SWAP_LO_U32: u32 = 0xFF00_FF00;
const SWAP_HI_U32: u32 = 0x00FF_00FF;
const SWAP_LO_U64: u64 = 0xFF00_FF00_FF00_FF00;
const SWAP_HI_U64: u64 = 0x00FF_00FF_00FF_00FF;

static REQUEST_ICMP_SEQ: AtomicU16 = AtomicU16::new(0);
static REPLY_ICMP_SEQ: AtomicU16 = AtomicU16::new(0);

#[inline(always)]
const fn be16_16(b0: u8, b1: u8) -> u16 {
    b1 as u16 | ((b0 as u16) << 8)
}

#[inline(always)]
const fn be16_32(b0: u8, b1: u8) -> u32 {
    b1 as u32 | ((b0 as u32) << 8)
}

#[inline(always)]
fn be16_32_sum2(bytes: &[u8; 4]) -> u32 {
    // `x` is read in native endianness from bytes [b0,b1,b2,b3].
    // Little-endian: swap bytes within each halfword; big-endian: halves already match wire order.
    let mut x = pod_read_unaligned::<u32>(bytes);
    #[cfg(target_endian = "little")]
    {
        let swapped = ((x << 8) & SWAP_LO_U32) | ((x >> 8) & SWAP_HI_U32);
        x = swapped;
    }
    (x & WORD_LO_U32) + (x >> 16)
}

#[inline(always)]
fn be16_32_sum4(bytes: &[u8; 8]) -> u32 {
    // Same idea as `be16_32_sum2`, but over 8 bytes (four 16-bit words).
    let mut x = pod_read_unaligned::<u64>(bytes);
    #[cfg(target_endian = "little")]
    {
        let swapped = ((x << 8) & SWAP_LO_U64) | ((x >> 8) & SWAP_HI_U64);
        x = swapped;
    }
    (x as u32 & WORD_LO_U32)
        + (x as u32 >> 16)
        + ((x >> 32) as u32 & WORD_LO_U32)
        + ((x >> 48) as u32)
}

#[inline(always)]
fn csum_icmp_echo_hdr(hdr: &[u8; 8]) -> u32 {
    // Header: type,code ; checksum(0) ; ident ; seq
    // checksum field (hdr[2..4]) is treated as zero.
    let mut sum = be16_32(hdr[0], hdr[1]);
    sum += be16_32_sum2((&hdr[4..8]).try_into().unwrap());
    sum
}

#[inline(always)]
fn csum_bytes(bytes: &[u8]) -> u32 {
    // Sum the byte stream as RFC1071 16-bit big-endian words.
    // Pairing starts at bytes[0]. Odd tail byte contributes as the high byte of the final word.
    let mut sum = 0;

    // Fast path: 8 bytes (64 bits) at a time.
    let (chunks8, rem8) = bytes.as_chunks::<8>();
    for c in chunks8 {
        sum += be16_32_sum4(c);
    }

    // Next: 2 bytes (one word).
    let (chunks2, rem2) = rem8.as_chunks::<2>();
    for c in chunks2 {
        sum += be16_32(c[0], c[1]);
    }

    // Odd tail: last byte is the high byte of the final 16-bit word.
    if let [last] = rem2 {
        sum += (*last as u32) << 8;
    }
    sum
}

#[inline(always)]
const fn fold32_16(mut sum: u32) -> u16 {
    // End-around carry fold down to 16 bits.
    sum = (sum & WORD_LO_U32) + (sum >> 16);
    sum = (sum & WORD_LO_U32) + (sum >> 16);
    sum as u16
}

/// Create a socket (UDP datagram or ICMP) bound to `bind_addr`.
/// Returns the socket and the actual local SocketAddr after bind (for ICMP
/// datagram sockets the kernel may assign an identifier/port). When ICMP is
/// requested, `force_raw_icmp` can be used to skip the datagram attempt (needed
/// for listeners that must see incoming Echo Requests).
pub fn make_socket(
    bind_addr: SocketAddr,
    proto: SupportedProtocol,
    read_timeout_ms: u64,
    reuseaddr: bool,
    force_raw_icmp: bool,
) -> io::Result<(Socket, SocketAddr)> {
    // Raw ICMP: use well-known protocol numbers (see IANA)
    // IPv4 ICMP = 1, IPv6 ICMP = 58; same on Unix and Windows.
    let (domain, icmp_proto) = match bind_addr {
        SocketAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        _ => (Domain::IPV4, Protocol::ICMPV4),
    };

    let sock = match proto {
        SupportedProtocol::ICMP => {
            // Linux kernels expose SOCK_DGRAM ping sockets when ping_group_range
            // permits it; fall back to raw sockets elsewhere.
            make_icmp_socket(domain, icmp_proto, force_raw_icmp)?
        }
        _ => Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?,
    };

    if reuseaddr {
        sock.set_reuse_address(true)?;
        // Best effort: only some platforms support SO_REUSEPORT.
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
    }

    // Best-effort bigger buffers
    sock.set_recv_buffer_size(1 << 20)?;
    sock.set_send_buffer_size(1 << 20)?;

    // Bind
    let bind_sa = SockAddr::from(bind_addr);
    sock.bind(&bind_sa)?;

    // Read timeout
    sock.set_read_timeout(if read_timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(read_timeout_ms))
    })?;

    let actual_local = if force_raw_icmp {
        bind_addr
    } else {
        sock.local_addr()?.as_socket().unwrap_or(bind_addr)
    };

    Ok((sock, actual_local))
}

fn make_icmp_socket(domain: Domain, proto: Protocol, force_raw: bool) -> io::Result<Socket> {
    if force_raw {
        return Socket::new(domain, Type::RAW, Some(proto));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        // Linux/Android/macOS expose ping sockets as SOCK_DGRAM that enforce ICMP checksum
        // and avoid raw socket privileges. Prefer that path, but gracefully fall back to
        // SOCK_RAW if the kernel denies access or the feature is disabled.
        match Socket::new(domain, Type::DGRAM, Some(proto)) {
            Ok(sock) => Ok(sock),
            Err(err) => {
                log_warn!(
                    "ICMP datagram sockets unavailable on {:?} ({err}); falling back to raw sockets",
                    domain
                );
                Socket::new(domain, Type::RAW, Some(proto))
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        // Other OSes do not expose ping sockets via SOCK_DGRAM; raw sockets are the
        // only option for sending ICMP Echo traffic.
        Socket::new(domain, Type::RAW, Some(proto))
    }
}

pub fn send_payload(
    c2u: bool,
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &Stats,
    last_seen: &AtomicU64,
    sock: &Socket,
    buf: &[u8],
    sock_connected: bool,
    sock_type: Type,
    dest_sa: &SockAddr,
    dest_port_id: u16,
    recv_port_id: u16,
    log_drops: bool,
) -> bool {
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

    // Size check on the normalized payload.
    let len = payload.len();

    // Handle forwarding errors
    if !icmp_success {
        log_debug_dir!(
            log_drops,
            worker_id,
            c2u,
            "Dropping packet: Invalid or truncated ICMP Echo header"
        );
        stats.drop_err(c2u);
        return true;
    } else if c2u != src_is_req || src_ident != recv_port_id {
        // If this is the client->upstream direction and we received an ICMP Echo *reply* or
        // upstream->client and we received an ICMP Echo *request*, drop it to avoid feedback loops.
        // Also, ignore all packets with the wrong identity field.

        // Not an error; just ignore replies from the client side.
        log_debug_dir!(
            log_drops,
            worker_id,
            c2u,
            "Dropping packet: Wrong direction or identity"
        );
        return true;
    } else if len > cfg.max_payload {
        log_debug_dir!(
            log_drops,
            worker_id,
            c2u,
            "Dropping packet: {} bytes exceeds max {}",
            len,
            cfg.max_payload
        );
        stats.drop_oversize(c2u);
        return true;
    }

    // Update ICMP reply sequence when we receive a request
    if src_is_icmp && c2u {
        REPLY_ICMP_SEQ.store(src_seq, AtomOrdering::Relaxed);
    }

    // Send according to destination protocol and connection state.
    let mut dest_addr_okay = true;
    let send_res = match dst_proto {
        SupportedProtocol::ICMP => send_icmp_echo(
            sock,
            sock_connected,
            sock_type,
            dest_sa,
            dest_port_id,
            !c2u,
            payload,
        ),
        _ => {
            if sock_connected {
                sock.send(payload)
            } else {
                sock.send_to(payload, dest_sa)
            }
        }
    };

    if let Ok(_) = send_res {
        let t_send = Instant::now();
        last_seen.store(Stats::dur_ns(t_start, t_send), AtomOrdering::Relaxed);
        stats.send_add(c2u, len as u64, t_recv, t_send);
    } else if sock_connected && is_dest_addr_required(&send_res) {
        dest_addr_okay = false;

        // Try sending one more time
        let retry_res = match dst_proto {
            SupportedProtocol::ICMP => {
                send_icmp_echo(sock, false, sock_type, dest_sa, dest_port_id, !c2u, payload)
            }
            _ => sock.send_to(payload, dest_sa),
        };

        match retry_res {
            Ok(_) => {
                let t_send = Instant::now();
                last_seen.store(Stats::dur_ns(t_start, t_send), AtomOrdering::Relaxed);
                stats.send_add(c2u, len as u64, t_recv, t_send);
            }
            Err(e) => {
                log_debug_dir!(
                    log_drops,
                    worker_id,
                    c2u,
                    "send_to on dest_sa '{:?}' error: {}",
                    dest_sa.as_socket(),
                    e
                );
                stats.drop_err(c2u);
            }
        }
    } else if let Err(e) = send_res {
        log_debug_dir!(
            log_drops,
            worker_id,
            c2u,
            "{} on dest_sa '{:?}' error: {}",
            if sock_connected { "send" } else { "send_to" },
            dest_sa.as_socket(),
            e
        );
        stats.drop_err(c2u);
    }
    dest_addr_okay
}

#[inline]
fn is_dest_addr_required(res: &io::Result<usize>) -> bool {
    matches!(res, Err(e) if e.raw_os_error() == Some(DEST_ADDR_REQUIRED))
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

/// Create and connect a socket suitable for forwarding data to `dest`.
pub fn make_upstream_socket_for(
    dest: SocketAddr,
    proto: SupportedProtocol,
) -> io::Result<(Socket, SocketAddr)> {
    let local_port = if proto == SupportedProtocol::ICMP {
        dest.port()
    } else {
        0
    };
    let bind_addr = match dest {
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_port),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port),
    };

    let (sock, _) = make_socket(bind_addr, proto, 1000, false, false)?;

    let dest_sa = SockAddr::from(dest);
    sock.connect(&dest_sa)?;
    let actual_dest = sock.peer_addr()?.as_socket().unwrap_or(bind_addr);

    Ok((sock, actual_dest))
}

#[inline]
pub fn resolve_first(addr: &str) -> io::Result<SocketAddr> {
    // Fast path: direct SocketAddr parse (no DNS, no allocations).
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }

    // Fallback: resolve host:port or [IPv6]:port via DNS.
    let mut iter = addr.to_socket_addrs()?;
    iter.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No address resolved"))
}

#[inline]
pub const fn family_changed(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => false,
        _ => true,
    }
}

/// Disconnect a connected UDP socket so it returns to wildcard receive state.
///
/// macOS/*BSD man page: datagram sockets may dissolve the association by
/// connecting to an invalid address (NULL or AF_UNSPEC). The error
/// EAFNOSUPPORT may be harmlessly returned; consider it success.
#[cfg(unix)]
pub fn udp_disconnect(sock: &Socket) -> io::Result<()> {
    let fd = sock.as_raw_fd();

    // Interpret connect() rc correctly per platform.
    #[inline]
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    fn ok_or_eafnosupport(rc: i32) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAFNOSUPPORT) {
                // macOS/*BSD man page: harmless when disconnecting UDP
                Ok(())
            } else {
                Err(err)
            }
        }
    }

    // On non-BSD Unix (Linux/Android), do NOT ignore EAFNOSUPPORT.
    #[inline]
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    fn ok_or_eafnosupport(rc: i32) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    // --- macOS / iOS / *BSD: try AF_UNSPEC first, then NULL ---
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    {
        // sockaddr WITH sa_len on these platforms
        let addr = libc::sockaddr {
            sa_len: std::mem::size_of::<libc::sockaddr>() as u8,
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr,
                addr.sa_len as libc::socklen_t,
            )
        };
        if ok_or_eafnosupport(rc).is_ok() {
            return Ok(());
        }

        // Fallback: connect(fd, NULL, 0)
        let rc2 = unsafe { libc::connect(fd, std::ptr::null(), 0) };
        return ok_or_eafnosupport(rc2);
    }

    // --- Linux/Android: AF_UNSPEC is the standard way; no sa_len field. ---
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    {
        let addr = libc::sockaddr {
            sa_family: libc::AF_UNSPEC as libc::sa_family_t,
            sa_data: [0; 14],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };
        return ok_or_eafnosupport(rc);
    }
}

/// Windows: disconnect a UDP socket by connecting to INADDR_ANY/IN6ADDR_ANY and port 0.
#[cfg(windows)]
pub fn udp_disconnect(sock: &Socket) -> io::Result<()> {
    let local = sock.local_addr()?;
    let any_std = match local.as_socket() {
        Some(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    // Winsock treats connect(INADDR_ANY/IN6ADDR_ANY:0) as clearing the UDP peer
    let any = SockAddr::from(any_std);
    sock.connect(&any)
}

/// Fallback: not supported on this platform.
#[cfg(all(not(unix), not(windows)))]
pub fn udp_disconnect(_sock: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Function udp_disconnect is not supported on this OS",
    ))
}

/// Compute the Internet Checksum (RFC 1071) for ICMPv4 Echo header+payload.
///
/// The Internet checksum is a 1's-complement sum of 16-bit words in network byte
/// order (big-endian), with end-around carry, and then bitwise complemented.
///
/// Implementation notes:
///   * We use `wide::u32x16` to process 64-byte chunks as 16 lanes of `u32` (4 bytes per lane).
///     For a lane containing bytes `[b0,b1,b2,b3]` in memory, the RFC1071 contribution is:
///       `(b0<<8)+b1 + (b2<<8)+b3`
///   * On little-endian, the `u32` value is `v = b0 + (b1<<8) + (b2<<16) + (b3<<24)`.
///     Swapping bytes within each 16-bit halfword yields `[b1,b0,b3,b2]`, so the low 16 bits
///     become `(b0<<8)+b1` and the high 16 bits become `(b2<<8)+b3`. The per-lane contribution is:
///       `(swapped & 0xFFFF) + (swapped >> 16)`
///   * Big-endian hosts already match wire order, so we can split the 16-bit halves directly.
///
/// Uses a scalar fast path for small payloads and a wide SIMD path for medium/large payloads.
/// All casting is size-preserving and safe.
#[inline]
fn checksum16(hdr: &[u8; 8], data: &[u8]) -> u16 {
    // Use a u32 scalar accumulator for MAX_WIRE_PAYLOAD so we never rely on overflow before folding.
    let mut sum = csum_icmp_echo_hdr(hdr);

    // SIMD over 64-byte chunks (16 u32 lanes per iteration).
    let (head, aligned, tail) = pod_align_to::<u8, u32x16>(data);

    // Masks are loop-invariant; keep them as constants.
    const WORD_LO: u32x16 = u32x16::splat(WORD_LO_U32);
    const SWAP_LO: u32x16 = u32x16::splat(SWAP_LO_U32);
    const SWAP_HI: u32x16 = u32x16::splat(SWAP_HI_U32);

    let lane_contribution = |v: u32x16| -> u32x16 {
        #[cfg(target_endian = "little")]
        {
            // Swap bytes within each 16-bit halfword: [b0,b1,b2,b3] -> [b1,b0,b3,b2] in each lane.
            // Then sum the two 16-bit halves to get the RFC1071 contribution for the lane.
            let swapped = ((v << 8) & SWAP_LO) | ((v >> 8) & SWAP_HI);
            (swapped & WORD_LO) + (swapped >> 16)
        }

        #[cfg(target_endian = "big")]
        {
            // Big-endian: lane already matches wire order; split into two u16 halves directly.
            (v & WORD_LO) + (v >> 16)
        }
    };

    // SIMD accumulation over 64-byte chunks (16 lanes of u32). Each lane produces the RFC1071
    // contribution of its two 16-bit words; end-around carry is folded later via `fold32_16()`.
    let mut vsum = u32x16::ZERO;
    let mut idx = 0;
    let len = aligned.len();

    while idx + 3 < len {
        vsum += lane_contribution(aligned[idx])
            + lane_contribution(aligned[idx + 1])
            + lane_contribution(aligned[idx + 2])
            + lane_contribution(aligned[idx + 3]);
        idx += 4;
    }

    while idx + 1 < len {
        vsum += lane_contribution(aligned[idx]) + lane_contribution(aligned[idx + 1]);
        idx += 2;
    }

    if idx < len {
        vsum += lane_contribution(aligned[idx]);
    }

    // Horizontally reduce 16 u32 lanes using 8 packed pairs.
    // We accumulate low and high halves separately to avoid carry mixing.
    let pairs = must_cast_ref::<u32x16, [u64; 8]>(&vsum);
    let mut lo = 0;
    let mut hi = 0;
    for &p in pairs {
        lo += p as u32;
        hi += (p >> 32) as u32;
    }
    sum += lo + hi;

    // Handle the remaining bytes (both prefix and suffix) scalarly.
    sum += csum_bytes(head) + csum_bytes(tail);

    // Final 1’s-complement fold down to 16 bits.
    !(fold32_16(sum))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAX_WIRE_PAYLOAD;

    fn reference_checksum(hdr: &[u8; 8], data: &[u8]) -> u16 {
        let mut sum = csum_icmp_echo_hdr(hdr);
        sum += csum_bytes(data);
        !(fold32_16(sum))
    }

    #[test]
    fn checksum16_matches_reference_small_payloads() {
        let hdr = [8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let even_payload = [1u8, 2, 3, 4];
        let odd_payload = [0xAAu8, 0xBB, 0xCC];

        assert_eq!(
            checksum16(&hdr, &even_payload),
            reference_checksum(&hdr, &even_payload)
        );
        assert_eq!(
            checksum16(&hdr, &odd_payload),
            reference_checksum(&hdr, &odd_payload)
        );
    }

    #[test]
    fn checksum16_handles_large_payloads() {
        let hdr = [8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let payload: Vec<u8> = (0..400).map(|i| i as u8).collect();

        assert_eq!(
            checksum16(&hdr, &payload),
            reference_checksum(&hdr, &payload)
        );
    }

    #[test]
    fn checksum16_handles_max_wire_payload() {
        let hdr = [8, 0, 0, 0, 0xAB, 0xCD, 0x00, 0x01];
        let payload: Vec<u8> = (0..MAX_WIRE_PAYLOAD).map(|i| (i % 251) as u8).collect();

        assert_eq!(
            checksum16(&hdr, &payload),
            reference_checksum(&hdr, &payload)
        );
    }

    #[test]
    fn checksum16_handles_max_wire_payload_all_ff() {
        let hdr = [8, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        let payload = vec![0xFFu8; MAX_WIRE_PAYLOAD];

        assert_eq!(
            checksum16(&hdr, &payload),
            reference_checksum(&hdr, &payload)
        );
    }

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
