#[path = "../src/net/packet_headers.rs"]
mod packet_headers;
#[path = "../src/recv_buf.rs"]
mod recv_buf;

use packet_headers::parse_packet_headers;
use recv_buf::RecvBuf;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

#[cfg(test)]
const BOUND_RAW_PROBE_SEQ: u16 = 0x5a71;
#[cfg(test)]
const BOUND_RAW_PROBE_TAG: &[u8] = b"pkthere-bound-raw-request-probe";

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawLoopbackProbeResult {
    EchoRequest,
    OnlyEchoReply,
    NoMatchingIcmp,
}

pub fn probe_kernel_icmp_echo() -> io::Result<()> {
    let (sock, _sock_type) =
        if let Ok(s) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
            (s, Type::DGRAM)
        } else if let Ok(s) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            (s, Type::RAW)
        } else {
            return Err(io::Error::other("could not create ICMP socket"));
        };

    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let mut request = [
        8u8, 0, 0, 0, 0, 0, 0, 0, b'p', b'k', b't', b'h', b'e', b'r', b'e',
    ];
    let mut sum = 0u32;
    let (chunks, remainder) = request.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    request[2..4].copy_from_slice(&checksum.to_be_bytes());

    let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    sock.connect(&SockAddr::from(dest))?;
    sock.send(&request)?;

    let mut recv_buf = RecvBuf::<2048>::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        match sock.recv(recv_buf.recv_buf_mut()) {
            Ok(n) => {
                if n < 8 {
                    continue;
                }
                let buf = recv_buf.initialized(n);

                let parsed = parse_packet_headers(buf);
                if parsed.icmp.is_some_and(|icmp| !icmp.is_req) {
                    return Ok(());
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "kernel did not provide ICMP echo reply on localhost",
    ))
}

#[cfg(test)]
pub fn probe_bound_raw_icmp_loopback_request_delivery(
    ip: Ipv4Addr,
    ident: u16,
    timeout: Duration,
) -> io::Result<RawLoopbackProbeResult> {
    let listener = Socket::new(Domain::IPV4, Type::RAW, Some(raw_listener_protocol()))?;
    listener.set_read_timeout(Some(Duration::from_millis(50)))?;
    listener.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
        ip, ident,
    ))))?;

    #[cfg(windows)]
    enable_rcvall(&listener)?;

    let sender = make_icmp_sender()?;
    sender.set_read_timeout(Some(Duration::from_millis(50)))?;
    let request = build_probe_request(ident, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
    let dest = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(ip, ident)));
    sender.send_to(&request, &dest)?;

    let deadline = Instant::now() + timeout;
    let mut recv_buf = RecvBuf::<2048>::new();
    let mut saw_reply = false;
    while Instant::now() < deadline {
        match listener.recv(recv_buf.recv_buf_mut()) {
            Ok(n) => {
                let buf = recv_buf.initialized(n);
                match classify_bound_raw_probe_packet(buf, ident, BOUND_RAW_PROBE_SEQ) {
                    Some(RawLoopbackProbeResult::EchoRequest) => {
                        return Ok(RawLoopbackProbeResult::EchoRequest);
                    }
                    Some(RawLoopbackProbeResult::OnlyEchoReply) => saw_reply = true,
                    _ => {}
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    if saw_reply {
        Ok(RawLoopbackProbeResult::OnlyEchoReply)
    } else {
        Ok(RawLoopbackProbeResult::NoMatchingIcmp)
    }
}

#[cfg(test)]
fn classify_bound_raw_probe_packet(
    packet: &[u8],
    ident: u16,
    seq: u16,
) -> Option<RawLoopbackProbeResult> {
    let parsed = parse_packet_headers(packet);
    let icmp = parsed.icmp?;
    if icmp.ident != ident || icmp.seq != seq {
        return None;
    }
    let (payload_start, payload_end) = parsed.payload_bounds;
    if payload_end < payload_start || packet.get(payload_start..payload_end)? != BOUND_RAW_PROBE_TAG
    {
        return None;
    }
    if icmp.is_req {
        Some(RawLoopbackProbeResult::EchoRequest)
    } else {
        Some(RawLoopbackProbeResult::OnlyEchoReply)
    }
}

#[cfg(test)]
fn make_icmp_sender() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))
}

#[cfg(test)]
fn build_probe_request(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![8u8, 0, 0, 0, 0, 0, 0, 0];
    packet[4..6].copy_from_slice(&ident.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = checksum16(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[cfg(test)]
fn checksum16(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let chunks = buf.chunks_exact(2);
    let remainder = chunks.remainder();
    for chunk in chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(all(test, windows))]
fn raw_listener_protocol() -> Protocol {
    Protocol::from(0)
}

#[cfg(all(test, not(windows)))]
fn raw_listener_protocol() -> Protocol {
    Protocol::ICMPV4
}

#[cfg(all(test, windows))]
fn enable_rcvall(sock: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{RCVALL_IPLEVEL, SIO_RCVALL, WSAIoctl};

    let mut bytes_returned = 0;
    let option: u32 = RCVALL_IPLEVEL as u32;

    let res = unsafe {
        WSAIoctl(
            sock.as_raw_socket() as _,
            SIO_RCVALL,
            &option as *const _ as _,
            std::mem::size_of_val(&option) as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };

    if res == 0 {
        Ok(())
    } else {
        use windows_sys::Win32::Networking::WinSock::WSAGetLastError;
        let err = unsafe { WSAGetLastError() };
        Err(io::Error::from_raw_os_error(err))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG, RawLoopbackProbeResult, build_probe_request,
        classify_bound_raw_probe_packet,
    };

    #[test]
    fn bound_raw_probe_classifier_distinguishes_echo_request() {
        let packet = build_probe_request(0x4567, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
        assert_eq!(
            classify_bound_raw_probe_packet(&packet, 0x4567, BOUND_RAW_PROBE_SEQ),
            Some(RawLoopbackProbeResult::EchoRequest)
        );
    }

    #[test]
    fn bound_raw_probe_classifier_distinguishes_echo_reply() {
        let mut packet = build_probe_request(0x4567, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
        packet[0] = 0;
        assert_eq!(
            classify_bound_raw_probe_packet(&packet, 0x4567, BOUND_RAW_PROBE_SEQ),
            Some(RawLoopbackProbeResult::OnlyEchoReply)
        );
    }

    #[test]
    fn bound_raw_probe_classifier_ignores_wrong_id_or_payload() {
        let packet = build_probe_request(0x4567, BOUND_RAW_PROBE_SEQ, b"other");
        assert_eq!(
            classify_bound_raw_probe_packet(&packet, 0x4567, BOUND_RAW_PROBE_SEQ),
            None
        );
        let packet = build_probe_request(0x9999, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
        assert_eq!(
            classify_bound_raw_probe_packet(&packet, 0x4567, BOUND_RAW_PROBE_SEQ),
            None
        );
    }
}
