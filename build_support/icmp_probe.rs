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

const BOUND_RAW_PROBE_SEQ: u16 = 0x5a71;
const BOUND_RAW_PROBE_TAG: &[u8] = b"pkthere-bound-raw-request-probe";
const KERNEL_ECHO_PROBE_SEQ: u16 = 0;
const KERNEL_ECHO_PROBE_TAG: &[u8] = b"pkthere";
const RAW_CAPABILITY_PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const RAW_CAPABILITY_NODE2_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const RAW_CAPABILITY_NODE3_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const RAW_CAPABILITY_CONCRETE_ID: u16 = 1001;
const RAW_CAPABILITY_REMOTE_ID: u16 = 3003;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawLoopbackProbeResult {
    EchoRequest,
    EchoRequestAndEchoReply,
    SelfSourcedEchoRequest,
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

    let request = build_echo_packet(true, 0, KERNEL_ECHO_PROBE_SEQ, KERNEL_ECHO_PROBE_TAG);
    let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    sock.connect(&SockAddr::from(dest))?;
    sock.send(&request)?;

    if poll_socket_until(&sock, Duration::from_millis(500), |buf| {
        let parsed = parse_packet_headers(buf);
        parsed.icmp.is_some_and(|icmp| !icmp.is_req)
    })? {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "kernel did not provide ICMP echo reply on localhost",
    ))
}

pub fn probe_raw_icmp_capability() -> io::Result<()> {
    Socket::new(Domain::IPV4, Type::RAW, Some(raw_listener_protocol()))?;

    let probes = [
        (
            "node2 concrete listener",
            RAW_CAPABILITY_NODE2_IP,
            RAW_CAPABILITY_CONCRETE_ID,
            RAW_CAPABILITY_CONCRETE_ID,
        ),
        (
            "node3 wildcard-learn listener",
            RAW_CAPABILITY_NODE3_IP,
            0,
            RAW_CAPABILITY_REMOTE_ID,
        ),
    ];
    let mut diagnostics = Vec::new();
    let mut failed = false;

    for (name, ip, bind_ident, request_ident) in probes {
        match probe_bound_raw_icmp_loopback_request_delivery(
            ip,
            bind_ident,
            request_ident,
            RAW_CAPABILITY_PROBE_TIMEOUT,
        ) {
            Ok(RawLoopbackProbeResult::EchoRequest) => diagnostics.push(format!(
                "{name}: ok ({ip}:{bind_ident}, request id {request_ident})"
            )),
            Ok(RawLoopbackProbeResult::EchoRequestAndEchoReply) => {
                failed = true;
                diagnostics.push(format!(
                    "{name}: RAW listener saw the Echo Request, but sender also received a kernel Echo Reply ({ip}:{bind_ident}, request id {request_ident})"
                ));
            }
            Ok(RawLoopbackProbeResult::SelfSourcedEchoRequest) => {
                failed = true;
                diagnostics.push(format!(
                    "{name}: observed only self-sourced Echo Requests on the listener alias ({ip}:{bind_ident}, request id {request_ident})"
                ));
            }
            Ok(RawLoopbackProbeResult::OnlyEchoReply) => {
                failed = true;
                diagnostics.push(format!(
                    "{name}: observed only reflected Echo Replies ({ip}:{bind_ident}, request id {request_ident})"
                ));
            }
            Ok(RawLoopbackProbeResult::NoMatchingIcmp) => {
                failed = true;
                diagnostics.push(format!(
                    "{name}: no matching Echo Request before deadline ({ip}:{bind_ident}, request id {request_ident})"
                ));
            }
            Err(err) => {
                failed = true;
                diagnostics.push(format!(
                    "{name}: probe error for {ip}:{bind_ident}, request id {request_ident}: {err}"
                ));
            }
        }
    }

    if failed {
        Err(io::Error::other(format_raw_capability_probe_failure(
            &diagnostics,
        )))
    } else {
        Ok(())
    }
}

fn format_raw_capability_probe_failure(diagnostics: &[String]) -> String {
    format!(
        "requested-bound RAW ICMP capability probe failed:\n{}",
        diagnostics.join("\n")
    )
}

pub fn probe_bound_raw_icmp_loopback_request_delivery(
    ip: Ipv4Addr,
    bind_ident: u16,
    request_ident: u16,
    timeout: Duration,
) -> io::Result<RawLoopbackProbeResult> {
    let listener = Socket::new(Domain::IPV4, Type::RAW, Some(raw_listener_protocol()))?;
    listener.set_read_timeout(Some(Duration::from_millis(50)))?;
    listener.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
        ip, bind_ident,
    ))))?;

    #[cfg(windows)]
    enable_rcvall(&listener)?;

    let sender = make_icmp_sender()?;
    sender.set_read_timeout(Some(Duration::from_millis(50)))?;
    let request = build_probe_request(request_ident, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
    let dest = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(ip, request_ident)));
    sender.connect(&dest)?;
    sender.send(&request)?;

    probe_connected_sender_and_bound_listener(ip, &sender, &listener, request_ident, timeout)
}

fn probe_connected_sender_and_bound_listener(
    bind_ip: Ipv4Addr,
    sender: &Socket,
    listener: &Socket,
    request_ident: u16,
    timeout: Duration,
) -> io::Result<RawLoopbackProbeResult> {
    let deadline = Instant::now() + timeout;
    let mut sender_buf = RecvBuf::<2048>::new();
    let mut listener_buf = RecvBuf::<2048>::new();
    let mut saw_request = false;
    let mut saw_reply = false;

    while Instant::now() < deadline {
        if let Some(result) = poll_socket_once(listener, &mut listener_buf, |buf| {
            classify_bound_raw_probe_packet(buf, bind_ip, request_ident, BOUND_RAW_PROBE_SEQ)
        })? {
            match result {
                RawLoopbackProbeResult::EchoRequest => saw_request = true,
                RawLoopbackProbeResult::OnlyEchoReply => saw_reply = true,
                RawLoopbackProbeResult::EchoRequestAndEchoReply
                | RawLoopbackProbeResult::SelfSourcedEchoRequest
                | RawLoopbackProbeResult::NoMatchingIcmp => {}
            }
        }

        if let Some(result) = poll_socket_once(sender, &mut sender_buf, |buf| {
            classify_bound_raw_probe_packet(buf, bind_ip, request_ident, BOUND_RAW_PROBE_SEQ)
        })? {
            match result {
                RawLoopbackProbeResult::EchoRequest => saw_request = true,
                RawLoopbackProbeResult::OnlyEchoReply => saw_reply = true,
                RawLoopbackProbeResult::EchoRequestAndEchoReply
                | RawLoopbackProbeResult::SelfSourcedEchoRequest
                | RawLoopbackProbeResult::NoMatchingIcmp => {}
            }
        }

        if saw_request && saw_reply {
            return Ok(RawLoopbackProbeResult::EchoRequestAndEchoReply);
        }
    }

    match (saw_request, saw_reply) {
        (true, false) => Ok(RawLoopbackProbeResult::EchoRequest),
        (true, true) => Ok(RawLoopbackProbeResult::EchoRequestAndEchoReply),
        (false, true) => Ok(RawLoopbackProbeResult::OnlyEchoReply),
        (false, false) => Ok(RawLoopbackProbeResult::NoMatchingIcmp),
    }
}

fn poll_socket_once<F>(
    sock: &Socket,
    recv_buf: &mut RecvBuf<2048>,
    classify: F,
) -> io::Result<Option<RawLoopbackProbeResult>>
where
    F: FnOnce(&[u8]) -> Option<RawLoopbackProbeResult>,
{
    match sock.recv(recv_buf.recv_buf_mut()) {
        Ok(n) => Ok(classify(recv_buf.initialized(n))),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn poll_socket_until<F>(sock: &Socket, timeout: Duration, mut accept: F) -> io::Result<bool>
where
    F: FnMut(&[u8]) -> bool,
{
    let deadline = Instant::now() + timeout;
    let mut recv_buf = RecvBuf::<2048>::new();
    while Instant::now() < deadline {
        match sock.recv(recv_buf.recv_buf_mut()) {
            Ok(n) => {
                if accept(recv_buf.initialized(n)) {
                    return Ok(true);
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
    Ok(false)
}

fn classify_bound_raw_probe_packet(
    packet: &[u8],
    bind_ip: Ipv4Addr,
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
        let bind_addr = std::net::IpAddr::V4(bind_ip);
        if parsed.dst_ip.is_some_and(|dst| dst != bind_addr)
            || parsed.src_ip.is_some_and(|src| src == bind_addr)
        {
            return Some(RawLoopbackProbeResult::SelfSourcedEchoRequest);
        }
        Some(RawLoopbackProbeResult::EchoRequest)
    } else {
        Some(RawLoopbackProbeResult::OnlyEchoReply)
    }
}

fn make_icmp_sender() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))
}

fn build_probe_request(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    build_echo_packet(true, ident, seq, payload)
}

fn build_echo_packet(is_request: bool, ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![if is_request { 8u8 } else { 0u8 }, 0, 0, 0, 0, 0, 0, 0];
    packet[4..6].copy_from_slice(&ident.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = checksum16(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

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

#[cfg(windows)]
fn raw_listener_protocol() -> Protocol {
    Protocol::from(0)
}

#[cfg(not(windows))]
fn raw_listener_protocol() -> Protocol {
    Protocol::ICMPV4
}

#[cfg(windows)]
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
        BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG, RawLoopbackProbeResult, build_echo_packet,
        build_probe_request, checksum16, classify_bound_raw_probe_packet,
        format_raw_capability_probe_failure,
    };

    #[test]
    fn echo_packet_builder_sets_shape_id_seq_payload_and_checksum() {
        let packet = build_echo_packet(true, 0x4567, 0x89ab, BOUND_RAW_PROBE_TAG);
        assert_eq!(packet[0], 8);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x4567);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0x89ab);
        assert_eq!(&packet[8..], BOUND_RAW_PROBE_TAG);
        assert_eq!(checksum16(&packet), 0);

        let packet = build_echo_packet(false, 0x4567, 0x89ab, BOUND_RAW_PROBE_TAG);
        assert_eq!(packet[0], 0);
        assert_eq!(checksum16(&packet), 0);
    }

    #[test]
    fn bound_raw_probe_classifier_distinguishes_echo_request() {
        let packet = build_probe_request(0x4567, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
        assert_eq!(
            classify_bound_raw_probe_packet(
                &packet,
                std::net::Ipv4Addr::LOCALHOST,
                0x4567,
                BOUND_RAW_PROBE_SEQ
            ),
            Some(RawLoopbackProbeResult::EchoRequest)
        );
    }

    #[test]
    fn bound_raw_probe_classifier_distinguishes_echo_reply() {
        let mut packet = build_probe_request(0x4567, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
        packet[0] = 0;
        assert_eq!(
            classify_bound_raw_probe_packet(
                &packet,
                std::net::Ipv4Addr::LOCALHOST,
                0x4567,
                BOUND_RAW_PROBE_SEQ
            ),
            Some(RawLoopbackProbeResult::OnlyEchoReply)
        );
    }

    #[test]
    fn bound_raw_probe_classifier_ignores_wrong_id_or_payload() {
        let packet = build_probe_request(0x4567, BOUND_RAW_PROBE_SEQ, b"other");
        assert_eq!(
            classify_bound_raw_probe_packet(
                &packet,
                std::net::Ipv4Addr::LOCALHOST,
                0x4567,
                BOUND_RAW_PROBE_SEQ
            ),
            None
        );
        let packet = build_probe_request(0x9999, BOUND_RAW_PROBE_SEQ, BOUND_RAW_PROBE_TAG);
        assert_eq!(
            classify_bound_raw_probe_packet(
                &packet,
                std::net::Ipv4Addr::LOCALHOST,
                0x4567,
                BOUND_RAW_PROBE_SEQ
            ),
            None
        );
    }

    #[test]
    fn raw_icmp_capability_diagnostic_names_required_shapes() {
        let diagnostic = format_raw_capability_probe_failure(&[
            "node2 concrete listener: failed (127.0.0.2:1001, request id 1001)".to_string(),
            "node3 wildcard-learn listener: failed (127.0.0.3:0, request id 3003)".to_string(),
        ]);
        assert!(diagnostic.contains("requested-bound RAW ICMP capability probe failed"));
        assert!(diagnostic.contains("node2 concrete listener"));
        assert!(diagnostic.contains("node3 wildcard-learn listener"));
        assert!(diagnostic.contains("127.0.0.2:1001"));
        assert!(diagnostic.contains("127.0.0.3:0"));
    }
}
