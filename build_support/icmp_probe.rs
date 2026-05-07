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
    let checksum_bytes = checksum.to_be_bytes();
    request[2] = checksum_bytes[0];
    request[3] = checksum_bytes[1];

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
