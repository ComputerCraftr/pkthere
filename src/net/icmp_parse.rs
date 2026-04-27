#[inline(always)]
pub const fn be16_16(b0: u8, b1: u8) -> u16 {
    (b1 as u16) | ((b0 as u16) << 8)
}

/// Some OSes (notably Linux for IPv4 raw sockets) deliver the full IP header
/// followed by the ICMP message. Others deliver only the ICMP message.
#[inline]
pub const fn parse_icmp_echo_header(payload: &[u8]) -> (bool, &[u8], usize, usize, u16, u16, bool) {
    const ZERO_ARRAY: [u8; 1] = [0];
    let n = payload.len();

    let has0 = (n >= 1) as usize;
    let buf = if has0 != 0 { payload } else { &ZERO_ARRAY };
    let has9 = (n >= 10) as usize;
    let b9 = buf[9 * has9];
    let b6 = buf[6 * has9];
    let b0 = buf[0];

    let ver = (b0 >> 4) as usize;
    let ihl = ((b0 as usize) & 0x0F) << 2;

    let is_v4 = (ver == 4) as usize;
    let is_v6 = (ver == 6) as usize;

    let sane_ihl = (ihl >= 20) as usize;
    let proto_icmp = (b9 == 1) as usize;
    let room_v4 = (n >= ihl + 8) as usize;

    let next_icmp6 = (b6 == 58) as usize;
    let room_v6 = (n >= 48) as usize;

    let next_v4 = is_v4 & sane_ihl & proto_icmp & room_v4;
    let next_v6 = is_v6 & next_icmp6 & room_v6;

    let off_v4 = ihl * next_v4;
    let off_v6 = 40usize * next_v6;
    let off = off_v4 | off_v6;

    let have_hdr = (n >= off + 8) as usize;
    let icmp_code = buf[(off + 1) * have_hdr];
    let icmp_type = buf[off * have_hdr];

    let type_ok = (icmp_type == 8) as usize
        | (icmp_type == 0) as usize
        | (icmp_type == 128) as usize
        | (icmp_type == 129) as usize;

    let success = have_hdr & (icmp_code == 0) as usize & type_ok;
    let success_bool = success != 0;

    let ident_b1 = buf[(off + 5) * success];
    let ident_b0 = buf[(off + 4) * success];
    let ident = be16_16(ident_b0, ident_b1);

    let seq_b1 = buf[(off + 7) * success];
    let seq_b0 = buf[(off + 6) * success];
    let seq = be16_16(seq_b0, seq_b1);

    let is_request = ((icmp_type == 8) as usize | (icmp_type == 128) as usize) != 0;

    (
        success_bool,
        buf,
        (off + 8) * success,
        n * success,
        ident,
        seq,
        is_request,
    )
}

#[allow(dead_code)]
pub fn probe_kernel_icmp_echo() -> std::io::Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::{Duration, Instant};

    // Attempt DGRAM first, then RAW.
    let (sock, _sock_type) =
        if let Ok(s) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
            (s, Type::DGRAM)
        } else if let Ok(s) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            (s, Type::RAW)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "could not create ICMP socket",
            ));
        };

    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    // ICMP Echo Request
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
    sock.connect(&dest.into())?;
    sock.send(&request)?;

    let mut recv_buf = [std::mem::MaybeUninit::uninit(); 2048];
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        match sock.recv(&mut recv_buf) {
            Ok(n) => {
                if n < 8 {
                    continue;
                }
                let buf = unsafe {
                    &*(&recv_buf[..n] as *const [std::mem::MaybeUninit<u8>] as *const [u8])
                };

                let (ok, _raw, _start, _end, _ident, _seq, is_req) = parse_icmp_echo_header(buf);
                if ok && !is_req {
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
