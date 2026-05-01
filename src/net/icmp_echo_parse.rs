#[path = "../../src/net/byte_order.rs"]
mod byte_order;

/// Some OSes (notably Linux for IPv4 raw sockets) deliver the full IP header
/// followed by the ICMP message. Others deliver only the ICMP message.
#[inline]
pub(crate) const fn parse_icmp_echo_header(
    payload: &[u8],
) -> (bool, &[u8], usize, usize, u16, u16, bool) {
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
    let ident = byte_order::be16_16(ident_b0, ident_b1);

    let seq_b1 = buf[(off + 7) * success];
    let seq_b0 = buf[(off + 6) * success];
    let seq = byte_order::be16_16(seq_b0, seq_b1);

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
