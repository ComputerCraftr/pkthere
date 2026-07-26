use super::{
    IPV6_ADDR_SEG2_OFF, IPV6_ADDR_SEG3_OFF, IPV6_ADDR_SEG4_OFF, IPV6_ADDR_SEG5_OFF,
    IPV6_ADDR_SEG6_OFF, IPV6_ADDR_SEG7_OFF, IPV6_EXT_DEST_OPTS, IPV6_EXT_FRAGMENT,
    IPV6_EXT_HOP_BY_HOP, IPV6_EXT_ROUTING, IPV6_MIN_LEN, IcmpMalformedReason, IpAddr, Ipv4Addr,
    Ipv6Addr, bool01, byte_at, has_len, not01, read_be16, select2_usize,
};

#[inline]
pub(super) const fn parse_ipv6_at(payload: &[u8], off: usize, valid: usize) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        read_be16(payload, off, valid),
        read_be16(payload, off + 2, valid),
        read_be16(payload, off + IPV6_ADDR_SEG2_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG3_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG4_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG5_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG6_OFF, valid),
        read_be16(payload, off + IPV6_ADDR_SEG7_OFF, valid),
    ))
}

pub(super) const fn first_icmp_malformed_reason(
    truncated_echo: usize,
    invalid_echo: usize,
    shim_reason: Option<IcmpMalformedReason>,
) -> Option<IcmpMalformedReason> {
    let invalid_echo = invalid_echo & not01(truncated_echo);
    [
        shim_reason,
        Some(IcmpMalformedReason::TruncatedEchoHeader),
        Some(IcmpMalformedReason::InvalidEchoTypeOrCode),
    ][truncated_echo | (invalid_echo * 2)]
}

#[inline]
pub(super) const fn is_skippable_v6_ext(next: usize) -> usize {
    ((next == IPV6_EXT_HOP_BY_HOP) as usize)
        | ((next == IPV6_EXT_ROUTING) as usize)
        | ((next == IPV6_EXT_DEST_OPTS) as usize)
}

#[inline]
pub(super) const fn ipv4_fragment_mask(frag_hi: u8, frag_lo: u8, valid_v4: usize) -> usize {
    let fragment_field = crate::be16_16(frag_hi, frag_lo);
    // 0x3fff covers MF + fragment offset bits.
    valid_v4 & bool01((fragment_field & 0x3fff) != 0)
}

#[inline]
pub(super) const fn ipv4_reserved_flag_mask(frag_hi: u8, valid_v4: usize) -> usize {
    valid_v4 & bool01((frag_hi & 0x80) != 0)
}

#[derive(Clone, Copy)]
pub(super) struct Ipv6TransportEvidence {
    pub protocol: usize,
    pub offset: usize,
    pub transport_candidate: usize,
    pub fragmented: usize,
    pub extension_chain: usize,
    pub extension_truncated: usize,
}

#[inline]
pub(super) const fn parse_ipv6_transport_evidence(
    next0: usize,
    valid_v6: usize,
    ext0: usize,
    ext0_next: usize,
    off1: usize,
    ext0_full: usize,
    ext0_truncated: usize,
) -> Ipv6TransportEvidence {
    let fragment0 = valid_v6 & bool01(next0 == IPV6_EXT_FRAGMENT);
    let direct_layout = valid_v6 & not01(ext0);
    let fragment1 = ext0_full & bool01(ext0_next == IPV6_EXT_FRAGMENT);
    let ext1 = ext0_full & is_skippable_v6_ext(ext0_next);
    let direct_transport = direct_layout & not01(fragment0);
    let extended_transport = ext0_full & not01(ext1) & not01(fragment1);

    Ipv6TransportEvidence {
        protocol: select2_usize(next0, direct_layout, ext0_next, ext0_full),
        offset: select2_usize(IPV6_MIN_LEN, direct_layout, off1, ext0_full),
        transport_candidate: direct_transport | extended_transport,
        fragmented: fragment0 | fragment1,
        extension_chain: ext1,
        extension_truncated: ext0_truncated,
    }
}

#[derive(Clone, Copy)]
pub(super) struct Ipv6ExtensionExtent {
    pub next_offset: usize,
    pub complete: usize,
    pub truncated: usize,
}

#[inline]
pub(super) const fn parse_ipv6_extension_extent(
    n: usize,
    off: usize,
    ext_ok: usize,
    prefix_ok: usize,
    len_units: usize,
) -> Ipv6ExtensionExtent {
    let len = (len_units + 1) << 3;
    let next_off = off + len;
    let full = prefix_ok & has_len(n, next_off);
    let truncated = ext_ok & ((full == 0) as usize);
    Ipv6ExtensionExtent {
        next_offset: next_off,
        complete: full,
        truncated,
    }
}

#[inline]
pub(super) const fn parse_ipv4_at(payload: &[u8], off: usize, valid: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        byte_at(payload, off, valid),
        byte_at(payload, off + 1, valid),
        byte_at(payload, off + 2, valid),
        byte_at(payload, off + 3, valid),
    ))
}
