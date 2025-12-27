use bytemuck::{must_cast_ref, pod_align_to, pod_read_unaligned};
use wide::u32x16;

const WORD_LO_U32: u32 = 0x0000_FFFF;
const SWAP_LO_U32: u32 = 0xFF00_FF00;
const SWAP_HI_U32: u32 = 0x00FF_00FF;
const SWAP_LO_U64: u64 = 0xFF00_FF00_FF00_FF00;
const SWAP_HI_U64: u64 = 0x00FF_00FF_00FF_00FF;

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
    let lo = x & WORD_LO_U32;
    let hi = x >> 16;
    lo + hi
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
    let a = x as u32 & WORD_LO_U32;
    let b = x as u32 >> 16;
    let c = (x >> 32) as u32 & WORD_LO_U32;
    let d = (x >> 48) as u32;
    let ab = a + b;
    let cd = c + d;
    ab + cd
}

#[inline(always)]
fn csum_icmp_echo_hdr(hdr: &[u8; 8]) -> u32 {
    // Header: type,code ; checksum(0) ; ident ; seq
    // checksum field (hdr[2..4]) is treated as zero.
    let a = be16_32(hdr[0], hdr[1]);
    let b = be16_32_sum2((&hdr[4..8]).try_into().unwrap());
    a + b
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
pub(crate) fn checksum16(hdr: &[u8; 8], data: &[u8]) -> u16 {
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
        let a = lane_contribution(aligned[idx]);
        let b = lane_contribution(aligned[idx + 1]);
        let c = lane_contribution(aligned[idx + 2]);
        let d = lane_contribution(aligned[idx + 3]);
        let ab = a + b;
        let cd = c + d;
        vsum += ab + cd;
        idx += 4;
    }

    while idx + 1 < len {
        let a = lane_contribution(aligned[idx]);
        let b = lane_contribution(aligned[idx + 1]);
        vsum += a + b;
        idx += 2;
    }

    if idx < len {
        vsum += lane_contribution(aligned[idx]);
    }

    // Horizontally reduce 16 u32 lanes.
    // `u32x16` is 64B-aligned, so this cast is safe and zero-copy.
    // We sum as 8 packed u64 pairs to keep the reduction short and keep the final
    // carry/fold behavior equivalent to summing all u16 words then folding.
    let pairs = must_cast_ref::<u32x16, [u64; 8]>(&vsum);

    // Tree reduction to shorten the dependency chain vs a single long add chain.
    let a = pairs[0] + pairs[1];
    let b = pairs[2] + pairs[3];
    let c = pairs[4] + pairs[5];
    let d = pairs[6] + pairs[7];
    let ab = a + b;
    let cd = c + d;
    let packed = ab + cd;
    let lo = packed as u32;
    let hi = (packed >> 32) as u32;
    let res = lo + hi;

    // Handle the remaining bytes (both prefix and suffix) scalarly.
    let scalar_head = csum_bytes(head);
    let scalar_tail = csum_bytes(tail);
    let scalar = scalar_head + scalar_tail;

    // Add low/high 32-bit halves into the scalar sum.
    sum += res + scalar;

    // Final 1's-complement fold down to 16 bits.
    !(fold32_16(sum))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::params::MAX_WIRE_PAYLOAD;

    fn reference_checksum(hdr: &[u8; 8], data: &[u8]) -> u16 {
        let a = csum_icmp_echo_hdr(hdr);
        let b = csum_bytes(data);
        !(fold32_16(a + b))
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
}
