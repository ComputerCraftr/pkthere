use bytemuck::{must_cast_ref, pod_align_to, pod_read_unaligned};
use wide::u32x16;

const WORD_LO_U32: u32 = 0x0000_FFFF;
const SWAP_LO_U32: u32 = 0xFF00_FF00;
const SWAP_HI_U32: u32 = 0x00FF_00FF;
const SWAP_LO_U64: u64 = 0xFF00_FF00_FF00_FF00;
const SWAP_HI_U64: u64 = 0x00FF_00FF_00FF_00FF;

/// Combine two bytes into a 16-bit word in network order, stored in a u32.
#[inline(always)]
const fn be16_32(b0: u8, b1: u8) -> u32 {
    b1 as u32 | ((b0 as u32) << 8)
}

/// Swaps bytes within each 16-bit halfword of a u32 accumulator: [b0,b1,b2,b3] -> [b1,b0,b3,b2].
/// This is the central bitwise operation for RFC 1071 endianness and alignment correction.
#[inline(always)]
const fn swap_words_u32(sum: u32) -> u32 {
    ((sum << 8) & SWAP_LO_U32) | ((sum >> 8) & SWAP_HI_U32)
}

/// Sum 4 bytes as two big-endian 16-bit words.
#[inline(always)]
fn csum_be32_4(bytes: &[u8; 4]) -> u32 {
    // `x` is read in native endianness.
    let mut x = pod_read_unaligned::<u32>(bytes);
    #[cfg(target_endian = "little")]
    {
        // Little-endian: swap bytes within each halfword to match wire order.
        x = swap_words_u32(x);
    }
    let lo = x & WORD_LO_U32;
    let hi = x >> 16;
    lo + hi
}

/// Sum 8 bytes as four big-endian 16-bit words. Uses a reduction tree for ILP.
#[inline(always)]
fn csum_be64_8(bytes: &[u8; 8]) -> u32 {
    let mut x = pod_read_unaligned::<u64>(bytes);
    #[cfg(target_endian = "little")]
    {
        let swapped = ((x << 8) & SWAP_LO_U64) | ((x >> 8) & SWAP_HI_U64);
        x = swapped;
    }
    // Reduction tree: (a+b) + (c+d) to maximize Instruction Level Parallelism.
    let a = x as u32 & WORD_LO_U32;
    let b = x as u32 >> 16;
    let c = (x >> 32) as u32 & WORD_LO_U32;
    let d = (x >> 48) as u32;
    (a + b) + (c + d)
}

/// Sum 8 bytes as four native-endian 16-bit words. Uses a reduction tree for ILP.
#[inline(always)]
fn csum_native64_8(bytes: &[u8; 8]) -> u32 {
    let x = pod_read_unaligned::<u64>(bytes);
    // Reduction tree: (a+b) + (c+d) to maximize Instruction Level Parallelism.
    let a = x as u32 & WORD_LO_U32;
    let b = x as u32 >> 16;
    let c = (x >> 32) as u32 & WORD_LO_U32;
    let d = (x >> 48) as u32;
    (a + b) + (c + d)
}

/// Internal helper for ICMP header sums (treating checksum field as zero).
#[inline(always)]
fn csum_icmp_header_8(hdr: &[u8; 8]) -> u32 {
    let a = be16_32(hdr[0], hdr[1]);
    let b = csum_be32_4((&hdr[4..8]).try_into().unwrap());
    a + b
}

/// Sum a byte slice as RFC 1071 big-endian 16-bit words. Optimized with ILP and dual accumulators.
#[inline(always)]
fn csum_be_slice(bytes: &[u8]) -> u32 {
    let mut sum_a = 0;
    let mut sum_b = 0;

    let (chunks8, rem8) = bytes.as_chunks::<8>();
    let (chunks16, rem_mid) = chunks8.as_chunks::<2>();
    // Dual accumulators break dependency chains, allowing superscalar CPUs to execute in parallel.
    for c in chunks16 {
        sum_a += csum_be64_8(&c[0]);
        sum_b += csum_be64_8(&c[1]);
    }
    for c in rem_mid {
        sum_a += csum_be64_8(c);
    }

    let mut sum = sum_a + sum_b;
    let (chunks2, rem2) = rem8.as_chunks::<2>();
    for c in chunks2 {
        sum += be16_32(c[0], c[1]);
    }
    if let [last] = rem2 {
        sum += (*last as u32) << 8;
    }
    sum
}

/// Sum a byte slice as native-endian 16-bit words. Optimized with ILP and dual accumulators.
#[inline(always)]
fn csum_native_slice(bytes: &[u8]) -> u32 {
    let mut sum_a = 0;
    let mut sum_b = 0;

    let (chunks8, rem8) = bytes.as_chunks::<8>();
    let (chunks16, rem_mid) = chunks8.as_chunks::<2>();
    for c in chunks16 {
        sum_a += csum_native64_8(&c[0]);
        sum_b += csum_native64_8(&c[1]);
    }
    for c in rem_mid {
        sum_a += csum_native64_8(c);
    }

    let mut sum = sum_a + sum_b;
    let (chunks2, rem2) = rem8.as_chunks::<2>();
    for c in chunks2 {
        sum += u16::from_ne_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = rem2 {
        // Last byte contributes as high byte of word started logical pairing.
        sum += u16::from_ne_bytes([*last, 0]) as u32;
    }
    sum
}

/// Fold a 32-bit sum into a 16-bit RFC 1071 sum.
#[inline(always)]
const fn fold32_16(mut sum: u32) -> u16 {
    sum = (sum & WORD_LO_U32) + (sum >> 16);
    sum = (sum & WORD_LO_U32) + (sum >> 16);
    sum as u16
}

/// Central SIMD logic with robust alignment correction.
#[inline(always)]
fn csum_slice(data: &[u8], initial_swap: bool) -> u32 {
    // Aligned SIMD handles 64-byte chunks with zero-cost native-endian summation.
    let (head, aligned, tail) = pod_align_to::<u8, u32x16>(data);
    if aligned.is_empty() {
        let sum = csum_be_slice(data);
        return if initial_swap {
            swap_words_u32(sum)
        } else {
            sum
        };
    }
    const WORD_LO: u32x16 = u32x16::splat(WORD_LO_U32);

    let mut vsum = u32x16::ZERO;
    let mut idx = 0;
    let len = aligned.len();

    // ILP loop unrolling for SIMD accumulation.
    while idx + 3 < len {
        let a = (aligned[idx] & WORD_LO) + (aligned[idx] >> 16);
        let b = (aligned[idx + 1] & WORD_LO) + (aligned[idx + 1] >> 16);
        let c = (aligned[idx + 2] & WORD_LO) + (aligned[idx + 2] >> 16);
        let d = (aligned[idx + 3] & WORD_LO) + (aligned[idx + 3] >> 16);
        vsum += (a + b) + (c + d);
        idx += 4;
    }
    while idx + 1 < len {
        let a = (aligned[idx] & WORD_LO) + (aligned[idx] >> 16);
        let b = (aligned[idx + 1] & WORD_LO) + (aligned[idx + 1] >> 16);
        vsum += a + b;
        idx += 2;
    }
    if idx < len {
        vsum += (aligned[idx] & WORD_LO) + (aligned[idx] >> 16);
    }

    // Horizontal reduction tree for SIMD lanes.
    let pairs = must_cast_ref::<u32x16, [u64; 8]>(&vsum);
    let ab = (pairs[0] + pairs[1]) + (pairs[2] + pairs[3]);
    let cd = (pairs[4] + pairs[5]) + (pairs[6] + pairs[7]);
    let packed = ab + cd;
    let res = (packed as u32) + (packed >> 32) as u32;

    // Correctly handle the aligned body relative to the Big-Endian head.
    // By using csum_native_slice or csum_be_slice selectively, we ensure
    // at most one swap per part.
    let h_sum = if initial_swap {
        #[cfg(target_endian = "little")]
        {
            csum_native_slice(head)
        }
        #[cfg(target_endian = "big")]
        {
            swap_words_u32(csum_be_slice(head))
        }
    } else {
        csum_be_slice(head)
    };

    #[cfg(target_endian = "little")]
    let b_needs_swap = head.len().is_multiple_of(2) ^ initial_swap;
    #[cfg(target_endian = "big")]
    let b_needs_swap = !head.len().is_multiple_of(2) ^ initial_swap;

    let b_sum = res + csum_native_slice(tail);
    let body_eff = if b_needs_swap {
        swap_words_u32(b_sum)
    } else {
        b_sum
    };

    h_sum + body_eff
}

/// Compute the Internet Checksum (RFC 1071) for the given byte slice.
#[inline]
pub fn checksum16_bytes(data: &[u8]) -> u16 {
    !fold32_16(csum_slice(data, false))
}

/// Compute the Internet Checksum (RFC 1071) for ICMPv4 Echo header+payload.
///
/// Implementation notes:
/// * We leverage the RFC 1071 property that Sum(LE) == Swap(Sum(BE)).
/// * Aligned SIMD summation loop is zero-cost; correction happens exactly once.
/// * Unaligned memory and logical offsets are handled via a unified bitwise logic.
/// * Scalar paths maximize Instruction Level Parallelism (ILP) with dual accumulators and reduction trees.
#[inline]
pub fn checksum16_header(hdr: &[u8; 8], data: &[u8]) -> u16 {
    let sum = csum_icmp_header_8(hdr) + csum_slice(data, false);
    !fold32_16(sum)
}

/// Multi-part ICMP header checksum supporting an arbitrary prefix and payload.
#[inline]
pub fn checksum16_header_parts(hdr: &[u8; 8], prefix: &[u8], data: &[u8]) -> u16 {
    let initial_swap = !prefix.len().is_multiple_of(2);
    let sum = csum_icmp_header_8(hdr) + csum_be_slice(prefix) + csum_slice(data, initial_swap);
    !fold32_16(sum)
}

#[cfg(test)]
mod tests {
    use super::{
        checksum16_bytes, checksum16_header, checksum16_header_parts, csum_be_slice,
        csum_icmp_header_8, fold32_16,
    };
    use crate::MAX_WIRE_PAYLOAD;

    fn reference_checksum(hdr: &[u8; 8], data: &[u8]) -> u16 {
        let a = csum_icmp_header_8(hdr);
        let b = csum_be_slice(data);
        !fold32_16(a + b)
    }

    fn reference_checksum_parts(hdr: &[u8; 8], prefix: &[u8], data: &[u8]) -> u16 {
        let mut buf = Vec::new();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(data);
        reference_checksum(hdr, &buf)
    }

    #[test]
    fn checksum16_header_parts_matches_joined_checksum16_header() {
        let hdr = [8, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        let prefix = [0xAA];
        let data = [0xBB, 0xCC, 0xDD];
        let mut joined = Vec::new();
        joined.extend_from_slice(&prefix);
        joined.extend_from_slice(&data);

        assert_eq!(
            checksum16_header_parts(&hdr, &prefix, &data),
            checksum16_header(&hdr, &joined),
            "Split header+prefix+payload checksum must match joined checksum"
        );
    }

    #[test]
    fn checksum16_header_parts_matches_reference() {
        let hdr = [8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let payloads = [
            vec![],
            vec![1],
            vec![1, 2],
            vec![1, 2, 3],
            (0..100).map(|i| i as u8).collect(),
        ];
        let prefixes = [vec![], vec![0xAA], vec![0xAA, 0xBB], vec![0xAA, 0xBB, 0xCC]];
        for prefix in &prefixes {
            for data in &payloads {
                assert_eq!(
                    checksum16_header_parts(&hdr, prefix, data),
                    reference_checksum_parts(&hdr, prefix, data),
                    "Reference mismatch for prefix len {} data len {}",
                    prefix.len(),
                    data.len()
                );
            }
        }
    }

    #[test]
    fn checksum16_header_matches_reference_small_payloads() {
        let hdr = [8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let even = [1, 2, 3, 4];
        let odd = [0xAA, 0xBB, 0xCC];
        assert_eq!(
            checksum16_header(&hdr, &even),
            reference_checksum(&hdr, &even),
            "Even payload reference mismatch"
        );
        assert_eq!(
            checksum16_header(&hdr, &odd),
            reference_checksum(&hdr, &odd),
            "Odd payload reference mismatch"
        );
    }

    #[test]
    fn checksum16_header_handles_large_payloads() {
        let hdr = [8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
        let payload: Vec<u8> = (0..400).map(|i| i as u8).collect();
        assert_eq!(
            checksum16_header(&hdr, &payload),
            reference_checksum(&hdr, &payload),
            "Large payload reference mismatch"
        );
    }

    #[test]
    fn checksum16_header_handles_max_wire_payload() {
        let hdr = [8, 0, 0, 0, 0xAB, 0xCD, 0x00, 0x01];
        let payload: Vec<u8> = (0..MAX_WIRE_PAYLOAD).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            checksum16_header(&hdr, &payload),
            reference_checksum(&hdr, &payload),
            "Max payload reference mismatch"
        );
    }

    #[test]
    fn checksum16_header_handles_max_wire_payload_all_ff() {
        let hdr = [8, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        let payload = vec![0xFFu8; MAX_WIRE_PAYLOAD];
        assert_eq!(
            checksum16_header(&hdr, &payload),
            reference_checksum(&hdr, &payload),
            "All-FF max payload reference mismatch"
        );
    }

    #[test]
    fn checksum16_bytes_handles_unaligned_buffers() {
        let mut data = [0u8; 128];
        for (i, val) in data.iter_mut().enumerate() {
            *val = i as u8;
        }

        // Test every alignment offset from 0 to 15
        for offset in 0..16 {
            let slice = &data[offset..offset + 64];
            let expected = reference_checksum(&[0; 8], slice);
            let actual = checksum16_bytes(slice);
            assert_eq!(
                actual, expected,
                "Alignment mismatch at offset {} (expected {:04x}, got {:04x})",
                offset, expected, actual
            );
        }
    }
}
