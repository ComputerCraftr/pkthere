#[cfg(not(miri))]
use bytemuck::pod_align_to;
use bytemuck::pod_read_unaligned;
#[cfg(not(miri))]
use wide::u32x16;

#[cfg(not(miri))]
const WORD_LO_U32: u32 = 0x0000_FFFF;
#[cfg(not(miri))]
const SIMD_LANE_MAX_PER_VECTOR: u64 = 0x0001_FFFE;
#[cfg(not(miri))]
const SIMD_VECTORS_PER_FOLD: usize = 32_768;
#[cfg(not(miri))]
const _: () = assert!(
    SIMD_LANE_MAX_PER_VECTOR * SIMD_VECTORS_PER_FOLD as u64 + WORD_LO_U32 as u64 == u32::MAX as u64
);
const WORD_LO_U64: u64 = 0x0000_0000_0000_FFFF;
const SWAP_LO_U64: u64 = 0xFF00_FF00_FF00_FF00;
const SWAP_HI_U64: u64 = 0x00FF_00FF_00FF_00FF;

/// Combine two bytes into a 16-bit word in network order, stored in a u64 accumulator.
#[inline(always)]
const fn be16_64(b0: u8, b1: u8) -> u64 {
    (b1 as u64) | ((b0 as u64) << 8)
}

/// Combine two bytes into a native-endian 16-bit word, stored in a u64 accumulator.
#[cfg(not(miri))]
#[inline(always)]
const fn ne16_64(b0: u8, b1: u8) -> u64 {
    u16::from_ne_bytes([b0, b1]) as u64
}

/// Sum 8 bytes as four big-endian 16-bit words. Uses a reduction tree for ILP.
#[inline(always)]
fn csum_be64_8(bytes: &[u8; 8]) -> u64 {
    let mut x = pod_read_unaligned::<u64>(bytes);
    #[cfg(target_endian = "little")]
    {
        let swapped = ((x << 8) & SWAP_LO_U64) | ((x >> 8) & SWAP_HI_U64);
        x = swapped;
    }
    // Reduction tree: (a+b) + (c+d) to maximize Instruction Level Parallelism.
    let a = x & WORD_LO_U64;
    let b = (x >> 16) & WORD_LO_U64;
    let c = (x >> 32) & WORD_LO_U64;
    let d = x >> 48;
    (a + b) + (c + d)
}

/// Sum 8 bytes as four native-endian 16-bit words. Uses a reduction tree for ILP.
#[cfg(not(miri))]
#[inline(always)]
fn csum_native64_8(bytes: &[u8; 8]) -> u64 {
    let x = pod_read_unaligned::<u64>(bytes);
    // Reduction tree: (a+b) + (c+d) to maximize Instruction Level Parallelism.
    let a = x & WORD_LO_U64;
    let b = (x >> 16) & WORD_LO_U64;
    let c = (x >> 32) & WORD_LO_U64;
    let d = x >> 48;
    (a + b) + (c + d)
}

/// Internal helper for ICMP header sums (treating checksum field as zero).
#[inline(always)]
fn csum_icmp_header_8(hdr: &[u8; 8]) -> u64 {
    be16_64(hdr[0], hdr[1]) + be16_64(hdr[4], hdr[5]) + be16_64(hdr[6], hdr[7])
}

/// Sum a byte slice as RFC 1071 big-endian 16-bit words. Optimized with ILP and dual accumulators.
#[inline(always)]
fn csum_be_slice(bytes: &[u8]) -> u64 {
    let (chunks8, rem8) = bytes.as_chunks::<8>();
    let (chunks16, rem_mid) = chunks8.as_chunks::<2>();
    let mut sum_a = 0u64;
    let mut sum_b = 0u64;
    // Dual accumulators break the dependency chain while retaining the
    // accumulator width used by every surrounding checksum helper.
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
        sum += be16_64(c[0], c[1]);
    }
    if let [last] = rem2 {
        sum += (*last as u64) << 8;
    }
    sum
}

/// Sum a byte slice as native-endian 16-bit words. Optimized with ILP and dual accumulators.
#[cfg(not(miri))]
#[inline(always)]
fn csum_native_slice(bytes: &[u8]) -> u64 {
    let (chunks8, rem8) = bytes.as_chunks::<8>();
    let (chunks16, rem_mid) = chunks8.as_chunks::<2>();
    let mut sum_a = 0u64;
    let mut sum_b = 0u64;
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
        sum += ne16_64(c[0], c[1]);
    }
    if let [last] = rem2 {
        // Last byte contributes as high byte of word started logical pairing.
        sum += ne16_64(*last, 0);
    }
    sum
}

/// Fold a 64-bit sum into a 16-bit RFC 1071 sum.
#[inline(always)]
const fn fold64_16(mut sum: u64) -> u16 {
    // The low and high halves sum to at most 0x1_ffff_fffe, so this single
    // 32-bit fold preserves the only possible carry before the 16-bit folds.
    sum = (sum & u32::MAX as u64) + (sum >> 32);
    sum = (sum & WORD_LO_U64) + (sum >> 16);
    sum = (sum & WORD_LO_U64) + (sum >> 16);
    sum as u16
}

/// Swap the byte order of an accumulated RFC 1071 sum.
#[inline(always)]
const fn swap_sum_bytes(sum: u64) -> u64 {
    fold64_16(sum).swap_bytes() as u64
}

/// Central SIMD logic with robust alignment correction.
#[cfg(miri)]
#[inline(always)]
fn csum_slice(data: &[u8], initial_swap: bool) -> u64 {
    let sum = csum_be_slice(data);
    if initial_swap {
        swap_sum_bytes(sum)
    } else {
        sum
    }
}

/// Central SIMD logic with robust alignment correction.
#[cfg(not(miri))]
#[inline(always)]
fn csum_slice(data: &[u8], initial_swap: bool) -> u64 {
    // Aligned SIMD handles 64-byte chunks with zero-cost native-endian summation.
    let (head, aligned, tail) = pod_align_to::<u8, u32x16>(data);
    if aligned.is_empty() {
        let sum = csum_be_slice(data);
        return if initial_swap {
            swap_sum_bytes(sum)
        } else {
            sum
        };
    }
    const WORD_LO: u32x16 = u32x16::splat(WORD_LO_U32);

    let mut vsum = u32x16::ZERO;
    let mut idx = 0;
    let len = aligned.len();

    while idx < len {
        let batch_end = (idx + SIMD_VECTORS_PER_FOLD).min(len);

        // Keep every SIMD lane within the proven u32 bound above.
        while idx + 3 < batch_end {
            let a = (aligned[idx] & WORD_LO) + (aligned[idx] >> 16);
            let b = (aligned[idx + 1] & WORD_LO) + (aligned[idx + 1] >> 16);
            let c = (aligned[idx + 2] & WORD_LO) + (aligned[idx + 2] >> 16);
            let d = (aligned[idx + 3] & WORD_LO) + (aligned[idx + 3] >> 16);
            vsum += (a + b) + (c + d);
            idx += 4;
        }
        while idx < batch_end {
            vsum += (aligned[idx] & WORD_LO) + (aligned[idx] >> 16);
            idx += 1;
        }

        if idx < len {
            // RFC 1071 end-around carry is associative, so fold every lane in
            // place before the next batch. Do not fold the final batch.
            vsum = (vsum & WORD_LO) + (vsum >> 16);
            vsum = (vsum & WORD_LO) + (vsum >> 16);
        }
    }
    // Normalize the final batch before horizontal reduction. Each lane is at
    // most 0x1fffe after one fold, so sixteen lanes fit comfortably in u32.
    vsum = (vsum & WORD_LO) + (vsum >> 16);
    let scalar_sum = u64::from(vsum.reduce_add());

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
            swap_sum_bytes(csum_be_slice(head))
        }
    } else {
        csum_be_slice(head)
    };

    #[cfg(target_endian = "little")]
    let b_needs_swap = head.len().is_multiple_of(2) ^ initial_swap;
    #[cfg(target_endian = "big")]
    let b_needs_swap = !head.len().is_multiple_of(2) ^ initial_swap;

    let b_sum = scalar_sum + csum_native_slice(tail);
    let body_eff = if b_needs_swap {
        swap_sum_bytes(b_sum)
    } else {
        b_sum
    };

    h_sum + body_eff
}

/// Compute the Internet Checksum (RFC 1071) for the given byte slice.
#[inline]
pub fn checksum16_bytes(data: &[u8]) -> u16 {
    !fold64_16(csum_slice(data, false))
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
    !fold64_16(sum)
}

/// Multi-part ICMP header checksum supporting an arbitrary prefix and payload.
#[inline]
pub fn checksum16_header_parts(hdr: &[u8; 8], prefix: &[u8], data: &[u8]) -> u16 {
    let initial_swap = !prefix.len().is_multiple_of(2);
    let sum = csum_icmp_header_8(hdr) + csum_be_slice(prefix) + csum_slice(data, initial_swap);
    !fold64_16(sum)
}

#[cfg(test)]
mod tests;
