#[cfg(not(miri))]
use super::SIMD_VECTORS_PER_FOLD;
use super::{checksum16_bytes, checksum16_header, checksum16_header_parts, fold64_16};
use crate::MAX_WIRE_PAYLOAD;

fn fold_oracle(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn checksum_oracle(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    let mut chunks = bytes.chunks_exact(2);
    for word in &mut chunks {
        sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u64::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn reference_checksum(hdr: &[u8; 8], data: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(hdr.len() + data.len());
    bytes.extend_from_slice(&hdr[..2]);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&hdr[4..]);
    bytes.extend_from_slice(data);
    checksum_oracle(&bytes)
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
    let mut data = [0u8; 192];
    for (i, val) in data.iter_mut().enumerate() {
        *val = i as u8;
    }

    for offset in 0..64 {
        let slice = &data[offset..offset + 64];
        let expected = checksum_oracle(slice);
        let actual = checksum16_bytes(slice);
        assert_eq!(
            actual, expected,
            "Alignment mismatch at offset {} (expected {:04x}, got {:04x})",
            offset, expected, actual
        );
    }
}

#[test]
fn checksum16_bytes_matches_published_ascii_vector() {
    assert_eq!(checksum16_bytes(b"123456789"), 0xf62a);
}

#[test]
fn fold64_16_preserves_the_high_carry_for_maximum_and_fuzzed_sums() {
    for sum in [
        0,
        1,
        0xffff,
        0x1_0000,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::from(u32::MAX) * 2,
        u64::MAX,
    ] {
        assert_eq!(fold64_16(sum), fold_oracle(sum), "sum={sum:#018x}");
    }

    let mut sum = 0xd131_0ba6_98df_b5acu64;
    for case in 0..4096 {
        sum ^= sum << 13;
        sum ^= sum >> 7;
        sum ^= sum << 17;
        assert_eq!(
            fold64_16(sum),
            fold_oracle(sum),
            "fuzzed case {case}, sum={sum:#018x}"
        );
    }
}

#[test]
fn checksum16_bytes_matches_ipv4_udp_and_icmp_vectors() {
    let ipv4_header = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    assert_eq!(checksum16_bytes(&ipv4_header), 0xb861);

    let udp_pseudo_header_and_datagram = [
        0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0x00, 0x11, 0x00, 0x0c, 0x00, 0x35, 0x00,
        0x35, 0x00, 0x0c, 0x00, 0x00, b't', b'e', b's', b't',
    ];
    assert_eq!(checksum16_bytes(&udp_pseudo_header_and_datagram), 0x9579);

    let icmp_echo_header = [8, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(checksum16_bytes(&icmp_echo_header), 0xf7ff);
}

#[test]
fn checksum_boundaries_match_independent_oracle() {
    for len in [0, 1, 2, 3, 7, 8, 9, 63, 64, 65, 127, 128, 129] {
        let bytes = (0..len)
            .map(|index| ((index * 37 + 11) % 251) as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            checksum16_bytes(&bytes),
            checksum_oracle(&bytes),
            "len={len}"
        );
    }
}

#[test]
fn checksum_randomized_inputs_match_independent_oracle() {
    // Miri interprets every byte operation. Keep the same randomized
    // differential path in that suite while the native runner owns the
    // larger sample corpus.
    let (case_count, maximum_length) = if cfg!(miri) {
        (8, 1024)
    } else {
        (512, MAX_WIRE_PAYLOAD + 1024)
    };
    let mut state = 0x6a09_e667_f3bc_c909u64;
    for case in 0..case_count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = (state as usize) % maximum_length;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        assert_eq!(
            checksum16_bytes(&bytes),
            checksum_oracle(&bytes),
            "randomized case {case}, len={len}"
        );
    }
}

#[cfg(not(miri))]
#[test]
fn checksum_large_adversarial_buffer_periodically_folds_simd_lanes() {
    const THREE_BATCH_BOUNDARY: usize = 3 * SIMD_VECTORS_PER_FOLD * 64;
    for bytes in [
        vec![0xff; THREE_BATCH_BOUNDARY + 1],
        (0..THREE_BATCH_BOUNDARY + 67)
            .map(|index| ((index * 17 + 3) % 256) as u8)
            .collect::<Vec<_>>(),
    ] {
        assert_eq!(checksum16_bytes(&bytes), checksum_oracle(&bytes));
        assert_eq!(checksum16_bytes(&bytes[1..]), checksum_oracle(&bytes[1..]));
    }
}
