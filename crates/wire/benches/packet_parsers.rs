use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pkthere_wire::checksum::checksum16_bytes;
use pkthere_wire::packet_headers::{
    parse_icmp_v4_transport, parse_icmp_v6_transport, parse_ipv4_icmp_packet,
    parse_ipv6_icmp_packet, parse_packet_headers, parse_udp_datagram_payload,
};
use std::hint::black_box;

fn ipv4_icmp_packet() -> [u8; 32] {
    let mut packet = [0; 32];
    packet[0] = 0x45;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
    packet[20] = 8;
    packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[26..28].copy_from_slice(&1u16.to_be_bytes());
    packet[28] = 0x90;
    packet[29..32].copy_from_slice(b"abc");
    packet
}

fn ipv6_icmp_packet() -> [u8; 52] {
    let mut packet = [0; 52];
    packet[0] = 0x60;
    packet[6] = 58;
    packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6]);
    packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12]);
    packet[40] = 128;
    packet[44..46].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[46..48].copy_from_slice(&1u16.to_be_bytes());
    packet[48] = 0x90;
    packet[49..52].copy_from_slice(b"abc");
    packet
}

fn packet_parser_benchmarks(c: &mut Criterion) {
    let ipv4_packet = ipv4_icmp_packet();
    let ipv6_packet = ipv6_icmp_packet();
    let icmpv4 = &ipv4_packet[20..];
    let icmpv6 = &ipv6_packet[40..];
    let udp_payload = b"payload-only UDP datagram";

    c.bench_function("generic_ipv4_icmp", |b| {
        b.iter(|| parse_packet_headers(black_box(&ipv4_packet)))
    });
    c.bench_function("specialized_ipv4_icmp", |b| {
        b.iter(|| parse_ipv4_icmp_packet(black_box(&ipv4_packet)))
    });
    c.bench_function("generic_ipv6_icmp", |b| {
        b.iter(|| parse_packet_headers(black_box(&ipv6_packet)))
    });
    c.bench_function("specialized_ipv6_icmp", |b| {
        b.iter(|| parse_ipv6_icmp_packet(black_box(&ipv6_packet)))
    });
    c.bench_function("specialized_icmpv4_transport", |b| {
        b.iter(|| parse_icmp_v4_transport(black_box(icmpv4)))
    });
    c.bench_function("specialized_icmpv6_transport", |b| {
        b.iter(|| parse_icmp_v6_transport(black_box(icmpv6)))
    });
    c.bench_function("specialized_udp_payload", |b| {
        b.iter(|| parse_udp_datagram_payload(black_box(udp_payload)))
    });
}

fn checksum_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum16");
    for len in [0usize, 1, 8, 32, 64, 256, 1500, 65_535] {
        let storage = vec![0xa5; len + 16];
        group.throughput(Throughput::Bytes(len as u64));
        for offset in [0usize, 1, 7, 15] {
            let data = &storage[offset..offset + len];
            group.bench_with_input(
                BenchmarkId::new(format!("offset_{offset}"), len),
                data,
                |b, data| b.iter(|| checksum16_bytes(black_box(data))),
            );
        }
    }
    group.finish();
}

criterion_group!(benches, packet_parser_benchmarks, checksum_benchmarks);
criterion_main!(benches);
