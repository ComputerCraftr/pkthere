use crate::socket_reality::evidence::{IcmpDgramCollectionOutcome, ReceiveEvidence};
use pkthere_socket_policy::IcmpChecksumMode;
use pkthere_wire::packet_headers::{
    ICMP_TUNNEL_SESSION_ID_LEN, SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER,
};
use socket2::Domain;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const ICMP_SEQUENCE: u16 = 0x51a7;
pub(super) const ICMP_DGRAM_NOISE_PACKET_LIMIT: usize = 64;
pub(super) const ICMP_DGRAM_NONCE_LEN: usize = 16;
const ICMP_ECHO_HEADER_LEN: usize = 8;
const ICMP_DGRAM_SHIM_FLAGS_LEN: usize = 1;
const ICMP_DGRAM_PROBE_SESSION_ID: u64 = 0x706b_7468_6572_6502;
pub(super) const ICMP_DGRAM_SESSION_OFFSET: usize =
    ICMP_ECHO_HEADER_LEN + ICMP_DGRAM_SHIM_FLAGS_LEN;
pub(super) const ICMP_DGRAM_NONCE_OFFSET: usize =
    ICMP_DGRAM_SESSION_OFFSET + ICMP_TUNNEL_SESSION_ID_LEN;
const ICMP_DGRAM_CORRELATED_LEN: usize = ICMP_DGRAM_NONCE_OFFSET + ICMP_DGRAM_NONCE_LEN;
static NEXT_ICMP_DGRAM_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EchoReplyExpectation {
    pub(super) peer: IpAddr,
    pub(super) realized_echo_id: u16,
    pub(super) sequence: u16,
    pub(super) payload_nonce: [u8; ICMP_DGRAM_NONCE_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EchoCandidate {
    Reply,
    ReflectedRequest,
    Noise,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EchoSearchDecision {
    Continue,
    ReplyObserved,
    NoiseLimitExceeded { observed_noise_packets: usize },
}

pub(super) fn build_correlated_echo(
    domain: Domain,
    identifier: u16,
    sequence: u16,
    payload_nonce: &[u8; ICMP_DGRAM_NONCE_LEN],
    checksum_mode: IcmpChecksumMode,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        ICMP_DGRAM_SHIM_FLAGS_LEN + ICMP_TUNNEL_SESSION_ID_LEN + payload_nonce.len(),
    );
    payload.push(SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER);
    payload.extend_from_slice(&ICMP_DGRAM_PROBE_SESSION_ID.to_be_bytes());
    payload.extend_from_slice(payload_nonce);
    super::direct_icmp::build_echo_with_payload(
        domain,
        identifier,
        sequence,
        &payload,
        checksum_mode,
    )
}

pub(super) fn next_nonce(domain: Domain) -> [u8; ICMP_DGRAM_NONCE_LEN] {
    let counter = NEXT_ICMP_DGRAM_NONCE
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .expect("ICMP DGRAM reality nonce counter exhausted");
    let mut nonce = [0u8; ICMP_DGRAM_NONCE_LEN];
    nonce[..8].copy_from_slice(&counter.to_be_bytes());
    nonce[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    nonce[12..14].copy_from_slice(&ICMP_SEQUENCE.to_be_bytes());
    nonce[14] = 1;
    nonce[15] = if domain == Domain::IPV4 { 4 } else { 6 };
    nonce
}

pub(super) fn observe(
    domain: Domain,
    receive: &ReceiveEvidence,
    expectation: EchoReplyExpectation,
    observed_noise_packets: &mut usize,
) -> Option<IcmpDgramCollectionOutcome> {
    terminal_collection_outcome(observe_echo_candidate(
        classify_echo_candidate(domain, receive, expectation),
        observed_noise_packets,
    ))
}

pub(super) fn classify_echo_candidate(
    domain: Domain,
    receive: &ReceiveEvidence,
    expectation: EchoReplyExpectation,
) -> EchoCandidate {
    if receive.source.map(|source| source.ip()) != Some(expectation.peer) {
        return EchoCandidate::Noise;
    }
    let Some((icmp, packet_source)) = exact_icmp_transport(domain, &receive.bytes) else {
        return EchoCandidate::Noise;
    };
    if packet_source.is_some_and(|source| source != expectation.peer)
        || icmp.len() != ICMP_DGRAM_CORRELATED_LEN
        || icmp[1] != 0
        || u16::from_be_bytes([icmp[4], icmp[5]]) != expectation.realized_echo_id
        || u16::from_be_bytes([icmp[6], icmp[7]]) != expectation.sequence
        || icmp[ICMP_ECHO_HEADER_LEN] != (SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER)
        || icmp[ICMP_DGRAM_SESSION_OFFSET..ICMP_DGRAM_NONCE_OFFSET]
            != ICMP_DGRAM_PROBE_SESSION_ID.to_be_bytes()
        || icmp[ICMP_DGRAM_NONCE_OFFSET..] != expectation.payload_nonce
    {
        return EchoCandidate::Noise;
    }
    match (domain, icmp[0]) {
        (Domain::IPV4, 0) | (Domain::IPV6, 129) => EchoCandidate::Reply,
        (Domain::IPV4, 8) | (Domain::IPV6, 128) => EchoCandidate::ReflectedRequest,
        _ => EchoCandidate::Noise,
    }
}

fn exact_icmp_transport(domain: Domain, bytes: &[u8]) -> Option<(&[u8], Option<IpAddr>)> {
    let transport_offset = match (domain, bytes.first().map(|byte| byte >> 4)) {
        (Domain::IPV4, Some(4)) => {
            if bytes.len() < 20 || bytes[9] != 1 {
                return None;
            }
            let header_length = usize::from(bytes[0] & 0x0f) * 4;
            let declared_network_total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            let declared_host_payload = usize::from(u16::from_ne_bytes([bytes[2], bytes[3]]));
            let network_total_matches = declared_network_total == bytes.len();
            let darwin_payload_matches =
                header_length.checked_add(declared_host_payload) == Some(bytes.len());
            if header_length < 20 || !(network_total_matches || darwin_payload_matches) {
                return None;
            }
            let source = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
            return bytes.get(header_length..).map(|icmp| (icmp, Some(source)));
        }
        (Domain::IPV6, Some(6)) => {
            if bytes.len() < 40 || bytes[6] != 58 {
                return None;
            }
            let declared_payload = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            if 40usize.checked_add(declared_payload)? != bytes.len() {
                return None;
            }
            let source = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes.get(8..24)?).ok()?,
            ));
            return bytes.get(40..).map(|icmp| (icmp, Some(source)));
        }
        _ => 0,
    };
    bytes.get(transport_offset..).map(|icmp| (icmp, None))
}

pub(super) fn observe_echo_candidate(
    candidate: EchoCandidate,
    observed_noise_packets: &mut usize,
) -> EchoSearchDecision {
    match candidate {
        EchoCandidate::Reply => EchoSearchDecision::ReplyObserved,
        EchoCandidate::ReflectedRequest => EchoSearchDecision::Continue,
        EchoCandidate::Noise => {
            *observed_noise_packets += 1;
            if *observed_noise_packets >= ICMP_DGRAM_NOISE_PACKET_LIMIT {
                EchoSearchDecision::NoiseLimitExceeded {
                    observed_noise_packets: *observed_noise_packets,
                }
            } else {
                EchoSearchDecision::Continue
            }
        }
    }
}

pub(super) fn terminal_collection_outcome(
    decision: EchoSearchDecision,
) -> Option<IcmpDgramCollectionOutcome> {
    match decision {
        EchoSearchDecision::Continue => None,
        EchoSearchDecision::ReplyObserved => Some(IcmpDgramCollectionOutcome::ReplyObserved),
        EchoSearchDecision::NoiseLimitExceeded {
            observed_noise_packets,
        } => Some(IcmpDgramCollectionOutcome::NoiseLimitExceeded {
            limit: ICMP_DGRAM_NOISE_PACKET_LIMIT,
            observed_noise_packets,
        }),
    }
}
