use super::{ErrorCategory, Instant, PacketRejectionCategory, Snapshot, Stats};

pub(super) fn record_send_snapshot(
    snapshot: &mut Snapshot,
    c2u: bool,
    bytes: u64,
    received_at: Instant,
    attempted_at: Instant,
    completed_at: Instant,
) {
    let duration_ns = |start: Instant, end: Instant| {
        u64::try_from(end.saturating_duration_since(start).as_nanos()).unwrap_or(u64::MAX)
    };
    let queue_ns = duration_ns(received_at, attempted_at);
    let service_ns = duration_ns(attempted_at, completed_at);
    let latency_ns = u128::from(queue_ns) + u128::from(service_ns);
    let latency_max_ns = u64::try_from(latency_ns).unwrap_or(u64::MAX);
    let mut overflowed = snapshot.accounting_overflowed;
    let (
        packets,
        total_bytes,
        bytes_max,
        latency_sum,
        latency_max,
        queue_sum,
        queue_max,
        service_sum,
        service_max,
        zero_resolution_samples,
    ) = if c2u {
        (
            &mut snapshot.c2u.pkts,
            &mut snapshot.c2u.bytes,
            &mut snapshot.c2u.bytes_max,
            &mut snapshot.c2u.lat_sum_ns,
            &mut snapshot.c2u.lat_max_ns,
            &mut snapshot.c2u.queue_sum_ns,
            &mut snapshot.c2u.queue_max_ns,
            &mut snapshot.c2u.service_sum_ns,
            &mut snapshot.c2u.service_max_ns,
            &mut snapshot.c2u.zero_resolution_samples,
        )
    } else {
        (
            &mut snapshot.u2c.pkts,
            &mut snapshot.u2c.bytes,
            &mut snapshot.u2c.bytes_max,
            &mut snapshot.u2c.lat_sum_ns,
            &mut snapshot.u2c.lat_max_ns,
            &mut snapshot.u2c.queue_sum_ns,
            &mut snapshot.u2c.queue_max_ns,
            &mut snapshot.u2c.service_sum_ns,
            &mut snapshot.u2c.service_max_ns,
            &mut snapshot.u2c.zero_resolution_samples,
        )
    };
    Stats::add_u64(packets, 1, &mut overflowed);
    Stats::add_u128(total_bytes, u128::from(bytes), &mut overflowed);
    *bytes_max = (*bytes_max).max(bytes);
    Stats::add_u128(latency_sum, latency_ns, &mut overflowed);
    *latency_max = (*latency_max).max(latency_max_ns);
    Stats::add_u128(queue_sum, u128::from(queue_ns), &mut overflowed);
    *queue_max = (*queue_max).max(queue_ns);
    Stats::add_u128(service_sum, u128::from(service_ns), &mut overflowed);
    *service_max = (*service_max).max(service_ns);
    if service_ns == 0 {
        Stats::add_u64(zero_resolution_samples, 1, &mut overflowed);
    }
    snapshot.accounting_overflowed = overflowed;
}

pub(super) fn record_drop_error_snapshot(snapshot: &mut Snapshot, c2u: bool) {
    let mut overflowed = snapshot.accounting_overflowed;
    let errors = if c2u {
        &mut snapshot.c2u.errs
    } else {
        &mut snapshot.u2c.errs
    };
    Stats::add_u64(errors, 1, &mut overflowed);
    snapshot.accounting_overflowed = overflowed;
}

pub(super) fn record_spurious_readiness_snapshot(snapshot: &mut Snapshot) {
    let mut overflowed = snapshot.accounting_overflowed;
    Stats::add_u64(
        &mut snapshot.control.spurious_readiness_events,
        1,
        &mut overflowed,
    );
    snapshot.accounting_overflowed = overflowed;
}

fn record_admission_snapshot(snapshot: &mut Snapshot, c2u: bool, overflowed: &mut bool) {
    let drops = if c2u {
        &mut snapshot.c2u.admission_drops
    } else {
        &mut snapshot.u2c.admission_drops
    };
    Stats::add_u64(drops, 1, overflowed);
}

pub(super) fn record_categorical_error_snapshot(
    snapshot: &mut Snapshot,
    c2u: bool,
    category: ErrorCategory,
) {
    let mut overflowed = snapshot.accounting_overflowed;
    if !matches!(
        category,
        ErrorCategory::WrongPeer
            | ErrorCategory::WrongSource
            | ErrorCategory::Replay
            | ErrorCategory::IcmpAbuseBudget
            | ErrorCategory::StaleSession
            | ErrorCategory::StaleAuthority
    ) {
        let errors = if c2u {
            &mut snapshot.c2u.errs
        } else {
            &mut snapshot.u2c.errs
        };
        Stats::add_u64(errors, 1, &mut overflowed);
    }
    match (c2u, category) {
        (true, ErrorCategory::Receive) => {
            Stats::add_u64(&mut snapshot.c2u.receive_errors, 1, &mut overflowed);
        }
        (false, ErrorCategory::Receive) => {
            Stats::add_u64(&mut snapshot.u2c.receive_errors, 1, &mut overflowed);
        }
        (true, ErrorCategory::UserSend) => {
            Stats::add_u64(&mut snapshot.c2u.user_send_errors, 1, &mut overflowed);
        }
        (false, ErrorCategory::UserSend) => {
            Stats::add_u64(&mut snapshot.u2c.user_send_errors, 1, &mut overflowed);
        }
        (true, ErrorCategory::ControlSend) => {
            Stats::add_u64(&mut snapshot.c2u.control_send_errors, 1, &mut overflowed);
        }
        (false, ErrorCategory::ControlSend) => {
            Stats::add_u64(&mut snapshot.u2c.control_send_errors, 1, &mut overflowed);
        }
        (true, ErrorCategory::Admission) => {
            Stats::add_u64(&mut snapshot.c2u.admission_drops, 1, &mut overflowed);
        }
        (false, ErrorCategory::Admission) => {
            Stats::add_u64(&mut snapshot.u2c.admission_drops, 1, &mut overflowed);
        }
        (true, ErrorCategory::Topology) => {
            Stats::add_u64(&mut snapshot.c2u.topology_errors, 1, &mut overflowed);
        }
        (false, ErrorCategory::Topology) => {
            Stats::add_u64(&mut snapshot.u2c.topology_errors, 1, &mut overflowed);
        }
        (_, ErrorCategory::MalformedPacket) => {
            Stats::add_u64(
                &mut snapshot.admission.malformed_packets,
                1,
                &mut overflowed,
            );
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::WrongPeer) => {
            Stats::add_u64(&mut snapshot.admission.wrong_peer_drops, 1, &mut overflowed);
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::WrongSource) => {
            Stats::add_u64(
                &mut snapshot.admission.wrong_source_drops,
                1,
                &mut overflowed,
            );
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::HandshakeInvalid) => {
            Stats::add_u64(
                &mut snapshot.admission.handshake_invalid_drops,
                1,
                &mut overflowed,
            );
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::Replay) => {
            Stats::add_u64(&mut snapshot.admission.replay_drops, 1, &mut overflowed);
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::IcmpAbuseBudget) => {
            Stats::add_u64(
                &mut snapshot.admission.icmp_abuse_budget_drops,
                1,
                &mut overflowed,
            );
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::StaleSession) => {
            Stats::add_u64(
                &mut snapshot.admission.stale_session_drops,
                1,
                &mut overflowed,
            );
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::StaleAuthority) => {
            Stats::add_u64(
                &mut snapshot.admission.stale_authority_drops,
                1,
                &mut overflowed,
            );
            record_admission_snapshot(snapshot, c2u, &mut overflowed);
        }
        (_, ErrorCategory::InvariantFailure) => {
            Stats::add_u64(
                &mut snapshot.admission.invariant_failures,
                1,
                &mut overflowed,
            );
        }
    }
    snapshot.accounting_overflowed = overflowed;
}

pub(super) fn record_drop_oversize_snapshot(snapshot: &mut Snapshot, c2u: bool) {
    let mut overflowed = snapshot.accounting_overflowed;
    let drops = if c2u {
        &mut snapshot.c2u.drops_oversize
    } else {
        &mut snapshot.u2c.drops_oversize
    };
    Stats::add_u64(drops, 1, &mut overflowed);
    snapshot.accounting_overflowed = overflowed;
}

pub(super) fn record_packet_rejection_snapshot(
    snapshot: &mut Snapshot,
    category: PacketRejectionCategory,
) {
    let mut overflowed = snapshot.accounting_overflowed;
    let counter = match category {
        PacketRejectionCategory::IpMissingHeader => &mut snapshot.network.ip_missing_header,
        PacketRejectionCategory::IpInvalidVersion => &mut snapshot.network.ip_invalid_version,
        PacketRejectionCategory::IpTruncatedHeader => &mut snapshot.network.ip_truncated_header,
        PacketRejectionCategory::IpDeclaredLengthInvalid => {
            &mut snapshot.network.ip_declared_length_invalid
        }
        PacketRejectionCategory::IpCaptureTruncated => &mut snapshot.network.ip_capture_truncated,
        PacketRejectionCategory::IpFragmented => &mut snapshot.network.ip_fragmented,
        PacketRejectionCategory::IpReservedFlag => &mut snapshot.network.ip_reserved_flag,
        PacketRejectionCategory::IpExtensionChain => &mut snapshot.network.ip_extension_chain,
        PacketRejectionCategory::IpRoutingUnsupported => {
            &mut snapshot.network.ip_routing_unsupported
        }
        PacketRejectionCategory::IpJumbogramUnsupported => {
            &mut snapshot.network.ip_jumbogram_unsupported
        }
        PacketRejectionCategory::IpSourceMismatch => &mut snapshot.network.ip_source_mismatch,
        PacketRejectionCategory::IpDestinationMismatch => {
            &mut snapshot.network.ip_destination_mismatch
        }
        PacketRejectionCategory::UnrelatedIpProtocol => &mut snapshot.network.unrelated_ip_protocol,
        PacketRejectionCategory::IcmpMalformed => &mut snapshot.network.icmp_malformed,
    };
    Stats::add_u64(counter, 1, &mut overflowed);
    snapshot.accounting_overflowed = overflowed;
}

pub(super) fn record_handshake_snapshot(snapshot: &mut Snapshot, invalid_control: bool) {
    let mut overflowed = snapshot.accounting_overflowed;
    let counter = if invalid_control {
        &mut snapshot.control.handshake_invalid_control
    } else {
        &mut snapshot.control.handshake_stale_ack
    };
    Stats::add_u64(counter, 1, &mut overflowed);
    snapshot.accounting_overflowed = overflowed;
}
