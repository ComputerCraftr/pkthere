use super::{Stats, StatsSink, record_send_snapshot};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

impl super::StatsRecorder {
    pub(crate) fn flush(&mut self) {
        if let super::RecorderRuntime::Enabled(enabled) = &mut self.runtime {
            enabled.publish_pending(Instant::now());
        }
    }
}

pub(super) fn drain_for_test(
    enabled: &super::EnabledStats,
    snapshot: &mut super::Snapshot,
    last_sequences: &mut [u64],
) {
    assert_eq!(enabled.producers.len(), last_sequences.len());
    for (producer, last_sequence) in enabled.producers.iter().zip(last_sequences) {
        while let Some(publication) = producer
            .accept_next(last_sequence)
            .expect("test stats publication ordering")
        {
            if let super::finality_core::AcceptedStatsPublication::Delta(delta) = publication {
                Stats::merge_snapshot(snapshot, delta);
            }
        }
    }
}

#[test]
fn aggregated_snapshot_matches_sum_of_shards() {
    let stats = Stats::with_worker_shards(2);
    let mut shard0 = stats.recorder(0);
    let mut shard1 = stats.recorder(1);
    let now = Instant::now();
    shard0.send_add(
        true,
        10,
        now,
        now + Duration::from_micros(4),
        now + Duration::from_micros(10),
    );
    shard1.send_add(
        true,
        5,
        now,
        now + Duration::from_micros(8),
        now + Duration::from_micros(20),
    );
    shard1.receive_error(false);
    shard0.spurious_readiness(true);
    shard0.drop_oversize(true);
    shard0.handshake_invalid_control(true);
    shard1.handshake_stale_ack();
    shard0.flush();
    shard1.flush();

    let snap = stats.load_snapshot();
    assert_eq!(snap.c2u.pkts, 2);
    assert_eq!(snap.c2u.bytes, 15);
    assert_eq!(snap.u2c.errs, 1);
    assert_eq!(snap.u2c.receive_errors, 1);
    assert_eq!(snap.control.spurious_readiness_events, 1);
    assert_eq!(snap.c2u.drops_oversize, 1);
    assert_eq!(snap.control.handshake_invalid_control, 1);
    assert_eq!(snap.control.handshake_stale_ack, 1);
    assert_eq!(snap.c2u.bytes_max, 10);
    assert_eq!(snap.c2u.lat_max_ns, 20_000);
}

#[test]
fn packet_layer_rejections_keep_distinct_schema_counters() {
    use super::PacketRejectionCategory as Category;

    let stats = Stats::with_worker_shards(1);
    let mut shard = stats.recorder(0);
    for category in [
        Category::IpMissingHeader,
        Category::IpInvalidVersion,
        Category::IpTruncatedHeader,
        Category::IpDeclaredLengthInvalid,
        Category::IpCaptureTruncated,
        Category::IpFragmented,
        Category::IpReservedFlag,
        Category::IpExtensionChain,
        Category::IpRoutingUnsupported,
        Category::IpJumbogramUnsupported,
        Category::IpSourceMismatch,
        Category::IpDestinationMismatch,
        Category::UnrelatedIpProtocol,
        Category::IcmpMalformed,
    ] {
        shard.packet_rejection(true, category);
    }
    shard.flush();
    let snapshot = stats.load_snapshot();
    assert_eq!(snapshot.network.ip_missing_header, 1);
    assert_eq!(snapshot.network.ip_invalid_version, 1);
    assert_eq!(snapshot.network.ip_truncated_header, 1);
    assert_eq!(snapshot.network.ip_declared_length_invalid, 1);
    assert_eq!(snapshot.network.ip_capture_truncated, 1);
    assert_eq!(snapshot.network.ip_fragmented, 1);
    assert_eq!(snapshot.network.ip_reserved_flag, 1);
    assert_eq!(snapshot.network.ip_extension_chain, 1);
    assert_eq!(snapshot.network.ip_routing_unsupported, 1);
    assert_eq!(snapshot.network.ip_jumbogram_unsupported, 1);
    assert_eq!(snapshot.network.ip_source_mismatch, 1);
    assert_eq!(snapshot.network.ip_destination_mismatch, 1);
    assert_eq!(snapshot.network.unrelated_ip_protocol, 1);
    assert_eq!(snapshot.network.icmp_malformed, 1);
}

#[test]
fn nanosecond_accounting_preserves_sub_microsecond_samples() {
    let stats = Stats::with_worker_shards(1);
    let mut shard = stats.recorder(0);
    let now = Instant::now();
    shard.send_add(
        true,
        1,
        now,
        now + Duration::from_nanos(199),
        now + Duration::from_nanos(499),
    );
    shard.flush();

    let snap = stats.load_snapshot();
    assert_eq!(snap.c2u.lat_sum_ns, 499);
    assert_eq!(snap.c2u.lat_max_ns, 499);
    assert_eq!(snap.c2u.queue_sum_ns, 199);
    assert_eq!(snap.c2u.service_sum_ns, 300);
    assert_eq!(
        snap.c2u.lat_sum_ns,
        snap.c2u.queue_sum_ns + snap.c2u.service_sum_ns
    );
    assert_eq!(Stats::average_ns(snap.c2u.lat_sum_ns, snap.c2u.pkts), 499);
}

#[test]
fn zero_resolution_send_is_reported_without_fabricating_latency() {
    let stats = Stats::with_worker_shards(1);
    let mut shard = stats.recorder(0);
    let now = Instant::now();
    shard.send_add(true, 0, now, now, now);
    shard.flush();

    let snap = stats.load_snapshot();
    assert_eq!(snap.c2u.pkts, 1);
    assert_eq!(snap.c2u.queue_sum_ns, 0);
    assert_eq!(snap.c2u.service_sum_ns, 0);
    assert_eq!(snap.c2u.lat_sum_ns, 0);
    assert_eq!(snap.c2u.zero_resolution_samples, 1);
    assert_eq!(Stats::average_ns(snap.c2u.lat_sum_ns, snap.c2u.pkts), 0);
}

#[test]
fn interval_mean_ewma_matches_half_life_and_handles_extreme_sample_counts() {
    assert_eq!(Stats::ewma_compute(17, 99, 0), 17);
    assert_eq!(
        Stats::ewma_compute(100, 300, 200_000),
        200,
        "one configured half-life gives equal weight to the prior value and interval mean"
    );
    let result = Stats::ewma_compute(u64::MAX - 1, u64::MAX, u64::MAX);
    assert!(result > 0);
}

#[test]
fn snapshot_merge_is_order_independent_for_totals_and_maxima() {
    let left = super::Snapshot {
        c2u: super::DirectionSnapshot {
            pkts: 2,
            bytes: 7,
            lat_sum_ns: 11,
            lat_max_ns: 8,
            ..super::DirectionSnapshot::default()
        },
        ..super::Snapshot::default()
    };
    let right = super::Snapshot {
        c2u: super::DirectionSnapshot {
            pkts: 3,
            bytes: 13,
            lat_sum_ns: 17,
            lat_max_ns: 9,
            ..super::DirectionSnapshot::default()
        },
        ..super::Snapshot::default()
    };
    let mut forward = super::Snapshot::default();
    Stats::merge_snapshot(&mut forward, left);
    Stats::merge_snapshot(&mut forward, right);
    let mut reverse = super::Snapshot::default();
    Stats::merge_snapshot(&mut reverse, right);
    Stats::merge_snapshot(&mut reverse, left);
    assert_eq!(forward.c2u.pkts, reverse.c2u.pkts);
    assert_eq!(forward.c2u.bytes, reverse.c2u.bytes);
    assert_eq!(forward.c2u.lat_sum_ns, reverse.c2u.lat_sum_ns);
    assert_eq!(forward.c2u.lat_max_ns, reverse.c2u.lat_max_ns);
}

#[test]
fn u128_projection_reports_loss_instead_of_hiding_saturation() {
    assert_eq!(Stats::project_u128(u128::from(u64::MAX)), (u64::MAX, false));
    assert_eq!(
        Stats::project_u128(u128::from(u64::MAX) + 1),
        (u64::MAX, true)
    );
}

#[test]
fn categorical_errors_preserve_the_compatibility_aggregate() {
    let stats = Stats::with_worker_shards(1);
    let mut shard = stats.recorder(0);
    shard.receive_error(true);
    shard.user_send_error(true);
    shard.control_send_error(true);
    shard.malformed_packet(true);
    shard.wrong_peer_drop(true);
    shard.wrong_source_drop(true);
    shard.handshake_invalid_drop(true);
    shard.replay_drop(true);
    shard.icmp_abuse_budget_drop(true);
    shard.stale_session_drop(true);
    shard.invariant_failure(true);
    shard.topology_error(true);
    shard.flush();

    let snap = stats.load_snapshot();
    assert_eq!(snap.c2u.errs, 7);
    assert_eq!(snap.c2u.receive_errors, 1);
    assert_eq!(snap.c2u.user_send_errors, 1);
    assert_eq!(snap.c2u.control_send_errors, 1);
    assert_eq!(snap.c2u.admission_drops, 7);
    assert_eq!(snap.admission.malformed_packets, 1);
    assert_eq!(snap.admission.wrong_peer_drops, 1);
    assert_eq!(snap.admission.wrong_source_drops, 1);
    assert_eq!(snap.admission.handshake_invalid_drops, 1);
    assert_eq!(snap.admission.replay_drops, 1);
    assert_eq!(snap.admission.icmp_abuse_budget_drops, 1);
    assert_eq!(snap.admission.stale_session_drops, 1);
    assert_eq!(snap.admission.invariant_failures, 1);
    assert_eq!(snap.c2u.topology_errors, 1);
}

#[test]
fn concurrent_writers_publish_coherent_wide_snapshots() {
    const WRITERS: usize = 4;
    const ITERATIONS: usize = 64;

    let stats = Stats::with_worker_shards(WRITERS);
    let workers = (0..WRITERS)
        .map(|index| {
            let mut recorder = stats.recorder(index);
            thread::spawn(move || {
                let now = Instant::now();
                for _ in 0..ITERATIONS {
                    recorder.send_add(
                        true,
                        3,
                        now,
                        now + Duration::from_nanos(2),
                        now + Duration::from_nanos(7),
                    );
                }
                let generation = recorder.begin_final_flush();
                assert_eq!(
                    recorder.seal_until(
                        generation,
                        Instant::now() + super::STATS_FINAL_FLUSH_DEADLINE,
                    ),
                    super::ProducerSealResult::Sealed
                );
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().expect("join stats writer");
    }
    let snap = stats.load_snapshot();
    let expected_packets = (WRITERS * ITERATIONS) as u64;
    assert_eq!(snap.c2u.pkts, expected_packets);
    assert_eq!(snap.c2u.bytes, u128::from(expected_packets * 3));
    assert_eq!(snap.c2u.lat_sum_ns, u128::from(expected_packets * 7));
    assert_eq!(snap.c2u.lat_max_ns, 7);
}

#[test]
fn thread_owned_recorder_batches_and_explicitly_flushes() {
    let stats = Stats::with_worker_shards(1);
    let mut recorder = stats.recorder(0);
    let now = Instant::now();
    let merge_clock = recorder
        .last_merge_for_test()
        .expect("enabled recorder has a merge clock");
    for _ in 0..255 {
        recorder.update_at(merge_clock, |snapshot| {
            record_send_snapshot(
                snapshot,
                true,
                3,
                now,
                now + Duration::from_nanos(2),
                now + Duration::from_nanos(7),
            );
        });
    }
    let snapshot = stats.load_snapshot();
    assert_eq!(snapshot.c2u.pkts, 0, "sub-batch writes stay thread-local");
    recorder.flush();
    let snapshot = stats.load_snapshot();
    assert_eq!(snapshot.c2u.pkts, 255);
    assert_eq!(snapshot.c2u.bytes, 765);
    assert_eq!(snapshot.c2u.lat_sum_ns, 1_785);
}

#[test]
fn thread_owned_recorder_packet_updates_use_no_allocation_or_queue_rmw() {
    let stats = Stats::with_worker_shards(1);
    let mut recorder = stats.recorder(0);
    let now = Instant::now();
    let merge_clock = recorder
        .last_merge_for_test()
        .expect("enabled recorder has a merge clock");
    let queue_rmws = crate::authority::shared_rmw_count_for_test(
        crate::authority::AuthorityId::StatsPublication,
    );
    let (_, allocations) = crate::allocation_test_support::count_allocations(|| {
        for _ in 0..128 {
            recorder.update_at(merge_clock, |snapshot| {
                record_send_snapshot(snapshot, true, 3, now, now, now);
            });
        }
    });
    assert_eq!(allocations, 0);
    assert_eq!(
        crate::authority::shared_rmw_count_for_test(
            crate::authority::AuthorityId::StatsPublication,
        ),
        queue_rmws,
        "packet accounting must not touch the Crossbeam publication boundary"
    );
    assert_eq!(
        stats.load_snapshot().c2u.pkts,
        0,
        "packet updates remain worker-owned until maintenance"
    );
    recorder.flush();
    assert_eq!(stats.load_snapshot().c2u.pkts, 128);
}

#[test]
fn queue_full_delta_is_retained_and_later_published_exactly() {
    let stats = Stats::with_worker_shards(1);
    let mut recorder = stats.recorder(0);
    let now = Instant::now();
    let merge_clock = recorder
        .last_merge_for_test()
        .expect("enabled recorder has a merge clock");
    for _ in 0..5 {
        for _ in 0..super::STATS_MERGE_EVENTS {
            recorder.update_at(merge_clock, |snapshot| {
                record_send_snapshot(snapshot, true, 1, now, now, now + Duration::from_nanos(1));
            });
        }
        // Packet updates remain thread-local. The worker maintenance boundary
        // publishes after packet authorities are released.
        recorder.maintenance();
    }

    let super::StatsRuntime::Enabled(shared) = &stats.runtime else {
        panic!("test stats runtime must be enabled");
    };
    let mut last_sequences = vec![0; shared.producers.len()];
    let mut cumulative = super::Snapshot::default();
    drain_for_test(shared, &mut cumulative, &mut last_sequences);
    assert_eq!(
        cumulative.c2u.pkts,
        u64::from(super::STATS_MERGE_EVENTS) * 4,
        "the fifth delta remains producer-owned while the four-slot queue is full"
    );
    recorder.maintenance();
    drain_for_test(shared, &mut cumulative, &mut last_sequences);
    assert_eq!(
        cumulative.c2u.pkts,
        u64::from(super::STATS_MERGE_EVENTS) * 5
    );
}

#[test]
fn final_flush_waits_for_each_distinct_worker_recorder() {
    let stats = Arc::new(Stats::with_worker_shards(2));
    let stop = Arc::new(AtomicBool::new(false));
    let workers = (0..2)
        .map(|index| {
            let mut recorder = stats.recorder(index);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let now = Instant::now();
                recorder.send_add(true, 1, now, now, now + Duration::from_nanos(1));
                while !stop.load(Ordering::Acquire) {
                    recorder.maintenance();
                    thread::yield_now();
                }
                let generation = recorder.begin_final_flush();
                assert_eq!(
                    recorder.seal_until(
                        generation,
                        Instant::now() + super::STATS_FINAL_FLUSH_DEADLINE,
                    ),
                    super::ProducerSealResult::Sealed
                );
            })
        })
        .collect::<Vec<_>>();

    stop.store(true, Ordering::Release);
    let snapshot =
        stats.request_final_flush_for_test(Instant::now() + super::STATS_FINAL_FLUSH_DEADLINE);
    for worker in workers {
        worker.join().expect("join recorder worker");
    }
    assert!(!stats.final_flush_incomplete());
    assert_eq!(snapshot.c2u.pkts, 2);
}

#[test]
fn final_flush_accepts_a_recorder_that_already_flushed_and_exited() {
    let stats = Stats::with_worker_shards(1);
    {
        let mut recorder = stats.recorder(0);
        let now = Instant::now();
        recorder.send_add(true, 3, now, now, now + Duration::from_nanos(1));
        let generation = recorder.begin_final_flush();
        assert_eq!(
            recorder.seal_until(
                generation,
                Instant::now() + super::STATS_FINAL_FLUSH_DEADLINE,
            ),
            super::ProducerSealResult::Sealed
        );
    }

    let snapshot =
        stats.request_final_flush_for_test(Instant::now() + super::STATS_FINAL_FLUSH_DEADLINE);

    assert!(!stats.final_flush_incomplete());
    assert_eq!(snapshot.c2u.pkts, 1);
    assert_eq!(snapshot.c2u.bytes, 3);
}

#[test]
fn final_flush_generation_exhaustion_fails_without_wrapping() {
    let generation = std::sync::atomic::AtomicU64::new(u64::MAX);
    assert_eq!(
        crate::atomic_core::advance_notification_generation(&generation),
        Err(crate::atomic_core::ExpectedPublicationError::Exhausted)
    );
}

#[test]
fn disabled_stats_create_a_noop_recorder() {
    let stats = Stats::new(usize::MAX, false).expect("disabled stats require no allocation");
    assert!(!stats.is_enabled());
    let recorder = stats.try_recorder(usize::MAX).expect("disabled recorder");
    assert!(recorder.is_disabled());
}

#[test]
fn inline_stats_publication_allocates_nothing_at_the_queue_boundary() {
    use super::finality_core::StatsPublicationKind;
    use super::publication::STATS_PUBLICATION_QUEUE_CAPACITY;
    use super::{Snapshot, StatsPublication};
    use crossbeam_queue::ArrayQueue;

    let queue = ArrayQueue::new(STATS_PUBLICATION_QUEUE_CAPACITY);
    let (publication_kind, allocations) = crate::allocation_test_support::count_allocations(|| {
        let publication = StatsPublication::delta(1, Snapshot::default());
        assert!(queue.push(publication).is_ok());
        queue.pop().map(|publication| publication.kind)
    });

    assert_eq!(publication_kind, Some(StatsPublicationKind::Delta));
    assert_eq!(allocations, 0);
}

#[test]
fn claimed_but_unstarted_recorder_is_abandoned_and_final_flush_is_incomplete() {
    let stats = Stats::with_worker_shards(1);
    let recorder = stats.recorder(0);
    drop(recorder);

    stats.request_final_flush(Instant::now() + super::STATS_FINAL_FLUSH_DEADLINE);

    assert!(stats.final_flush_incomplete());
    let super::StatsRuntime::Enabled(shared) = &stats.runtime else {
        panic!("test requested enabled stats");
    };
    assert_eq!(shared.abandoned_producers.load(Ordering::Acquire), 1);
}

#[test]
fn worker_panic_flushes_recorder_before_terminal_publication() {
    use crate::runtime_support::{ShutdownController, ThreadRole, ThreadSupervisor};

    let stats = Stats::with_worker_shards(1);
    let recorder = stats.recorder(0);
    let (shutdown, events) = ShutdownController::bootstrap(2).expect("shutdown controller");
    let mut supervisor = ThreadSupervisor::new(Arc::clone(&shutdown), events);
    supervisor
        .spawn_forwarder_with_stats(
            ThreadRole::ClientWorker,
            "stats-panic-flush".to_owned(),
            crate::authority::WorkerAuditIdentity {
                worker: 0,
                direction: crate::authority::AuditDirection::ClientToUpstream,
            },
            recorder,
            |recorder| {
                let now = Instant::now();
                recorder.send_add(
                    true,
                    9,
                    now,
                    now + Duration::from_nanos(2),
                    now + Duration::from_nanos(5),
                );
                panic!("injected worker panic");
            },
        )
        .expect("spawn supervised worker");

    shutdown.wait_for_change(Instant::now() + Duration::from_secs(1));
    assert!(shutdown.is_requested());
    assert!(supervisor.finish(Instant::now() + Duration::from_secs(1)));

    let snapshot = stats.load_snapshot();
    assert_eq!(snapshot.c2u.pkts, 1);
    assert_eq!(snapshot.c2u.bytes, 9);
    assert!(!stats.final_flush_incomplete());
}
