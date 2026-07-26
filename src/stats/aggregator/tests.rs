use super::StatsAggregator;
use crate::stats::{Stats, StatsRuntime};
use std::time::Instant;

fn enabled_stats(
    producers: usize,
) -> (
    Stats,
    std::sync::Arc<super::EnabledStats>,
    super::StatsAggregatorBootstrap,
) {
    let (stats, aggregator) = Stats::bootstrap(producers, true).expect("create enabled stats");
    let shared = match &stats.runtime {
        StatsRuntime::Enabled(shared) => std::sync::Arc::clone(shared),
        StatsRuntime::Disabled => unreachable!("requested enabled stats"),
    };
    (stats, shared, aggregator.expect("enabled stats aggregator"))
}

#[test]
fn flush_marker_acknowledges_only_after_preceding_delta_is_drained() {
    let (stats, shared, aggregator) = enabled_stats(1);
    let mut recorder = stats.try_recorder(0).expect("claim producer recorder");
    recorder.update_at(Instant::now(), |snapshot| snapshot.c2u.pkts = 1);
    assert_eq!(
        recorder.seal_until(7, Instant::now() + std::time::Duration::from_secs(1)),
        super::super::ProducerSealResult::Sealed
    );
    let producer = &shared.producers[0];
    assert_eq!(producer.acknowledged_generation_for_test(), 0);

    let mut aggregator =
        StatsAggregator::new(std::sync::Arc::clone(&shared), aggregator, Instant::now())
            .expect("start aggregator");
    aggregator.drain_producer(0).expect("drain producer");

    assert_eq!(aggregator.snapshot.c2u.pkts, 1);
    assert_eq!(producer.acknowledged_generation_for_test(), 7);
}
