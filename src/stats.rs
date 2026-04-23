use crate::flow_state::FlowRuntimeState;
use crate::net::sock_mgr::SocketManager;
use crate::stats_support::{EWMA_LN_BETA, MAINT_TICK_MS};
use serde_json::json;
use socket2::Type;

use std::io::Write;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering as AtomOrdering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) trait StatsSink {
    fn send_add(&self, c2u: bool, bytes: u64, start: Instant, end: Instant);
    fn drop_err(&self, c2u: bool);
    fn drop_oversize(&self, c2u: bool);
}

pub struct Stats {
    start: OnceLock<Instant>,
    spawned: AtomicBool,
    shards: Vec<Arc<StatsShard>>,
}

pub struct StatsShard {
    agg: Agg,
}

#[derive(Clone, Copy, Default)]
struct Snapshot {
    c2u_pkts: u64,
    c2u_bytes: u64,
    c2u_bytes_max: u64,
    c2u_errs: u64,
    u2c_pkts: u64,
    u2c_bytes: u64,
    u2c_bytes_max: u64,
    u2c_errs: u64,
    c2u_lat_sum_ns: u64,
    c2u_lat_max_ns: u64,
    u2c_lat_sum_ns: u64,
    u2c_lat_max_ns: u64,
    c2u_drops_oversize: u64,
    u2c_drops_oversize: u64,
}

struct Agg {
    c2u_pkts: AtomicU64,
    c2u_bytes: AtomicU64,
    c2u_bytes_max: AtomicU64,
    c2u_errs: AtomicU64,
    u2c_pkts: AtomicU64,
    u2c_bytes: AtomicU64,
    u2c_bytes_max: AtomicU64,
    u2c_errs: AtomicU64,
    c2u_lat_sum_ns: AtomicU64,
    c2u_lat_max_ns: AtomicU64,
    u2c_lat_sum_ns: AtomicU64,
    u2c_lat_max_ns: AtomicU64,
    c2u_drops_oversize: AtomicU64,
    u2c_drops_oversize: AtomicU64,
}

impl Stats {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_worker_shards(1)
    }

    pub fn with_worker_shards(worker_pairs: usize) -> Self {
        let shard_count = worker_pairs.max(1);
        Self {
            start: OnceLock::new(),
            spawned: AtomicBool::new(false),
            shards: (0..shard_count)
                .map(|_| Arc::new(StatsShard::new()))
                .collect(),
        }
    }

    pub fn shard(&self, worker_pair_idx: usize) -> Arc<StatsShard> {
        self.shards
            .get(worker_pair_idx)
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.shards[0]))
    }

    /// Returns the Instant when the stats thread was spawned, if started.
    pub fn start_time(&self) -> Option<Instant> {
        self.start.get().cloned()
    }

    /// Returns uptime in seconds since the stats thread was spawned, if started.
    pub fn uptime_seconds(&self) -> Option<u64> {
        self.start.get().map(|s| s.elapsed().as_secs())
    }

    #[inline]
    fn load_snapshot(&self) -> Snapshot {
        self.shards
            .iter()
            .fold(Snapshot::default(), |mut acc, shard| {
                let snap = shard.load_snapshot();
                acc.c2u_pkts += snap.c2u_pkts;
                acc.c2u_bytes += snap.c2u_bytes;
                acc.c2u_bytes_max = acc.c2u_bytes_max.max(snap.c2u_bytes_max);
                acc.c2u_errs += snap.c2u_errs;
                acc.u2c_pkts += snap.u2c_pkts;
                acc.u2c_bytes += snap.u2c_bytes;
                acc.u2c_bytes_max = acc.u2c_bytes_max.max(snap.u2c_bytes_max);
                acc.u2c_errs += snap.u2c_errs;
                acc.c2u_lat_sum_ns += snap.c2u_lat_sum_ns;
                acc.c2u_lat_max_ns = acc.c2u_lat_max_ns.max(snap.c2u_lat_max_ns);
                acc.u2c_lat_sum_ns += snap.u2c_lat_sum_ns;
                acc.u2c_lat_max_ns = acc.u2c_lat_max_ns.max(snap.u2c_lat_max_ns);
                acc.c2u_drops_oversize += snap.c2u_drops_oversize;
                acc.u2c_drops_oversize += snap.u2c_drops_oversize;
                acc
            })
    }

    #[inline]
    fn ewma_compute(prev_ns: u64, sample_avg_ns: u64, sample_count: u64) -> u64 {
        if sample_count == 0 {
            return prev_ns;
        }
        if prev_ns == 0 {
            return sample_avg_ns;
        }
        let k = sample_count as f64;
        let x = EWMA_LN_BETA * k;
        let one_minus_beta_k = -x.exp_m1();
        let beta_k = 1.0 - one_minus_beta_k;

        let prev_f = prev_ns as f64;
        let samp_f = sample_avg_ns as f64;
        let newf = beta_k * prev_f + one_minus_beta_k * samp_f;

        if !newf.is_finite() {
            return 0;
        }
        let r = newf.max(0.0).round();
        if r >= (u64::MAX as f64) {
            u64::MAX
        } else {
            r as u64
        }
    }

    #[inline]
    fn safe_println(s: &str) {
        log_info!("{}", s);
        let _ = std::io::stdout().flush();
    }

    fn print_snapshot(
        &self,
        sock_mgrs: &[Arc<SocketManager>],
        flow_states: &[Arc<FlowRuntimeState>],
        c2u_ewma_ns: u64,
        u2c_ewma_ns: u64,
    ) {
        let snap = self.load_snapshot();
        let uptime = self.uptime_seconds().unwrap_or(0);
        let c2u_us_avg = if snap.c2u_pkts > 0 {
            snap.c2u_lat_sum_ns / (snap.c2u_pkts * 1000)
        } else {
            0
        };
        let u2c_us_avg = if snap.u2c_pkts > 0 {
            snap.u2c_lat_sum_ns / (snap.u2c_pkts * 1000)
        } else {
            0
        };
        let c2u_us_ewma = c2u_ewma_ns / 1000;
        let u2c_us_ewma = u2c_ewma_ns / 1000;
        let c2u_us_max = snap.c2u_lat_max_ns / 1000;
        let u2c_us_max = snap.u2c_lat_max_ns / 1000;
        let worker_flows: Vec<_> = sock_mgrs
            .iter()
            .zip(flow_states.iter())
            .enumerate()
            .map(|(worker_pair, (sock_mgr, state))| {
                let snapshot = sock_mgr.snapshot_state();
                let locked = state.is_locked();
                let client_sock_type = match snapshot.listen_sock_type {
                    Type::RAW => "RAW",
                    Type::DGRAM => "DGRAM",
                    _ => "OTHER",
                };
                let upstream_sock_type = match snapshot.upstream_sock_type {
                    Type::RAW => "RAW",
                    Type::DGRAM => "DGRAM",
                    _ => "OTHER",
                };
                json!({
                    "worker_pair": worker_pair,
                    "locked": locked,
                    "client_proto": snapshot.client_proto.to_str(),
                    "client_sock_type": client_sock_type,
                    "client_connected": if locked { snapshot.client_connected } else { false },
                    "flow_key": if locked { snapshot.locked_flow.map(|key| key.to_string()) } else { None::<String> },
                    "client_addr": if locked { snapshot.locked_flow.map(|key| key.display_addr().to_string()) } else { None::<String> },
                    "client_canonical": if locked { snapshot.client_peer.map(|addr| addr.to_string()) } else { None::<String> },
                    "listen_canonical": snapshot.listen.to_string(),
                    "upstream_canonical": snapshot.upstream.to_string(),
                    "upstream_connected": snapshot.upstream_connected,
                    "upstream_local_canonical": snapshot.upstream_local.to_string(),
                    "upstream_proto": snapshot.upstream_proto.to_str(),
                    "upstream_sock_type": upstream_sock_type,
                })
            })
            .collect();
        let locked_worker_pairs = flow_states.iter().filter(|state| state.is_locked()).count();
        let line = json!({
            "uptime_s": uptime,
            "locked": locked_worker_pairs > 0,
            "locked_worker_pairs": locked_worker_pairs,
            "worker_flows": worker_flows,
            "c2u_pkts": snap.c2u_pkts,
            "c2u_bytes": snap.c2u_bytes,
            "c2u_bytes_max": snap.c2u_bytes_max,
            "c2u_drops_oversize": snap.c2u_drops_oversize,
            "c2u_us_avg": c2u_us_avg,
            "c2u_us_ewma": c2u_us_ewma,
            "c2u_us_max": c2u_us_max,
            "c2u_errs": snap.c2u_errs,
            "u2c_pkts": snap.u2c_pkts,
            "u2c_bytes": snap.u2c_bytes,
            "u2c_bytes_max": snap.u2c_bytes_max,
            "u2c_drops_oversize": snap.u2c_drops_oversize,
            "u2c_us_avg": u2c_us_avg,
            "u2c_us_ewma": u2c_us_ewma,
            "u2c_us_max": u2c_us_max,
            "u2c_errs": snap.u2c_errs,
        });
        Self::safe_println(&line.to_string());
    }

    pub fn spawn_stats_printer(
        self: &Arc<Self>,
        sock_mgrs: Vec<Arc<SocketManager>>,
        flow_states: Vec<Arc<FlowRuntimeState>>,
        start: Instant,
        every_secs: u64,
        exit_code_set: Arc<AtomicU32>,
    ) -> bool {
        let every = every_secs.max(1);
        let stats = Arc::clone(self);
        if self
            .spawned
            .compare_exchange(false, true, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
            .is_err()
        {
            return false;
        }
        let _ = stats.start.set(start);
        thread::spawn(move || {
            let mut prev = stats.load_snapshot();
            let mut c2u_ewma_ns = 0u64;
            let mut u2c_ewma_ns = 0u64;
            let print_period = Duration::from_secs(every);
            let mut next_print_at = stats.start_time().unwrap_or_else(Instant::now) + print_period;
            loop {
                let snap = stats.load_snapshot();
                let d_c2u_pkts = snap.c2u_pkts.saturating_sub(prev.c2u_pkts);
                let d_u2c_pkts = snap.u2c_pkts.saturating_sub(prev.u2c_pkts);
                let d_c2u_lat = snap.c2u_lat_sum_ns.saturating_sub(prev.c2u_lat_sum_ns);
                let d_u2c_lat = snap.u2c_lat_sum_ns.saturating_sub(prev.u2c_lat_sum_ns);
                if d_c2u_pkts > 0 {
                    c2u_ewma_ns =
                        Self::ewma_compute(c2u_ewma_ns, d_c2u_lat / d_c2u_pkts, d_c2u_pkts);
                }
                if d_u2c_pkts > 0 {
                    u2c_ewma_ns =
                        Self::ewma_compute(u2c_ewma_ns, d_u2c_lat / d_u2c_pkts, d_u2c_pkts);
                }
                prev = snap;

                let now = Instant::now();
                if now >= next_print_at {
                    stats.print_snapshot(&sock_mgrs, &flow_states, c2u_ewma_ns, u2c_ewma_ns);
                    next_print_at += print_period;
                    if next_print_at <= now {
                        next_print_at = now + print_period;
                    }
                }

                let exit = exit_code_set.load(AtomOrdering::Relaxed);
                if exit >> 31 == 1 {
                    stats.print_snapshot(&sock_mgrs, &flow_states, c2u_ewma_ns, u2c_ewma_ns);
                    process::exit((exit & 0xFF) as i32);
                }

                thread::sleep(Duration::from_millis(MAINT_TICK_MS));
            }
        });
        true
    }
}

impl StatsShard {
    fn new() -> Self {
        Self {
            agg: Agg {
                c2u_pkts: AtomicU64::new(0),
                c2u_bytes: AtomicU64::new(0),
                c2u_bytes_max: AtomicU64::new(0),
                c2u_errs: AtomicU64::new(0),
                u2c_pkts: AtomicU64::new(0),
                u2c_bytes: AtomicU64::new(0),
                u2c_bytes_max: AtomicU64::new(0),
                u2c_errs: AtomicU64::new(0),
                c2u_lat_sum_ns: AtomicU64::new(0),
                c2u_lat_max_ns: AtomicU64::new(0),
                u2c_lat_sum_ns: AtomicU64::new(0),
                u2c_lat_max_ns: AtomicU64::new(0),
                c2u_drops_oversize: AtomicU64::new(0),
                u2c_drops_oversize: AtomicU64::new(0),
            },
        }
    }

    #[inline]
    fn atomic_fetch_max(a: &AtomicU64, val: u64) {
        let mut cur = a.load(AtomOrdering::Relaxed);
        while val > cur {
            match a.compare_exchange_weak(cur, val, AtomOrdering::Relaxed, AtomOrdering::Relaxed) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }

    #[inline]
    fn load_snapshot(&self) -> Snapshot {
        let a = &self.agg;
        Snapshot {
            c2u_pkts: a.c2u_pkts.load(AtomOrdering::Relaxed),
            c2u_bytes: a.c2u_bytes.load(AtomOrdering::Relaxed),
            c2u_bytes_max: a.c2u_bytes_max.load(AtomOrdering::Relaxed),
            c2u_errs: a.c2u_errs.load(AtomOrdering::Relaxed),
            u2c_pkts: a.u2c_pkts.load(AtomOrdering::Relaxed),
            u2c_bytes: a.u2c_bytes.load(AtomOrdering::Relaxed),
            u2c_bytes_max: a.u2c_bytes_max.load(AtomOrdering::Relaxed),
            u2c_errs: a.u2c_errs.load(AtomOrdering::Relaxed),
            c2u_lat_sum_ns: a.c2u_lat_sum_ns.load(AtomOrdering::Relaxed),
            c2u_lat_max_ns: a.c2u_lat_max_ns.load(AtomOrdering::Relaxed),
            u2c_lat_sum_ns: a.u2c_lat_sum_ns.load(AtomOrdering::Relaxed),
            u2c_lat_max_ns: a.u2c_lat_max_ns.load(AtomOrdering::Relaxed),
            c2u_drops_oversize: a.c2u_drops_oversize.load(AtomOrdering::Relaxed),
            u2c_drops_oversize: a.u2c_drops_oversize.load(AtomOrdering::Relaxed),
        }
    }
}

impl StatsSink for StatsShard {
    #[inline]
    fn send_add(&self, c2u: bool, bytes: u64, start: Instant, end: Instant) {
        self.record_send(c2u, bytes, start, end);
    }

    #[inline]
    fn drop_err(&self, c2u: bool) {
        self.record_drop_err(c2u);
    }

    #[inline]
    fn drop_oversize(&self, c2u: bool) {
        self.record_drop_oversize(c2u);
    }
}

impl StatsShard {
    #[inline]
    fn record_send(&self, c2u: bool, bytes: u64, start: Instant, end: Instant) {
        let lat_ns = end.saturating_duration_since(start).as_nanos() as u64;
        let (atom_pkts, atom_bytes, atom_lat_sum_ns, atom_lat_max_ns, atom_bytes_max) = if c2u {
            (
                &self.agg.c2u_pkts,
                &self.agg.c2u_bytes,
                &self.agg.c2u_lat_sum_ns,
                &self.agg.c2u_lat_max_ns,
                &self.agg.c2u_bytes_max,
            )
        } else {
            (
                &self.agg.u2c_pkts,
                &self.agg.u2c_bytes,
                &self.agg.u2c_lat_sum_ns,
                &self.agg.u2c_lat_max_ns,
                &self.agg.u2c_bytes_max,
            )
        };

        atom_pkts.fetch_add(1, AtomOrdering::Relaxed);
        atom_bytes.fetch_add(bytes, AtomOrdering::Relaxed);
        atom_lat_sum_ns.fetch_add(lat_ns, AtomOrdering::Relaxed);
        Self::atomic_fetch_max(atom_lat_max_ns, lat_ns);
        Self::atomic_fetch_max(atom_bytes_max, bytes);
    }

    #[inline]
    fn record_drop_err(&self, c2u: bool) {
        let atom_errs = if c2u {
            &self.agg.c2u_errs
        } else {
            &self.agg.u2c_errs
        };
        atom_errs.fetch_add(1, AtomOrdering::Relaxed);
    }

    #[inline]
    fn record_drop_oversize(&self, c2u: bool) {
        let atom_drops_oversize = if c2u {
            &self.agg.c2u_drops_oversize
        } else {
            &self.agg.u2c_drops_oversize
        };
        atom_drops_oversize.fetch_add(1, AtomOrdering::Relaxed);
    }
}

impl StatsSink for Stats {
    #[inline]
    fn send_add(&self, c2u: bool, bytes: u64, start: Instant, end: Instant) {
        self.shards[0].record_send(c2u, bytes, start, end);
    }

    #[inline]
    fn drop_err(&self, c2u: bool) {
        self.shards[0].record_drop_err(c2u);
    }

    #[inline]
    fn drop_oversize(&self, c2u: bool) {
        self.shards[0].record_drop_oversize(c2u);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregated_snapshot_matches_sum_of_shards() {
        let stats = Stats::with_worker_shards(2);
        let shard0 = stats.shard(0);
        let shard1 = stats.shard(1);
        let now = Instant::now();
        shard0.send_add(true, 10, now, now + Duration::from_micros(10));
        shard1.send_add(true, 5, now, now + Duration::from_micros(20));
        shard1.drop_err(false);
        shard0.drop_oversize(true);

        let snap = stats.load_snapshot();
        assert_eq!(snap.c2u_pkts, 2);
        assert_eq!(snap.c2u_bytes, 15);
        assert_eq!(snap.u2c_errs, 1);
        assert_eq!(snap.c2u_drops_oversize, 1);
        assert_eq!(snap.c2u_bytes_max, 10);
        assert_eq!(snap.c2u_lat_max_ns, 20_000);
    }
}
