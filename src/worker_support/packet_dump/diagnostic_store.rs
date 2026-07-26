use crate::diagnostics::PacketTraceId;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub(super) const TERMINAL_TRACE_CAPACITY: usize = 64;
pub(super) static LOST_DIAGNOSTIC_STORES: crate::authority::AuthorityAtomic<
    crate::authority::tags::Diagnostic,
    AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    0,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);
static DEFERRED_UPDATE_DROPS: crate::authority::AuthorityAtomic<
    crate::authority::tags::Diagnostic,
    AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    0,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);
static DIAGNOSTIC_SLOTS: crate::authority::AuthorityOnceLock<
    crate::authority::tags::Diagnostic,
    Box<[DirectionDiagnosticSlot]>,
> = crate::authority::AuthorityOnceLock::new();

#[derive(Clone, Copy)]
pub(super) enum DiagnosticClass {
    Accepted,
    Filtered,
    ReceiveNoise,
}

struct OutputBucket {
    tokens: u32,
    capacity: u32,
    refill_per_second: u32,
    updated_at: Instant,
    fractional_nanos: u64,
}

impl OutputBucket {
    fn new(capacity: u32, refill_per_second: u32, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            updated_at: now,
            fractional_nanos: 0,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated_at);
        self.updated_at = now;
        let scaled = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.refill_per_second))
            .saturating_add(u128::from(self.fractional_nanos));
        let second_nanos = Duration::from_secs(1).as_nanos();
        let replenished = (scaled / second_nanos).min(u128::from(u32::MAX)) as u32;
        self.fractional_nanos = (scaled % second_nanos) as u64;
        self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

pub(super) struct DirectionDiagnosticStore {
    accepted: OutputBucket,
    filtered: OutputBucket,
    receive_noise: OutputBucket,
    pub(super) in_flight: HashMap<PacketTraceId, TraceState>,
    accepted_terminal: VecDeque<PacketTraceId>,
    filtered_terminal: VecDeque<PacketTraceId>,
    noise_terminal: VecDeque<PacketTraceId>,
    pub(super) pending_trace_suppressed: u64,
    terminal_overwrites: u64,
}

#[derive(Clone, Copy)]
pub(super) struct TraceState {
    class: DiagnosticClass,
    completion: Option<CompletedPacketDisposition>,
}

#[derive(Clone, Copy)]
pub(super) struct CompletedPacketDisposition {
    pub(super) trace: PacketTraceId,
    pub(super) disposition: super::PacketDisposition,
    pub(super) retried_unconnected: Option<bool>,
}

impl DirectionDiagnosticStore {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            accepted: OutputBucket::new(16, 4, now),
            filtered: OutputBucket::new(8, 1, now),
            receive_noise: OutputBucket::new(4, 1, now),
            in_flight: HashMap::with_capacity(TERMINAL_TRACE_CAPACITY),
            accepted_terminal: VecDeque::with_capacity(TERMINAL_TRACE_CAPACITY),
            filtered_terminal: VecDeque::with_capacity(TERMINAL_TRACE_CAPACITY),
            noise_terminal: VecDeque::with_capacity(TERMINAL_TRACE_CAPACITY),
            pending_trace_suppressed: 0,
            terminal_overwrites: 0,
        }
    }

    pub(super) fn begin(
        &mut self,
        trace: PacketTraceId,
        class: DiagnosticClass,
        now: Instant,
    ) -> bool {
        if self.in_flight.len() == TERMINAL_TRACE_CAPACITY {
            self.pending_trace_suppressed = self.pending_trace_suppressed.saturating_add(1);
            return false;
        }
        let bucket = match class {
            DiagnosticClass::Accepted => &mut self.accepted,
            DiagnosticClass::Filtered => &mut self.filtered,
            DiagnosticClass::ReceiveNoise => &mut self.receive_noise,
        };
        if !bucket.take(now) {
            self.pending_trace_suppressed = self.pending_trace_suppressed.saturating_add(1);
            return false;
        }
        self.in_flight
            .insert(
                trace,
                TraceState {
                    class,
                    completion: None,
                },
            )
            .is_none()
    }

    pub(super) fn finish(
        &mut self,
        trace: PacketTraceId,
        disposition: super::PacketDisposition,
        retried_unconnected: Option<bool>,
    ) -> bool {
        let Some(state) = self.in_flight.get_mut(&trace) else {
            return false;
        };
        if state.completion.is_some() {
            return false;
        }
        state.completion = Some(CompletedPacketDisposition {
            trace,
            disposition,
            retried_unconnected,
        });
        true
    }

    fn take_completed(&mut self, trace: PacketTraceId) -> Option<CompletedPacketDisposition> {
        let state = self.in_flight.get(&trace)?;
        let completion = state.completion?;
        let class = state.class;
        self.in_flight.remove(&trace);
        let terminal = match class {
            DiagnosticClass::Accepted => &mut self.accepted_terminal,
            DiagnosticClass::Filtered => &mut self.filtered_terminal,
            DiagnosticClass::ReceiveNoise => &mut self.noise_terminal,
        };
        if terminal.len() == TERMINAL_TRACE_CAPACITY {
            terminal.pop_front();
            self.terminal_overwrites = self.terminal_overwrites.saturating_add(1);
        }
        terminal.push_back(trace);
        Some(completion)
    }
}

struct DirectionDiagnosticSlot {
    store: crate::authority::AuthorityMutex<
        crate::authority::tags::Diagnostic,
        DirectionDiagnosticStore,
    >,
    deferred_updates: crate::authority::AuthorityQueue<
        crate::authority::tags::Diagnostic,
        DeferredDiagnosticUpdate,
    >,
}

#[derive(Clone, Copy)]
enum DeferredDiagnosticUpdate {
    Begin {
        trace: PacketTraceId,
        class: DiagnosticClass,
        now: Instant,
    },
    Finish(CompletedPacketDisposition),
}

pub(super) fn configure(worker_threads: usize) -> io::Result<()> {
    if worker_threads == 0 {
        return Err(io::Error::other(
            "packet diagnostic storage requires at least one worker",
        ));
    }
    let now = Instant::now();
    let update_capacity = TERMINAL_TRACE_CAPACITY
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("diagnostic update capacity overflow"))?;
    let slots = (0..worker_threads)
        .map(|index| DirectionDiagnosticSlot {
            store: crate::authority::AuthorityMutex::new(
                DirectionDiagnosticStore::new(now),
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::Diagnostic,
                    flow: 0,
                    direction: 0,
                    kind: 0,
                    session: index as u64,
                },
            ),
            deferred_updates: crate::authority::AuthorityQueue::new(
                update_capacity,
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::Diagnostic,
                    flow: 0,
                    direction: 0,
                    kind: 1,
                    session: index as u64,
                },
            ),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    DIAGNOSTIC_SLOTS
        .set(slots)
        .map_err(|_| io::Error::other("packet diagnostic storage was configured twice"))
}

pub(super) fn try_lock_diagnostic_store(
    store: &crate::authority::AuthorityMutex<
        crate::authority::tags::Diagnostic,
        DirectionDiagnosticStore,
    >,
) -> Option<
    crate::authority::AuthorityMutexGuard<
        '_,
        crate::authority::tags::Diagnostic,
        DirectionDiagnosticStore,
    >,
> {
    match store.try_lock_reinitializing(|| DirectionDiagnosticStore::new(Instant::now())) {
        Ok((guard, reinitialized)) => {
            if reinitialized
                && LOST_DIAGNOSTIC_STORES
                    .try_update(Ordering::Release, Ordering::Relaxed, |value| {
                        value.checked_add(1)
                    })
                    .is_err()
            {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "lost diagnostic-store counter exhausted"
                ));
            }
            Some(guard)
        }
        Err(crate::authority::AuthorityTryLockError::WouldBlock) => None,
        Err(crate::authority::AuthorityTryLockError::Authority(error)) => {
            crate::runtime_support::publish_process_fatal(format_args!(
                "diagnostic-store authority failed: {error}"
            ));
            None
        }
    }
}

fn drain_deferred_updates(slot: &DirectionDiagnosticSlot, store: &mut DirectionDiagnosticStore) {
    while let Some(update) = slot.deferred_updates.pop() {
        match update {
            DeferredDiagnosticUpdate::Begin { trace, class, now } => {
                store.begin(trace, class, now);
            }
            DeferredDiagnosticUpdate::Finish(completion) => {
                store.finish(
                    completion.trace,
                    completion.disposition,
                    completion.retried_unconnected,
                );
            }
        }
    }
}

pub(super) fn begin_trace_output(
    trace: PacketTraceId,
    class: DiagnosticClass,
    now: Instant,
) -> bool {
    let Some(slot) = DIAGNOSTIC_SLOTS
        .get()
        .and_then(|slots| slots.get(trace.worker_id))
    else {
        return false;
    };
    queue_deferred_update(slot, DeferredDiagnosticUpdate::Begin { trace, class, now })
}

pub(super) fn finish_trace_output(
    trace: PacketTraceId,
    disposition: super::PacketDisposition,
    retried_unconnected: Option<bool>,
) -> bool {
    let Some(slot) = DIAGNOSTIC_SLOTS
        .get()
        .and_then(|slots| slots.get(trace.worker_id))
    else {
        return false;
    };
    queue_deferred_update(
        slot,
        DeferredDiagnosticUpdate::Finish(CompletedPacketDisposition {
            trace,
            disposition,
            retried_unconnected,
        }),
    )
}

fn queue_deferred_update(slot: &DirectionDiagnosticSlot, update: DeferredDiagnosticUpdate) -> bool {
    let queued = slot.deferred_updates.push(update).is_ok();
    if !queued
        && DEFERRED_UPDATE_DROPS
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |drops| {
                drops.checked_add(1)
            })
            .is_err()
    {
        crate::runtime_support::publish_process_fatal(format_args!(
            "deferred diagnostic-update drop counter exhausted"
        ));
    }
    queued
}

pub(super) fn take_completed_trace(trace: PacketTraceId) -> Option<CompletedPacketDisposition> {
    let slot = DIAGNOSTIC_SLOTS
        .get()
        .and_then(|slots| slots.get(trace.worker_id))?;
    let mut store = try_lock_diagnostic_store(&slot.store)?;
    drain_deferred_updates(slot, &mut store);
    store.take_completed(trace)
}

pub(super) fn take_any_completed_trace(worker_id: usize) -> Option<CompletedPacketDisposition> {
    let slot = DIAGNOSTIC_SLOTS
        .get()
        .and_then(|slots| slots.get(worker_id))?;
    let mut store = try_lock_diagnostic_store(&slot.store)?;
    drain_deferred_updates(slot, &mut store);
    let trace = store
        .in_flight
        .iter()
        .find_map(|(trace, state)| state.completion.is_some().then_some(*trace))?;
    store.take_completed(trace)
}
