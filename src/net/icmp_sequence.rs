use crate::net::payload::IcmpPayloadMeta;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering as AtomOrdering};

const DEDUP_SLOT_COUNT: usize = 2048;

#[repr(align(64))]
pub(crate) struct AlignedAtomicU64(pub(crate) AtomicU64);

#[repr(align(64))]
pub(crate) struct AlignedLatest {
    pub(crate) seq: AtomicU16,
    pub(crate) valid: AtomicBool,
}

#[repr(align(64))]
pub(crate) struct AlignedReplySeq(pub(crate) AtomicU16);

#[repr(align(64))]
pub(crate) struct AlignedRequestSeq(pub(crate) AtomicU16);

#[repr(align(64))]
struct DedupSlot(AtomicU64);

pub(crate) struct SharedIcmpSequenceState {
    pub(crate) generation: AlignedAtomicU64,
    pub(crate) latest: AlignedLatest,
    pub(crate) reply_icmp_seq: AlignedReplySeq,
    pub(crate) request_icmp_seq: AlignedRequestSeq,
    dedup_slots: [DedupSlot; DEDUP_SLOT_COUNT],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct IcmpSequenceCache {
    pub(crate) generation: u64,
    pub(crate) latest_sent_seq: u16,
    pub(crate) latest_valid: bool,
    pub(crate) reply_icmp_seq: u16,
}

impl SharedIcmpSequenceState {
    pub(crate) fn new() -> Self {
        Self {
            generation: AlignedAtomicU64(AtomicU64::new(1)),
            latest: AlignedLatest {
                seq: AtomicU16::new(0),
                valid: AtomicBool::new(false),
            },
            reply_icmp_seq: AlignedReplySeq(AtomicU16::new(0)),
            request_icmp_seq: AlignedRequestSeq(AtomicU16::new(0)),
            dedup_slots: [const { DedupSlot(AtomicU64::new(0)) }; DEDUP_SLOT_COUNT],
        }
    }

    #[inline]
    pub(crate) fn cache(&self) -> IcmpSequenceCache {
        IcmpSequenceCache {
            generation: self.generation.0.load(AtomOrdering::Relaxed),
            latest_sent_seq: self.latest.seq.load(AtomOrdering::Relaxed),
            latest_valid: self.latest.valid.load(AtomOrdering::Relaxed),
            reply_icmp_seq: self.reply_icmp_seq.0.load(AtomOrdering::Relaxed),
        }
    }
}

impl IcmpSequenceCache {
    #[inline]
    pub(crate) fn refresh_from_shared(&mut self, shared: &SharedIcmpSequenceState) {
        self.generation = shared.generation.0.load(AtomOrdering::Relaxed);
        self.latest_sent_seq = shared.latest.seq.load(AtomOrdering::Relaxed);
        self.latest_valid = shared.latest.valid.load(AtomOrdering::Relaxed);
        self.reply_icmp_seq = shared.reply_icmp_seq.0.load(AtomOrdering::Relaxed);
    }
}

#[inline]
fn pack_dedup_stamp(generation: u64, seq: u16) -> u64 {
    (generation << 16) | u64::from(seq)
}

#[inline]
#[cfg(test)]
pub(crate) fn reset_request_counter_for_tests() {
    // No-op now that it's per-state, or we can just not call it.
}

pub(crate) fn reset_sequence_state(
    debug_packets: bool,
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> u64 {
    let next_generation = shared
        .generation
        .0
        .fetch_add(1, AtomOrdering::Relaxed)
        .wrapping_add(1);

    log_debug!(
        debug_packets,
        "[icmp_sequence] generation advanced to {}",
        next_generation
    );

    shared.latest.seq.store(0, AtomOrdering::Relaxed);
    shared.latest.valid.store(false, AtomOrdering::Relaxed);
    shared.reply_icmp_seq.0.store(0, AtomOrdering::Relaxed);
    shared.request_icmp_seq.0.store(0, AtomOrdering::Relaxed);

    for slot in &shared.dedup_slots {
        slot.0.store(0, AtomOrdering::Relaxed);
    }

    cache.generation = next_generation;
    cache.latest_valid = false;
    cache.latest_sent_seq = 0;
    cache.reply_icmp_seq = 0;
    next_generation
}

pub(crate) fn remember_request_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    icmp: &IcmpPayloadMeta,
) {
    shared
        .reply_icmp_seq
        .0
        .store(icmp.seq(), AtomOrdering::Relaxed);
    cache.reply_icmp_seq = icmp.seq();
}

pub(crate) fn admit_inbound_sequence(
    debug_packets: bool,
    shared: &SharedIcmpSequenceState,
    icmp: &IcmpPayloadMeta,
) -> io::Result<()> {
    let shared_gen = shared.generation.0.load(AtomOrdering::Relaxed);
    let stamp = pack_dedup_stamp(shared_gen, icmp.seq());
    let slot_idx = (icmp.seq() as usize) & (DEDUP_SLOT_COUNT - 1);
    let prev = shared.dedup_slots[slot_idx].0.load(AtomOrdering::Relaxed);

    log_debug!(
        debug_packets,
        "[icmp_sequence] seq={} stamp={:016x} slot_idx={} prev={:016x} generation={}",
        icmp.seq(),
        stamp,
        slot_idx,
        prev,
        shared_gen
    );

    let slot = &shared.dedup_slots[slot_idx].0;
    let mut prev = prev;
    loop {
        if prev == stamp {
            log_debug!(
                debug_packets,
                "[icmp_sequence] duplicate ICMP tunnel sequence"
            );

            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate ICMP tunnel sequence",
            ));
        }
        match slot.compare_exchange_weak(prev, stamp, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
        {
            Ok(_) => break,
            Err(current) => prev = current,
        }
    }
    Ok(())
}

pub(crate) fn remember_outbound_request_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> u16 {
    let seq = shared
        .request_icmp_seq
        .0
        .fetch_add(1, AtomOrdering::Relaxed);
    shared.latest.seq.store(seq, AtomOrdering::Relaxed);
    shared.latest.valid.store(true, AtomOrdering::Relaxed);
    cache.latest_sent_seq = seq;
    cache.latest_valid = true;
    cache.generation = shared.generation.0.load(AtomOrdering::Relaxed);
    seq
}

pub(crate) fn current_reply_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> u16 {
    cache.reply_icmp_seq = shared.reply_icmp_seq.0.load(AtomOrdering::Relaxed);
    cache.reply_icmp_seq
}
