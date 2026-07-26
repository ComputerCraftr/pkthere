use super::{
    IcmpPayloadMeta, IcmpSequenceCache, MAX_SEQUENCE_GENERATION, REPLAY_WINDOW_WORDS,
    ReceiveSequenceState, SharedIcmpSequenceState, TransmitSequenceState,
    admit_replay_sequence_window,
};
use std::io;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[inline]
pub(super) fn cache_from_windows(
    transmit: &TransmitSequenceState,
    reply_icmp_seq: u16,
) -> IcmpSequenceCache {
    IcmpSequenceCache {
        generation: transmit.generation,
        reply_icmp_seq,
        transmit_session: None,
    }
}

pub(crate) fn reset_sequence_pair_for_client_lock(
    debug_packets: bool,
    client_shared: &SharedIcmpSequenceState,
    client_cache: &mut IcmpSequenceCache,
    initial: Option<&IcmpPayloadMeta>,
    upstream_shared: &SharedIcmpSequenceState,
    upstream_cache: &mut IcmpSequenceCache,
) -> io::Result<()> {
    if std::ptr::eq(client_shared, upstream_shared) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client and upstream ICMP sequence authorities must be distinct",
        ));
    }
    if client_shared.authority_id < upstream_shared.authority_id {
        let mut client_transmit = crate::runtime_support::lock_authority_or_shutdown(
            &client_shared.transmit,
            "client ICMP transmit sequence",
        );
        let mut upstream_transmit = crate::runtime_support::lock_authority_or_shutdown(
            &upstream_shared.transmit,
            "upstream ICMP transmit sequence",
        );
        let mut client_receive = crate::runtime_support::lock_authority_or_shutdown(
            &client_shared.receive,
            "client ICMP receive sequence",
        );
        let mut upstream_receive = crate::runtime_support::lock_authority_or_shutdown(
            &upstream_shared.receive,
            "upstream ICMP receive sequence",
        );
        reset_locked_sequence_pair(
            debug_packets,
            LockedSequenceDirection {
                generation_authority: &client_shared.generation,
                reply_sequence: &client_shared.reply_icmp_seq,
                transmit: &mut client_transmit,
                receive: &mut client_receive,
                cache: client_cache,
            },
            initial,
            LockedSequenceDirection {
                generation_authority: &upstream_shared.generation,
                reply_sequence: &upstream_shared.reply_icmp_seq,
                transmit: &mut upstream_transmit,
                receive: &mut upstream_receive,
                cache: upstream_cache,
            },
        )
    } else {
        let mut upstream_transmit = crate::runtime_support::lock_authority_or_shutdown(
            &upstream_shared.transmit,
            "upstream ICMP transmit sequence",
        );
        let mut client_transmit = crate::runtime_support::lock_authority_or_shutdown(
            &client_shared.transmit,
            "client ICMP transmit sequence",
        );
        let mut upstream_receive = crate::runtime_support::lock_authority_or_shutdown(
            &upstream_shared.receive,
            "upstream ICMP receive sequence",
        );
        let mut client_receive = crate::runtime_support::lock_authority_or_shutdown(
            &client_shared.receive,
            "client ICMP receive sequence",
        );
        reset_locked_sequence_pair(
            debug_packets,
            LockedSequenceDirection {
                generation_authority: &client_shared.generation,
                reply_sequence: &client_shared.reply_icmp_seq,
                transmit: &mut client_transmit,
                receive: &mut client_receive,
                cache: client_cache,
            },
            initial,
            LockedSequenceDirection {
                generation_authority: &upstream_shared.generation,
                reply_sequence: &upstream_shared.reply_icmp_seq,
                transmit: &mut upstream_transmit,
                receive: &mut upstream_receive,
                cache: upstream_cache,
            },
        )
    }
}

struct LockedSequenceDirection<'a> {
    generation_authority:
        &'a crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolReceive, AtomicU64>,
    reply_sequence:
        &'a crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolReceive, AtomicU32>,
    transmit: &'a mut TransmitSequenceState,
    receive: &'a mut ReceiveSequenceState,
    cache: &'a mut IcmpSequenceCache,
}

fn reset_locked_sequence_pair(
    debug_packets: bool,
    client: LockedSequenceDirection<'_>,
    initial: Option<&IcmpPayloadMeta>,
    upstream: LockedSequenceDirection<'_>,
) -> io::Result<()> {
    preflight_sequence_generations([client.transmit.generation, upstream.transmit.generation])?;

    let client_generation = reset_sequence_windows(
        debug_packets,
        client.generation_authority,
        client.reply_sequence,
        client.transmit,
        client.receive,
        client.cache,
    )?;
    seed_receive_window(
        debug_packets,
        client.reply_sequence,
        client.receive,
        client.cache,
        client_generation,
        initial,
    )?;
    reset_sequence_windows(
        debug_packets,
        upstream.generation_authority,
        upstream.reply_sequence,
        upstream.transmit,
        upstream.receive,
        upstream.cache,
    )?;
    Ok(())
}

pub(super) fn preflight_sequence_generations(generations: [u64; 2]) -> io::Result<()> {
    for generation in generations {
        if generation
            .checked_add(1)
            .filter(|generation| *generation <= MAX_SEQUENCE_GENERATION)
            .is_none()
        {
            return Err(io::Error::other("ICMP sequence generation exhausted"));
        }
    }
    Ok(())
}

pub(super) fn seed_receive_window(
    debug_packets: bool,
    reply_sequence: &crate::authority::AuthorityAtomic<
        crate::authority::tags::ProtocolReceive,
        AtomicU32,
    >,
    state: &mut ReceiveSequenceState,
    cache: &mut IcmpSequenceCache,
    generation: u64,
    initial: Option<&IcmpPayloadMeta>,
) -> io::Result<()> {
    let Some(initial) = initial else {
        return Ok(());
    };
    state.receive_session_id = Some(initial.session_id());
    let mut replay_highest = state.replay_highest.take();
    let mut replay_bitmap = std::mem::replace(&mut state.replay_bitmap, [0; REPLAY_WINDOW_WORDS]);
    let result = admit_replay_sequence_window(
        debug_packets,
        &mut replay_highest,
        &mut replay_bitmap,
        &mut state.rejection_counters,
        initial.seq(),
    );
    state.replay_highest = replay_highest;
    state.replay_bitmap = replay_bitmap;
    result?;
    reply_sequence.store(u32::from(initial.seq()), Ordering::Release);
    cache.generation = generation;
    cache.reply_icmp_seq = initial.seq();
    Ok(())
}

pub(super) fn reset_sequence_windows(
    _debug_packets: bool,
    generation_authority: &crate::authority::AuthorityAtomic<
        crate::authority::tags::ProtocolReceive,
        AtomicU64,
    >,
    reply_sequence: &crate::authority::AuthorityAtomic<
        crate::authority::tags::ProtocolReceive,
        AtomicU32,
    >,
    transmit: &mut TransmitSequenceState,
    receive: &mut ReceiveSequenceState,
    cache: &mut IcmpSequenceCache,
) -> io::Result<u64> {
    let generation = transmit
        .generation
        .checked_add(1)
        .filter(|generation| *generation <= MAX_SEQUENCE_GENERATION)
        .ok_or_else(|| io::Error::other("ICMP sequence generation exhausted"))?;
    transmit.generation = generation;
    for session in &transmit.transmit_sessions {
        session.retire();
    }
    transmit.transmit_sessions.clear();
    receive.generation = generation;
    reply_sequence.store(0, Ordering::Release);
    receive.receive_session_id = None;
    receive.replay_highest = None;
    receive.replay_bitmap.fill(0);
    receive.draining_receive_sessions.clear();
    // Both directional authorities are fully reset before the generation is
    // released to worker caches.
    generation_authority.store(generation, Ordering::Release);
    *cache = cache_from_windows(transmit, 0);

    Ok(generation)
}
