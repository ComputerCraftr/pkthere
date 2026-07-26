use super::{
    IcmpPayloadMeta, IcmpSequenceCache, MAX_TRACKED_RECEIVE_SESSIONS, REPLAY_WINDOW_BITS,
    REPLAY_WINDOW_WORDS, ReceiveReplayWindow, ReceiveSequenceState, SequenceAdmissionError,
    SequenceRangeRejection, SequenceRejectionCounters, SessionAdmissionSnapshot, SessionId,
    SharedIcmpSequenceState, admission_error, validate_range,
};
use std::io;
use std::sync::atomic::Ordering;

pub(crate) fn remember_request_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    icmp: &IcmpPayloadMeta,
) {
    shared
        .reply_icmp_seq
        .store(u32::from(icmp.seq()), Ordering::Release);
    cache.reply_icmp_seq = icmp.seq();
    cache.generation = shared.generation.load(Ordering::Acquire);
}

pub(crate) fn admit_inbound_sequence(
    debug_packets: bool,
    shared: &SharedIcmpSequenceState,
    icmp: &IcmpPayloadMeta,
    catchup_window: Option<usize>,
) -> io::Result<()> {
    let transmit = catchup_window.map(|_| {
        crate::runtime_support::lock_authority_or_shutdown(
            &shared.transmit,
            "ICMP transmit sequence",
        )
    });
    let mut state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    match state.receive_session_id {
        None => {
            if let Some(index) = state
                .draining_receive_sessions
                .iter()
                .position(|session| session.session_id == icmp.session_id())
            {
                return admit_tracked_receive_sequence(
                    &mut state,
                    index,
                    debug_packets,
                    icmp.seq(),
                );
            }
            return Err(admission_error(SequenceAdmissionError::InactiveSession));
        }
        Some(active) if active != icmp.session_id() => {
            if let Some(index) = state
                .draining_receive_sessions
                .iter()
                .position(|session| session.session_id == icmp.session_id())
            {
                return admit_tracked_receive_sequence(
                    &mut state,
                    index,
                    debug_packets,
                    icmp.seq(),
                );
            }
            return Err(admission_error(SequenceAdmissionError::WrongSession));
        }
        Some(_) => {}
    }

    if let Some(catchup_window) = catchup_window
        && let Some(transmit) = transmit.as_ref()
        && let Err(reason) = validate_range(transmit, icmp.session_id(), icmp.seq(), catchup_window)
    {
        let reason = match reason {
            SequenceRangeRejection::Future => {
                state.rejection_counters.future = state.rejection_counters.future.saturating_add(1);
                SequenceAdmissionError::FutureSync
            }
            SequenceRangeRejection::Stale => {
                state.rejection_counters.stale = state.rejection_counters.stale.saturating_add(1);
                SequenceAdmissionError::StaleSync
            }
        };
        return Err(admission_error(reason));
    }

    let mut replay_highest = state.replay_highest.take();
    let mut replay_bitmap = std::mem::replace(&mut state.replay_bitmap, [0; REPLAY_WINDOW_WORDS]);
    let result = admit_replay_sequence_window(
        debug_packets,
        &mut replay_highest,
        &mut replay_bitmap,
        &mut state.rejection_counters,
        icmp.seq(),
    );
    state.replay_highest = replay_highest;
    state.replay_bitmap = replay_bitmap;
    result
}

fn admit_tracked_receive_sequence(
    state: &mut ReceiveSequenceState,
    index: usize,
    debug_packets: bool,
    sequence: u16,
) -> io::Result<()> {
    let Some(mut session) = state.draining_receive_sessions.remove(index) else {
        return Err(io::Error::other(
            "ICMP receive replay index changed while holding its sequence lock",
        ));
    };
    let result = admit_replay_sequence_window(
        debug_packets,
        &mut session.replay_highest,
        &mut session.replay_bitmap,
        &mut state.rejection_counters,
        sequence,
    );
    state.draining_receive_sessions.insert(index, session);
    result
}

pub(crate) fn register_receive_candidate(
    shared: &SharedIcmpSequenceState,
    session_id: SessionId,
) -> io::Result<bool> {
    let mut state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    if state.receive_session_id == Some(session_id)
        || state
            .draining_receive_sessions
            .iter()
            .any(|session| session.session_id == session_id)
    {
        return Ok(false);
    }
    if state.draining_receive_sessions.len() >= MAX_TRACKED_RECEIVE_SESSIONS - 1 {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "ICMP receive session candidate capacity exhausted",
        ));
    }
    state
        .draining_receive_sessions
        .push_back(ReceiveReplayWindow {
            session_id,
            replay_highest: None,
            replay_bitmap: [0; REPLAY_WINDOW_WORDS],
        });
    Ok(true)
}

pub(crate) fn unregister_receive_candidate(
    shared: &SharedIcmpSequenceState,
    session_id: SessionId,
) -> bool {
    let mut state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    if state.receive_session_id == Some(session_id) {
        return false;
    }
    let Some(index) = state
        .draining_receive_sessions
        .iter()
        .position(|session| session.session_id == session_id)
    else {
        return false;
    };
    state.draining_receive_sessions.remove(index).is_some()
}

pub(crate) fn retain_admitted_receive_sessions(
    shared: &SharedIcmpSequenceState,
    admission: SessionAdmissionSnapshot,
) {
    let mut state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    state
        .draining_receive_sessions
        .retain(|session| admission.contains(session.session_id));
}

pub(crate) fn activate_receive_session(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    session_id: SessionId,
) {
    let mut state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    if state.receive_session_id != Some(session_id) {
        if let Some(previous) = state.receive_session_id {
            if state.draining_receive_sessions.len() == MAX_TRACKED_RECEIVE_SESSIONS - 1 {
                state.draining_receive_sessions.pop_front();
            }
            let replay_highest = state.replay_highest.take();
            let replay_bitmap =
                std::mem::replace(&mut state.replay_bitmap, [0; REPLAY_WINDOW_WORDS]);
            state
                .draining_receive_sessions
                .push_back(ReceiveReplayWindow {
                    session_id: previous,
                    replay_highest,
                    replay_bitmap,
                });
        }
        if let Some(index) = state
            .draining_receive_sessions
            .iter()
            .position(|session| session.session_id == session_id)
        {
            if let Some(restored) = state.draining_receive_sessions.remove(index) {
                state.replay_highest = restored.replay_highest;
                state.replay_bitmap = restored.replay_bitmap;
            } else {
                state.replay_highest = None;
                state.replay_bitmap.fill(0);
            }
        } else {
            state.replay_highest = None;
            state.replay_bitmap.fill(0);
        }
        state.receive_session_id = Some(session_id);
    }
    cache.generation = state.generation;
    cache.reply_icmp_seq = shared.reply_icmp_seq.load(Ordering::Acquire) as u16;
}

pub(super) fn admit_replay_sequence_window(
    _debug_packets: bool,
    replay_highest: &mut Option<u64>,
    replay_bitmap: &mut [u64; REPLAY_WINDOW_WORDS],
    rejection_counters: &mut SequenceRejectionCounters,
    sequence: u16,
) -> io::Result<()> {
    let candidate = u64::from(sequence);

    let Some(highest) = *replay_highest else {
        *replay_highest = Some(candidate);
        replay_bitmap[0] = 1;
        return Ok(());
    };

    if candidate > highest {
        let advance = usize::try_from(candidate - highest).unwrap_or(usize::MAX);
        shift_replay_bitmap(replay_bitmap, advance);
        *replay_highest = Some(candidate);
        replay_bitmap[0] |= 1;
        return Ok(());
    }

    let lag = usize::try_from(highest - candidate).unwrap_or(usize::MAX);
    if lag >= REPLAY_WINDOW_BITS {
        rejection_counters.stale = rejection_counters.stale.saturating_add(1);
        return Err(admission_error(SequenceAdmissionError::StaleReplay));
    }

    let word = lag / u64::BITS as usize;
    let mask = 1_u64 << (lag % u64::BITS as usize);
    let Some(replay_word) = replay_bitmap.get_mut(word) else {
        return Err(admission_error(SequenceAdmissionError::StaleReplay));
    };
    if *replay_word & mask != 0 {
        rejection_counters.duplicate = rejection_counters.duplicate.saturating_add(1);
        return Err(admission_error(SequenceAdmissionError::Duplicate));
    }
    *replay_word |= mask;
    Ok(())
}

fn shift_replay_bitmap(bitmap: &mut [u64; REPLAY_WINDOW_WORDS], shift: usize) {
    if shift >= REPLAY_WINDOW_BITS {
        bitmap.fill(0);
        return;
    }
    let word_shift = shift / u64::BITS as usize;
    let bit_shift = shift % u64::BITS as usize;
    for destination in (0..REPLAY_WINDOW_WORDS).rev() {
        let shifted = destination
            .checked_sub(word_shift)
            .and_then(|source| bitmap.get(source))
            .map_or(0, |source| *source << bit_shift);
        let carry = if bit_shift == 0 {
            0
        } else {
            destination
                .checked_sub(word_shift + 1)
                .and_then(|source| bitmap.get(source))
                .map_or(0, |source| *source >> (u64::BITS as usize - bit_shift))
        };
        if let Some(destination) = bitmap.get_mut(destination) {
            *destination = shifted | carry;
        }
    }
}
