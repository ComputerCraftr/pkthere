use super::{
    IcmpPayloadMeta, IcmpSequenceCache, OutboundRequestSequence, RekeyRequired,
    SharedIcmpSequenceState, claim_prepared_outbound_session, install_outbound_request_session,
    publish_outbound_request_seq,
};
use crate::net::framing_shim::SessionId;
use std::io;
use std::sync::atomic::Ordering;

impl IcmpSequenceCache {
    #[inline]
    pub(crate) fn replace_from_shared_snapshot(&mut self, shared: &SharedIcmpSequenceState) {
        let transmit = crate::runtime_support::lock_authority_or_shutdown(
            &shared.transmit,
            "ICMP transmit sequence",
        );
        *self = super::reset::cache_from_windows(
            &transmit,
            shared.reply_icmp_seq.load(Ordering::Acquire) as u16,
        );
    }
}

impl SharedIcmpSequenceState {
    pub(crate) fn latest_for_tests(&self) -> Option<u16> {
        crate::runtime_support::lock_authority_or_shutdown(&self.transmit, "ICMP transmit sequence")
            .transmit_sessions
            .iter()
            .filter_map(|session| session.latest_published())
            .max()
    }

    pub(crate) fn tracked_receive_session_count_for_tests(&self) -> usize {
        let receive = crate::runtime_support::lock_authority_or_shutdown(
            &self.receive,
            "ICMP receive sequence",
        );
        usize::from(receive.receive_session_id.is_some()) + receive.draining_receive_sessions.len()
    }

    pub(crate) fn receive_session_id_for_tests(&self) -> Option<SessionId> {
        crate::runtime_support::lock_authority_or_shutdown(&self.receive, "ICMP receive sequence")
            .receive_session_id
    }
}

pub(crate) fn reset_sequence_state(
    debug_packets: bool,
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> io::Result<u64> {
    let mut transmit = crate::runtime_support::lock_authority_or_shutdown(
        &shared.transmit,
        "ICMP transmit sequence",
    );
    let mut receive = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    super::reset::reset_sequence_windows(
        debug_packets,
        &shared.generation,
        &shared.reply_icmp_seq,
        &mut transmit,
        &mut receive,
        cache,
    )
}

pub(crate) fn reset_sequence_state_and_seed_receive(
    debug_packets: bool,
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    initial: Option<&IcmpPayloadMeta>,
) -> io::Result<u64> {
    let mut transmit = crate::runtime_support::lock_authority_or_shutdown(
        &shared.transmit,
        "ICMP transmit sequence",
    );
    let mut receive = crate::runtime_support::lock_authority_or_shutdown(
        &shared.receive,
        "ICMP receive sequence",
    );
    let generation = super::reset::reset_sequence_windows(
        debug_packets,
        &shared.generation,
        &shared.reply_icmp_seq,
        &mut transmit,
        &mut receive,
        cache,
    )?;
    super::reset::seed_receive_window(
        debug_packets,
        &shared.reply_icmp_seq,
        &mut receive,
        cache,
        generation,
        initial,
    )?;
    Ok(generation)
}

pub(crate) fn reserve_outbound_request_seq<'cache>(
    shared: &'cache SharedIcmpSequenceState,
    cache: &'cache mut IcmpSequenceCache,
    session_id: SessionId,
) -> Result<OutboundRequestSequence<'cache>, RekeyRequired> {
    install_outbound_request_session(shared, cache, session_id)?;
    crate::worker_support::StableProtocolReservation::reserve(
        claim_prepared_outbound_session(shared, cache, session_id)
            .map_err(|_| RekeyRequired { session_id })?,
    )
}

pub(crate) fn reserve_and_publish_outbound_request_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    session_id: SessionId,
) -> Result<u16, RekeyRequired> {
    let reservation = reserve_outbound_request_seq(shared, cache, session_id)?;
    let sequence = reservation.sequence();
    publish_outbound_request_seq(shared, &reservation);
    Ok(sequence)
}

pub(crate) fn publish_outbound_request_through(
    shared: &SharedIcmpSequenceState,
    session_id: SessionId,
    final_sequence: u16,
) {
    let mut cache = shared.cache();
    loop {
        let sequence = reserve_and_publish_outbound_request_seq(shared, &mut cache, session_id)
            .expect("test sequence remains allocatable");
        assert!(
            sequence <= final_sequence,
            "test setup cannot move a session's sequence backward"
        );
        if sequence == final_sequence {
            return;
        }
    }
}
