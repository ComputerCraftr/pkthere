use super::{
    DataSequenceEvidenceState, IcmpSequenceCache, MAX_TRACKED_RECEIVE_SESSIONS,
    MAX_TRACKED_TRANSMIT_SESSIONS, NEXT_SEQUENCE_AUTHORITY_ID, REPLAY_WINDOW_WORDS,
    ReceiveSequenceState, SequenceRejectionCounters, SessionId, SharedIcmpSequenceState,
    TransmitSequenceState, cache_from_windows,
};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

impl SharedIcmpSequenceState {
    pub(crate) fn new() -> Self {
        let authority_id = NEXT_SEQUENCE_AUTHORITY_ID
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .unwrap_or_else(|_| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "ICMP sequence authority identity exhausted"
                ))
            });
        let state = Self {
            authority_id,
            generation: crate::authority::AuthorityAtomic::new_u64(
                1,
                crate::authority::AtomicProtocolId::ReceiveReplay,
            ),
            reply_icmp_seq: crate::authority::AuthorityAtomic::new_u32(
                0,
                crate::authority::AtomicProtocolId::ReceiveReplay,
            ),
            transmit: crate::authority::AuthorityMutex::new(
                TransmitSequenceState {
                    generation: 1,
                    transmit_sessions: Vec::with_capacity(MAX_TRACKED_TRANSMIT_SESSIONS),
                },
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::SessionControl,
                    flow: authority_id,
                    direction: 0,
                    kind: 0,
                    session: 0,
                },
            ),
            receive: crate::authority::AuthorityMutex::new(
                ReceiveSequenceState {
                    generation: 1,
                    receive_session_id: None,
                    replay_highest: None,
                    replay_bitmap: [0; REPLAY_WINDOW_WORDS],
                    draining_receive_sessions: VecDeque::with_capacity(
                        MAX_TRACKED_RECEIVE_SESSIONS - 1,
                    ),
                    rejection_counters: SequenceRejectionCounters::default(),
                },
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::ProtocolReceive,
                    flow: authority_id,
                    direction: 0,
                    kind: 0,
                    session: 0,
                },
            ),
        };
        state.transmit.prewarm().unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ICMP transmit authority prewarm failed: {error}"
            ))
        });
        state.receive.prewarm().unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ICMP receive authority prewarm failed: {error}"
            ))
        });
        state
    }

    #[inline]
    pub(crate) fn cache(&self) -> IcmpSequenceCache {
        let transmit = crate::runtime_support::lock_authority_or_shutdown(
            &self.transmit,
            "ICMP transmit sequence",
        );
        cache_from_windows(
            &transmit,
            self.reply_icmp_seq.load(Ordering::Acquire) as u16,
        )
    }

    pub(crate) fn rejection_counters(&self) -> SequenceRejectionCounters {
        crate::runtime_support::lock_authority_or_shutdown(&self.receive, "ICMP receive sequence")
            .rejection_counters
    }

    pub(super) fn outbound_session_requires_rekey(&self, session_id: SessionId) -> bool {
        let transmit = crate::runtime_support::lock_authority_or_shutdown(
            &self.transmit,
            "ICMP transmit sequence",
        );
        transmit
            .transmit_sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .is_some_and(|session| {
                session.status() != super::send_completion::TransmitSessionStatus::Active
            })
    }

    pub(crate) fn remaining_outbound_sequences(
        &self,
        session_ids: impl IntoIterator<Item = SessionId>,
    ) -> Option<u64> {
        const SEQUENCES_PER_SESSION: u32 = u16::MAX as u32 + 1;

        let transmit = crate::runtime_support::lock_authority_or_shutdown(
            &self.transmit,
            "ICMP transmit sequence",
        );
        session_ids
            .into_iter()
            .try_fold(0_u64, |total, session_id| {
                let allocated = transmit
                    .transmit_sessions
                    .iter()
                    .find(|session| session.session_id == session_id)?
                    .allocated();
                let remaining = SEQUENCES_PER_SESSION.checked_sub(allocated)?;
                total.checked_add(u64::from(remaining))
            })
    }

    pub(crate) fn retire_outbound_sessions(&self, session_ids: &[SessionId]) -> usize {
        let mut transmit = crate::runtime_support::lock_authority_or_shutdown(
            &self.transmit,
            "ICMP transmit sequence",
        );
        let before = transmit.transmit_sessions.len();
        for session in &transmit.transmit_sessions {
            if session_ids.contains(&session.session_id) {
                session.supersede();
            }
        }
        transmit
            .transmit_sessions
            .retain(|session| !session_ids.contains(&session.session_id));
        before - transmit.transmit_sessions.len()
    }

    pub(crate) fn outbound_data_evidence(
        &self,
        session_id: SessionId,
        sequence: u16,
    ) -> DataSequenceEvidenceState {
        let transmit = crate::runtime_support::lock_authority_or_shutdown(
            &self.transmit,
            "ICMP transmit sequence",
        );
        transmit
            .transmit_sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .map_or(DataSequenceEvidenceState::Unknown, |session| {
                session.data_evidence(sequence)
            })
    }

    pub(crate) fn defer_outbound_data_control(
        &self,
        session_id: SessionId,
        control: crate::flow_state::DeferredPeerControl,
    ) -> super::DeferredDataControlOutcome {
        let transmit = crate::runtime_support::lock_authority_or_shutdown(
            &self.transmit,
            "ICMP transmit sequence",
        );
        transmit
            .transmit_sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .map_or(super::DeferredDataControlOutcome::Rejected, |session| {
                session.defer_control(control)
            })
    }
}
