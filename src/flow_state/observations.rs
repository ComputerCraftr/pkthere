use super::{
    CONTROL_OBSERVATION_WORDS, ClientFlowKey, FlowRuntimeState, MAX_OBSERVATION_GENERATION,
    OBSERVATION_OBSERVED, OBSERVATION_PHASE_MASK, OBSERVATION_POLLING, PoolGeneration,
    RejectedFrameEvidence, SessionKey, runtime,
};
use std::sync::atomic::AtomicU64;
use std::time::Instant;

pub(super) struct ActivityLane {
    pub(super) publication_sequence:
        crate::authority::AuthorityAtomic<crate::authority::tags::Activity, AtomicU64>,
    pub(super) activity_generation:
        crate::authority::AuthorityAtomic<crate::authority::tags::Activity, AtomicU64>,
    pub(super) latest_tick:
        crate::authority::AuthorityAtomic<crate::authority::tags::Activity, AtomicU64>,
}

impl ActivityLane {
    pub(super) const fn new() -> Self {
        Self {
            publication_sequence: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::ActivityPublication,
            ),
            activity_generation: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::ActivityPublication,
            ),
            latest_tick: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::ActivityPublication,
            ),
        }
    }
}

pub(crate) struct ControlObservationGuard<'a> {
    state: &'a FlowRuntimeState,
    lane: usize,
    generation: u64,
}

pub(crate) struct ControlObservationReservation<'a> {
    pub(super) state: &'a FlowRuntimeState,
    pub(super) lane: usize,
    pub(super) generation: u64,
    pub(super) flow_epoch: u64,
    pub(super) c2u: bool,
    pub(super) observed_at: Option<Instant>,
    pub(super) active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ControlTransactionKey {
    flow_epoch: u64,
    c2u: bool,
    peer_flow: Option<ClientFlowKey>,
    icmp: crate::net::payload::IcmpPayloadMeta,
}

impl ControlTransactionKey {
    pub(crate) const fn new(
        flow_epoch: u64,
        c2u: bool,
        peer_flow: Option<ClientFlowKey>,
        icmp: crate::net::payload::IcmpPayloadMeta,
    ) -> Self {
        Self {
            flow_epoch,
            c2u,
            peer_flow,
            icmp,
        }
    }
}

pub(super) struct ControlObservationLanes {
    lanes: Box<[ControlObservationLane]>,
    origin: Instant,
}

pub(super) struct ExactControlObservation {
    pub(super) flow_epoch: u64,
    pub(super) c2u: bool,
    pub(super) peer_flow: Option<ClientFlowKey>,
    pub(super) remote_source_id: u16,
    pub(super) local_destination_id: u16,
    pub(super) deadline: Instant,
}

impl ControlObservationLanes {
    pub(super) fn with_capacity(capacity: usize, origin: Instant) -> Self {
        let mut lanes = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            lanes.push(ControlObservationLane::new());
        }
        Self {
            lanes: lanes.into_boxed_slice(),
            origin,
        }
    }

    pub(super) fn lane(&self, index: usize) -> Option<&ControlObservationLane> {
        self.lanes.get(index)
    }

    pub(super) fn blocks_matching(
        &self,
        deadline: Instant,
        mut matches: impl FnMut(ControlObservationBinding) -> bool,
    ) -> bool {
        let deadline_tick = runtime::monotonic_tick_ns(self.origin, deadline);
        self.lanes.iter().any(|lane| {
            lane.observed().is_some_and(|observed| {
                observed.observed_tick < deadline_tick && matches(observed.binding)
            })
        })
    }

    pub(super) fn blocks_exact_control_variants(
        &self,
        expected: ExactControlObservation,
        mut expected_controls: impl FnMut(
            u16,
        )
            -> [Option<crate::net::framing_shim::IcmpTunnelControl>; 2],
    ) -> bool {
        self.blocks_matching(expected.deadline, |observed| {
            let sequence = observed.sequence();
            expected_controls(sequence)
                .into_iter()
                .flatten()
                .any(|control| {
                    observed.matches_key(ControlTransactionKey::new(
                        expected.flow_epoch,
                        expected.c2u,
                        expected.peer_flow,
                        crate::net::payload::IcmpPayloadMeta::new_control(
                            expected.remote_source_id,
                            expected.local_destination_id,
                            sequence,
                            control,
                        ),
                    ))
                })
        })
    }

    pub(super) fn blocks_exact_key(
        &self,
        transaction_key: ControlTransactionKey,
        deadline: Instant,
    ) -> bool {
        let deadline_tick = runtime::monotonic_tick_ns(self.origin, deadline);
        let expected = ControlObservationBinding::from_key(transaction_key);
        self.lanes.iter().any(|lane| {
            lane.core.blocks_exact(
                OBSERVATION_PHASE_MASK,
                OBSERVATION_OBSERVED,
                &expected.words,
                deadline_tick,
            )
        })
    }

    #[cfg(test)]
    pub(super) fn active_count(&self) -> usize {
        self.lanes
            .iter()
            .filter(|lane| lane.core.is_active())
            .count()
    }
}

#[derive(Clone, Copy)]
struct ObservedControlSnapshot {
    binding: ControlObservationBinding,
    observed_tick: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ControlObservationBinding {
    words: [u64; CONTROL_OBSERVATION_WORDS],
}

impl ControlObservationBinding {
    fn from_key(key: ControlTransactionKey) -> Self {
        let mut words = [0_u64; CONTROL_OBSERVATION_WORDS];
        words[0] = key.flow_epoch;
        words[1] = u64::from(key.c2u);
        if let Some(peer_flow) = key.peer_flow {
            let (kind, endpoint) = match peer_flow {
                ClientFlowKey::Udp(endpoint) => (1_u64, endpoint),
                ClientFlowKey::Icmp(endpoint) => (2_u64, endpoint),
            };
            words[1] |= kind << 1;
            match endpoint.ip() {
                std::net::IpAddr::V4(ip) => {
                    words[1] |= 1 << 3;
                    words[2] = u64::from(u32::from(ip));
                }
                std::net::IpAddr::V6(ip) => {
                    words[1] |= 2 << 3;
                    let address = u128::from(ip);
                    words[2] = address as u64;
                    words[3] = (address >> 64) as u64;
                }
            }
            words[4] = u64::from(endpoint.id()) | (u64::from(endpoint.scope_id()) << 16);
        }
        let identity = key.icmp.flow_identity();
        words[5] = u64::from(identity.remote_source_id())
            | (u64::from(identity.local_destination_id()) << 16)
            | (u64::from(key.icmp.seq()) << 32);
        words[6] = key.icmp.session_id().get();
        if let Some(control) = key.icmp.control() {
            Self::encode_control(&mut words, control);
        }
        Self { words }
    }

    pub(super) fn matches_key(self, expected: ControlTransactionKey) -> bool {
        self == Self::from_key(expected)
    }

    pub(super) const fn sequence(self) -> u16 {
        (self.words[5] >> 32) as u16
    }

    fn encode_session_key(words: &mut [u64; CONTROL_OBSERVATION_WORDS], key: SessionKey) {
        words[8] = key.pool_generation();
        words[9] = u64::from(key.ordinal());
        words[10] = key.session_id().get();
    }

    fn encode_rejected(
        words: &mut [u64; CONTROL_OBSERVATION_WORDS],
        rejected: RejectedFrameEvidence,
    ) {
        words[14] = (u64::from(rejected.sequence()) << 40) | u64::from(rejected.kind() as u8);
        words[15] = rejected.session_id().get();
        if let RejectedFrameEvidence::Negotiate { candidate, .. } = rejected {
            words[13] = candidate.pool_generation();
            words[14] |= u64::from(candidate.ordinal()) << 8;
        }
    }

    fn encode_control(
        words: &mut [u64; CONTROL_OBSERVATION_WORDS],
        control: crate::net::framing_shim::IcmpTunnelControl,
    ) {
        use crate::net::framing_shim::IcmpTunnelControl;
        match control {
            IcmpTunnelControl::Negotiate(negotiation)
            | IcmpTunnelControl::NegotiateAck(negotiation) => {
                words[7] = if negotiation.is_negotiate() { 1 } else { 2 }
                    | (u64::from(negotiation.reply_id()) << 8);
                Self::encode_session_key(words, negotiation.session_key());
                words[11] = negotiation.reset_challenge();
            }
            IcmpTunnelControl::ResetRequired(reset) => {
                words[7] = 3;
                words[11] = reset.challenge().get();
                words[12] = reset.receiver_generation().map_or(0, PoolGeneration::get);
                words[14] = (u64::from(reset.rejected_sequence()) << 40)
                    | u64::from(reset.rejected_kind() as u8);
                words[15] = reset.rejected_session().get();
            }
            IcmpTunnelControl::ChallengeNegotiate(challenge)
            | IcmpTunnelControl::ChallengeAck(challenge) => {
                words[7] = if matches!(control, IcmpTunnelControl::ChallengeNegotiate(_)) {
                    4
                } else {
                    5
                } | (u64::from(challenge.reply_id()) << 8);
                Self::encode_session_key(words, challenge.new_session());
                words[11] = challenge.challenge().get();
                words[12] = challenge
                    .receiver_generation()
                    .map_or(0, PoolGeneration::get);
                Self::encode_rejected(words, challenge.rejected());
            }
            IcmpTunnelControl::GenerationAdvance(advance)
            | IcmpTunnelControl::GenerationAdvanceAck(advance) => {
                words[7] = if matches!(control, IcmpTunnelControl::GenerationAdvance(_)) {
                    6
                } else {
                    7
                };
                Self::encode_session_key(words, advance.current());
                words[12] = advance.proposed_generation().get();
            }
            IcmpTunnelControl::SessionActivated(activated) => {
                words[7] = 8 | (u64::from(activated.accepted_sequence()) << 8);
                Self::encode_session_key(words, activated.session_key());
            }
        }
    }
}

#[repr(align(128))]
pub(super) struct ControlObservationLane {
    core: super::observation_core::ObservationLifecycleCore<
        crate::authority::AuthorityAtomic<crate::authority::tags::ControlObservation, AtomicU64>,
        CONTROL_OBSERVATION_WORDS,
    >,
}

impl ControlObservationLane {
    fn new() -> Self {
        Self {
            core: super::observation_core::ObservationLifecycleCore::new(|| {
                crate::authority::AuthorityAtomic::new_u64(
                    0,
                    crate::authority::AtomicProtocolId::ControlObservation,
                )
            }),
        }
    }

    pub(super) fn begin(&self) -> std::io::Result<u64> {
        self.core
            .begin(MAX_OBSERVATION_GENERATION, 2, OBSERVATION_POLLING)
            .map_err(observation_lifecycle_error)
    }

    pub(super) fn finish_receive(
        &self,
        generation: u64,
        observation: Option<(ControlTransactionKey, u64)>,
    ) -> std::io::Result<bool> {
        let binding = observation
            .map(|(key, observed_tick)| (ControlObservationBinding::from_key(key), observed_tick));
        self.core
            .finish_receive(
                generation,
                2,
                OBSERVATION_POLLING,
                OBSERVATION_OBSERVED,
                binding
                    .as_ref()
                    .map(|(binding, observed_tick)| (&binding.words, *observed_tick)),
            )
            .map_err(observation_lifecycle_error)
    }

    pub(super) fn clear(&self, generation: u64, owner: &'static str) {
        if self.core.clear(generation, 2).is_err() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "control observation lane generation ownership was lost by {owner}: expected generation {generation}, observed encoded state {}",
                self.core.encoded_state()
            ));
        }
    }

    fn observed(&self) -> Option<ObservedControlSnapshot> {
        let (words, observed_tick) = self
            .core
            .observed(OBSERVATION_PHASE_MASK, OBSERVATION_OBSERVED)?;
        Some(ObservedControlSnapshot {
            binding: ControlObservationBinding { words },
            observed_tick,
        })
    }
}

fn observation_lifecycle_error(
    error: super::observation_core::ObservationLifecycleError,
) -> std::io::Error {
    std::io::Error::other(match error {
        super::observation_core::ObservationLifecycleError::Occupied => {
            "worker control observation lane is already occupied"
        }
        super::observation_core::ObservationLifecycleError::GenerationExhausted => {
            "control observation generation exhausted"
        }
        super::observation_core::ObservationLifecycleError::StateOverflow => {
            "control observation state overflowed"
        }
        super::observation_core::ObservationLifecycleError::OwnershipLost => {
            "control observation lane publication lost ownership"
        }
        super::observation_core::ObservationLifecycleError::WidthMismatch => {
            "control observation binding width is inconsistent"
        }
    })
}

impl Drop for ControlObservationGuard<'_> {
    fn drop(&mut self) {
        self.state
            .release_control_observation(self.lane, self.generation);
    }
}

impl Drop for ControlObservationReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.state
                .release_control_observation_reservation(self.lane, self.generation);
        }
    }
}

impl<'a> ControlObservationReservation<'a> {
    pub(crate) fn observe(mut self, observed_at: Instant) -> Self {
        self.observed_at = Some(observed_at);
        self
    }

    pub(crate) fn finish(
        mut self,
        key: Option<ControlTransactionKey>,
    ) -> std::io::Result<Option<ControlObservationGuard<'a>>> {
        if key.is_some() && self.observed_at.is_none() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "control observation receive timestamp and transaction key ownership diverged"
            ));
            return Err(std::io::Error::other(
                "control observation receive timestamp is inconsistent",
            ));
        }
        if key.is_some_and(|key| key.flow_epoch != self.flow_epoch || key.c2u != self.c2u) {
            crate::runtime_support::publish_process_fatal(format_args!(
                "control observation transaction identity does not match its polling reservation"
            ));
            return Err(std::io::Error::other(
                "control observation transaction identity mismatch",
            ));
        }
        let observation = self
            .state
            .control_observations
            .lane(self.lane)
            .ok_or_else(|| std::io::Error::other("control observation lane is out of range"))?;
        let observed = match (key, self.observed_at) {
            (Some(key), Some(observed_at)) => Some((
                key,
                runtime::monotonic_tick_ns(self.state.maintenance_origin, observed_at),
            )),
            _ => None,
        };
        let published = observation.finish_receive(self.generation, observed)?;
        self.active = false;
        Ok(published.then(|| ControlObservationGuard {
            state: self.state,
            lane: self.lane,
            generation: self.generation,
        }))
    }
}
