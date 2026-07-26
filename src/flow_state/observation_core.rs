use crate::atomic_core::{
    AtomicObservationWord, ObservationPublicationError, publish_observation_words,
    read_observation_binding,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObservationLifecycleError {
    Occupied,
    GenerationExhausted,
    StateOverflow,
    OwnershipLost,
    WidthMismatch,
}

pub(super) struct ObservationLifecycleCore<Atomic, const WORDS: usize> {
    next_generation: Atomic,
    state: Atomic,
    observed_tick: Atomic,
    binding: [Atomic; WORDS],
}

impl<Atomic: AtomicObservationWord, const WORDS: usize> ObservationLifecycleCore<Atomic, WORDS> {
    pub(super) fn new(mut create: impl FnMut() -> Atomic) -> Self {
        Self {
            next_generation: create(),
            state: create(),
            observed_tick: create(),
            binding: std::array::from_fn(|_| create()),
        }
    }

    pub(super) fn begin(
        &self,
        maximum_generation: u64,
        generation_shift: u32,
        polling_phase: u64,
    ) -> Result<u64, ObservationLifecycleError> {
        let generation = self
            .next_generation
            .load_relaxed()
            .checked_add(1)
            .filter(|generation| *generation <= maximum_generation)
            .ok_or(ObservationLifecycleError::GenerationExhausted)?;
        let encoded = encode_state(generation, generation_shift, polling_phase)?;
        // The generation counter is lane-local. The state CAS is the actual
        // ownership boundary and prevents an accidental second writer from
        // overwriting a live observation.
        self.next_generation.store_relaxed(generation);
        self.state
            .compare_acqrel(0, encoded)
            .map(|_| generation)
            .map_err(|_| ObservationLifecycleError::Occupied)
    }

    pub(super) fn publish_observed(
        &self,
        generation: u64,
        generation_shift: u32,
        polling_phase: u64,
        observed_phase: u64,
        binding: &[u64; WORDS],
        observed_tick: u64,
    ) -> Result<(), ObservationLifecycleError> {
        let polling = encode_state(generation, generation_shift, polling_phase)?;
        let observed = encode_state(generation, generation_shift, observed_phase)?;
        publish_observation_words(
            &self.state,
            &self.binding,
            &self.observed_tick,
            polling,
            observed,
            binding,
            observed_tick,
        )
        .map_err(|error| match error {
            ObservationPublicationError::OwnershipLost => ObservationLifecycleError::OwnershipLost,
            ObservationPublicationError::WidthMismatch => ObservationLifecycleError::WidthMismatch,
        })
    }

    pub(super) fn finish_receive(
        &self,
        generation: u64,
        generation_shift: u32,
        polling_phase: u64,
        observed_phase: u64,
        observation: Option<(&[u64; WORDS], u64)>,
    ) -> Result<bool, ObservationLifecycleError> {
        match observation {
            Some((binding, observed_tick)) => {
                self.publish_observed(
                    generation,
                    generation_shift,
                    polling_phase,
                    observed_phase,
                    binding,
                    observed_tick,
                )?;
                Ok(true)
            }
            None => {
                self.clear(generation, generation_shift)?;
                Ok(false)
            }
        }
    }

    pub(super) fn observed(
        &self,
        phase_mask: u64,
        observed_phase: u64,
    ) -> Option<([u64; WORDS], u64)> {
        read_observation_binding(
            &self.state,
            &self.binding,
            &self.observed_tick,
            phase_mask,
            observed_phase,
        )
    }

    pub(super) fn blocks_exact(
        &self,
        phase_mask: u64,
        observed_phase: u64,
        expected_binding: &[u64; WORDS],
        deadline_tick: u64,
    ) -> bool {
        self.observed(phase_mask, observed_phase)
            .is_some_and(|(binding, observed_tick)| {
                binding == *expected_binding && observed_tick < deadline_tick
            })
    }

    pub(super) fn clear(
        &self,
        generation: u64,
        generation_shift: u32,
    ) -> Result<(), ObservationLifecycleError> {
        let observed = self.state.load_acquire();
        if observed >> generation_shift != generation {
            return Err(ObservationLifecycleError::OwnershipLost);
        }
        self.state
            .compare_release(observed, 0)
            .map(|_| ())
            .map_err(|_| ObservationLifecycleError::OwnershipLost)
    }

    #[cfg(test)]
    pub(super) fn is_active(&self) -> bool {
        self.state.load_acquire() != 0
    }

    pub(super) fn encoded_state(&self) -> u64 {
        self.state.load_acquire()
    }
}

fn encode_state(
    generation: u64,
    generation_shift: u32,
    phase: u64,
) -> Result<u64, ObservationLifecycleError> {
    generation
        .checked_shl(generation_shift)
        .and_then(|value| value.checked_add(phase))
        .ok_or(ObservationLifecycleError::StateOverflow)
}
