use crate::atomic_core::AtomicU64Authority;

const PHASE_MASK: u64 = 0b11;
const VACANT: u64 = 0;
const RESERVED: u64 = 1;
const COMMITTED: u64 = 2;
const TAKEN: u64 = 3;
pub(super) const MAX_CLAIM_GENERATION: u64 = u64::MAX >> 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClaimOwnershipError {
    GenerationOutOfRange,
    Occupied,
    OwnershipLost,
}

pub(super) struct FlowClaimOwnershipCore<State> {
    pub(super) state: State,
}

pub(super) fn reserve_flow_claim<State>(
    core: &FlowClaimOwnershipCore<State>,
    generation: u64,
) -> Result<(), ClaimOwnershipError>
where
    State: AtomicU64Authority,
{
    core.reserve(generation)
}

impl<State> FlowClaimOwnershipCore<State>
where
    State: AtomicU64Authority,
{
    pub(super) fn reserve(&self, generation: u64) -> Result<(), ClaimOwnershipError> {
        let reserved = encode(generation, RESERVED)?;
        self.state
            .compare_acqrel(VACANT, reserved)
            .map(|_| ())
            .map_err(|_| ClaimOwnershipError::Occupied)
    }

    pub(super) fn commit(&self, generation: u64) -> Result<(), ClaimOwnershipError> {
        let reserved = encode(generation, RESERVED)?;
        let committed = encode(generation, COMMITTED)?;
        self.state
            .compare_acqrel(reserved, committed)
            .map(|_| ())
            .map_err(|_| ClaimOwnershipError::OwnershipLost)
    }

    pub(super) fn release(&self, generation: u64) -> Result<bool, ClaimOwnershipError> {
        for phase in [RESERVED, COMMITTED, TAKEN] {
            let owned = encode(generation, phase)?;
            match self.state.compare_release(owned, VACANT) {
                Ok(_) => return Ok(true),
                Err(observed) if generation_of(observed) != Some(generation) => return Ok(false),
                Err(_) => {}
            }
        }
        Err(ClaimOwnershipError::OwnershipLost)
    }

    pub(super) fn take_committed(&self, generation: u64) -> Result<(), ClaimOwnershipError> {
        let committed = encode(generation, COMMITTED)?;
        let taken = encode(generation, TAKEN)?;
        self.state
            .compare_acqrel(committed, taken)
            .map(|_| ())
            .map_err(|_| ClaimOwnershipError::OwnershipLost)
    }

    #[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
    pub(super) fn generation(&self) -> Option<u64> {
        generation_of(self.state.load_acquire())
    }
}

fn encode(generation: u64, phase: u64) -> Result<u64, ClaimOwnershipError> {
    if generation == 0 || generation > MAX_CLAIM_GENERATION {
        return Err(ClaimOwnershipError::GenerationOutOfRange);
    }
    Ok((generation << 2) | phase)
}

fn generation_of(state: u64) -> Option<u64> {
    let phase = state & PHASE_MASK;
    (phase == RESERVED || phase == COMMITTED || phase == TAKEN).then_some(state >> 2)
}
