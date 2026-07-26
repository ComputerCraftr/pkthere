use crate::flow_key::ClientFlowKey;
use std::collections::HashMap;
use std::num::NonZeroU64;

mod core;
use core::{FlowClaimOwnershipCore, MAX_CLAIM_GENERATION, reserve_flow_claim};
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod core_loom;

struct ClaimRecord {
    worker_pair_id: usize,
    ownership: FlowClaimOwnershipCore<
        crate::authority::AuthorityAtomic<
            crate::authority::tags::FlowClaim,
            std::sync::atomic::AtomicU64,
        >,
    >,
}

struct ClaimState {
    claims: HashMap<ClientFlowKey, ClaimRecord>,
    next_generation: NonZeroU64,
}

pub(crate) struct FlowClaimTable {
    state: crate::authority::AuthorityMutex<crate::authority::tags::FlowClaim, ClaimState>,
}

#[must_use]
pub(crate) struct FlowClaim<'table> {
    table: &'table FlowClaimTable,
    flow: ClientFlowKey,
    worker_pair_id: usize,
    generation: NonZeroU64,
    armed: bool,
}

#[must_use]
pub(crate) struct CommittedFlowClaim<'table> {
    table: &'table FlowClaimTable,
    flow: ClientFlowKey,
    worker_pair_id: usize,
    generation: NonZeroU64,
    armed: bool,
}

impl FlowClaimTable {
    pub fn new() -> Self {
        Self {
            state: crate::authority::AuthorityMutex::new(
                ClaimState {
                    claims: HashMap::with_capacity(crate::cli::MAX_WORKER_PAIRS),
                    next_generation: NonZeroU64::MIN,
                },
                crate::authority::AuthorityInstance::singleton(
                    crate::authority::AuthorityId::FlowClaim,
                ),
            ),
        }
    }

    pub fn try_claim(
        &self,
        flow: ClientFlowKey,
        worker_pair_id: usize,
    ) -> Result<FlowClaim<'_>, ()> {
        let mut state =
            crate::runtime_support::lock_authority_or_shutdown(&self.state, "flow claim");
        if state.claims.contains_key(&flow) {
            return Err(());
        }
        let generation = state.next_generation;
        if generation.get() > MAX_CLAIM_GENERATION {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "flow claim generation exhausted"
            ));
        }
        state.next_generation =
            NonZeroU64::new(generation.get().checked_add(1).unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "flow claim generation exhausted"
                ))
            }))
            .unwrap_or_else(|| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "flow claim generation became zero"
                ))
            });
        let ownership = FlowClaimOwnershipCore {
            state: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::FlowClaimOwnership,
            ),
        };
        reserve_flow_claim(&ownership, generation.get()).unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "flow claim reservation failed: {error:?}"
            ))
        });
        state.claims.insert(
            flow,
            ClaimRecord {
                worker_pair_id,
                ownership,
            },
        );
        Ok(FlowClaim {
            table: self,
            flow,
            worker_pair_id,
            generation,
            armed: true,
        })
    }

    pub(crate) fn take_committed(
        &self,
        flow: ClientFlowKey,
        worker_pair_id: usize,
        generation: NonZeroU64,
    ) -> Result<CommittedFlowClaim<'_>, ()> {
        let state = crate::runtime_support::lock_authority_or_shutdown(&self.state, "flow claim");
        let matches = state.claims.get(&flow).is_some_and(|claim| {
            claim.worker_pair_id == worker_pair_id
                && claim.ownership.take_committed(generation.get()).is_ok()
        });
        drop(state);
        matches
            .then_some(CommittedFlowClaim {
                table: self,
                flow,
                worker_pair_id,
                generation,
                armed: true,
            })
            .ok_or(())
    }

    fn commit_exact(&self, flow: ClientFlowKey, worker_pair_id: usize, generation: NonZeroU64) {
        let state = crate::runtime_support::lock_authority_or_shutdown(&self.state, "flow claim");
        let Some(claim) = state.claims.get(&flow) else {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "flow claim disappeared before commit"
            ));
        };
        if claim.worker_pair_id != worker_pair_id {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "flow claim ownership changed before commit"
            ));
        }
        claim
            .ownership
            .commit(generation.get())
            .unwrap_or_else(|error| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "flow claim ownership changed before commit: {error:?}"
                ))
            });
    }

    fn release_exact(&self, flow: ClientFlowKey, worker_pair_id: usize, generation: NonZeroU64) {
        let mut state =
            crate::runtime_support::lock_authority_or_shutdown(&self.state, "flow claim");
        let released = state.claims.get(&flow).is_some_and(|claim| {
            claim.worker_pair_id == worker_pair_id
                && claim
                    .ownership
                    .release(generation.get())
                    .unwrap_or_else(|error| {
                        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                            "flow claim release failed: {error:?}"
                        ))
                    })
        });
        if released {
            state.claims.remove(&flow);
        }
    }
}

impl FlowClaim<'_> {
    pub(crate) const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    pub(crate) fn commit(mut self) {
        self.table
            .commit_exact(self.flow, self.worker_pair_id, self.generation);
        self.armed = false;
    }
}

impl Drop for FlowClaim<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.table
                .release_exact(self.flow, self.worker_pair_id, self.generation);
            self.armed = false;
        }
    }
}

impl CommittedFlowClaim<'_> {
    pub(crate) fn release(mut self) {
        self.table
            .release_exact(self.flow, self.worker_pair_id, self.generation);
        self.armed = false;
    }
}

impl Drop for CommittedFlowClaim<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.table
                .release_exact(self.flow, self.worker_pair_id, self.generation);
            self.armed = false;
        }
    }
}

#[cfg(test)]
mod tests;
