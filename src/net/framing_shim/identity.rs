use super::{PoolGeneration, SessionId};
use std::io;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

static SESSION_ID_ALLOCATOR: crate::authority::AuthorityOnceLock<
    crate::authority::tags::IdentityAllocation,
    Result<SessionIdentityAllocator, String>,
> = crate::authority::AuthorityOnceLock::new();

#[derive(Debug)]
pub(super) struct SessionIdentityAllocator {
    pub(super) last_issued:
        crate::authority::AuthorityAtomic<crate::authority::tags::IdentityAllocation, AtomicU64>,
}

impl SessionIdentityAllocator {
    pub(super) fn from_seed(seed: u64) -> Self {
        // The allocator increments before returning an ID. Mapping the one
        // unusable terminal seed to the final allocatable starting point
        // preserves the random separation without ever wrapping to zero.
        let last_issued = if seed == u64::MAX { u64::MAX - 1 } else { seed };
        Self {
            last_issued: crate::authority::AuthorityAtomic::new_u64(
                last_issued,
                crate::authority::AtomicProtocolId::IdentityGeneration,
            ),
        }
    }

    pub(super) fn from_random_seed(
        mut fill: impl FnMut(&mut [u8]) -> Result<(), String>,
    ) -> Result<Self, String> {
        let mut bytes = [0_u8; size_of::<u64>()];
        fill(&mut bytes)?;
        Ok(Self::from_seed(u64::from_ne_bytes(bytes)))
    }

    pub(super) fn allocate(&self) -> io::Result<SessionId> {
        let previous = self
            .last_issued
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| io::Error::other("ICMP session ID allocator exhausted"))?;
        let value = previous
            .checked_add(1)
            .ok_or_else(|| io::Error::other("ICMP session ID allocation wrapped unexpectedly"))?;
        SessionId::new(value)
            .ok_or_else(|| io::Error::other("ICMP session ID allocator produced zero"))
    }

    pub(super) fn allocate_directional_pair(&self) -> io::Result<SessionId> {
        let previous = self
            .last_issued
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(2)
            })
            .map_err(|_| io::Error::other("ICMP directional session allocator exhausted"))?;
        let transmit = previous.checked_add(1).ok_or_else(|| {
            io::Error::other("ICMP directional session allocation wrapped unexpectedly")
        })?;
        let receive = transmit.checked_add(1).ok_or_else(|| {
            io::Error::other(
                "ICMP directional session allocation lacked response identity headroom",
            )
        })?;
        if receive == 0 {
            return Err(io::Error::other(
                "ICMP directional session allocator produced zero response identity",
            ));
        }
        SessionId::new(transmit)
            .ok_or_else(|| io::Error::other("ICMP directional session allocator produced zero"))
    }
}

pub(super) fn allocate_identity() -> io::Result<NonZeroU64> {
    let allocator = SESSION_ID_ALLOCATOR.get_or_init(|| {
        SessionIdentityAllocator::from_random_seed(|bytes| {
            getrandom::fill(bytes)
                .map_err(|error| format!("secure ICMP identity generation failed: {error}"))
        })
    });
    match allocator {
        Ok(allocator) => Ok(allocator.allocate()?.0),
        Err(error) => Err(io::Error::other(error.clone())),
    }
}

pub(super) fn allocate_directional_session() -> io::Result<NonZeroU64> {
    let allocator = SESSION_ID_ALLOCATOR.get_or_init(|| {
        SessionIdentityAllocator::from_random_seed(|bytes| {
            getrandom::fill(bytes)
                .map_err(|error| format!("secure ICMP identity generation failed: {error}"))
        })
    });
    match allocator {
        Ok(allocator) => Ok(allocator.allocate_directional_pair()?.0),
        Err(error) => Err(io::Error::other(error.clone())),
    }
}
impl SessionId {
    pub(crate) fn fresh() -> io::Result<Self> {
        Ok(Self(allocate_directional_session()?))
    }

    pub(crate) const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) const fn response_session_id(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }

    /// Returns the transmit-session identity whose Echo sequence space is
    /// echoed by this directional response session.
    ///
    /// Production sessions are allocated as adjacent request/response pairs.
    /// Keeping this relation out of the wire format prevents reflected Echo
    /// Requests from sharing the admitted response identity without adding
    /// bytes to every data frame.
    pub(crate) const fn request_session_id(self) -> Option<Self> {
        match self.get().checked_sub(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        Self(NonZeroU64::new(1).expect("one is nonzero"))
    }
}

impl PoolGeneration {
    pub(crate) fn fresh() -> io::Result<Self> {
        Ok(Self(allocate_identity()?))
    }

    pub(crate) const fn new(value: u64) -> Option<Self> {
        match SessionId::new(value) {
            Some(session) => Some(Self(session.0)),
            None => None,
        }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }
}
