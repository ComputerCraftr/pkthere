use super::AtomicU64Value;

/// Generation proof shared by production transmit-cache capabilities and Loom.
/// Claim and reservation both observe the same publication authority, closing
/// the install-to-reserve TOCTOU window without relying on a total `SeqCst` order.
pub(crate) struct PreparedSessionGeneration {
    generation: u64,
}

impl PreparedSessionGeneration {
    pub(crate) fn claim<Generation: AtomicU64Value>(
        published: &Generation,
        cached_generation: u64,
        exact_session_present: bool,
    ) -> Option<Self> {
        let generation = published.load_acquire();
        (exact_session_present && cached_generation == generation).then_some(Self { generation })
    }

    pub(crate) fn is_current<Generation: AtomicU64Value>(&self, published: &Generation) -> bool {
        published.load_acquire() == self.generation
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}
