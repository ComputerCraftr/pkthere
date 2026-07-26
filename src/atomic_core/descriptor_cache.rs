use super::{
    AtomicBoolAuthority, AtomicU64Value, acknowledge_descriptor_cache_revocation,
    register_descriptor_cache, unregister_descriptor_cache,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DescriptorCacheRegistration {
    Registered,
    GateClosed,
    SlotOccupied,
}

/// Single-writer owner of one worker's strong descriptor reference.
pub(crate) struct DescriptorCacheCore<T> {
    registered: bool,
    cached_generation: u64,
    topology_epoch: u64,
    resource_generation: u64,
    descriptor: Option<T>,
}

impl<T> DescriptorCacheCore<T> {
    pub(crate) const fn new() -> Self {
        Self {
            registered: false,
            cached_generation: 0,
            topology_epoch: u64::MAX,
            resource_generation: 0,
            descriptor: None,
        }
    }

    pub(crate) const fn is_registered(&self) -> bool {
        self.registered
    }

    pub(crate) const fn has_descriptor(&self) -> bool {
        self.descriptor.is_some()
    }

    pub(crate) fn descriptor_for_io(
        &mut self,
        resource_generation: u64,
        topology_epoch: u64,
    ) -> Option<&T> {
        if self.resource_generation != resource_generation || self.descriptor.is_none() {
            return None;
        }
        self.topology_epoch = topology_epoch;
        self.descriptor.as_ref()
    }

    pub(crate) fn register_with<Registered, Gate, Error>(
        &mut self,
        registered: &Registered,
        gate: &Gate,
        closed_mask: u64,
        resource_generation: u64,
        acquire: impl FnOnce() -> Result<T, Error>,
    ) -> Result<DescriptorCacheRegistration, Error>
    where
        Registered: AtomicBoolAuthority,
        Gate: AtomicU64Value,
    {
        let registration = register_descriptor_cache(registered, gate, closed_mask);
        if registration != DescriptorCacheRegistration::Registered {
            return Ok(registration);
        }
        self.registered = true;
        match acquire() {
            Ok(descriptor) => {
                self.resource_generation = resource_generation;
                self.descriptor = Some(descriptor);
                Ok(DescriptorCacheRegistration::Registered)
            }
            Err(error) => {
                self.unregister(registered);
                Err(error)
            }
        }
    }

    pub(crate) fn acknowledge<Generation: AtomicU64Value>(
        &mut self,
        requested: &Generation,
        acknowledged: &Generation,
    ) -> bool {
        self.registered
            && acknowledge_descriptor_cache_revocation(
                requested,
                acknowledged,
                &mut self.cached_generation,
                &mut self.topology_epoch,
                &mut self.descriptor,
            )
    }

    pub(crate) fn unregister<Registered: AtomicBoolAuthority>(&mut self, registered: &Registered) {
        if self.registered {
            unregister_descriptor_cache(
                registered,
                &mut self.cached_generation,
                &mut self.topology_epoch,
                &mut self.descriptor,
            );
            self.registered = false;
        } else {
            self.descriptor = None;
            self.topology_epoch = u64::MAX;
            self.cached_generation = 0;
        }
        self.resource_generation = 0;
    }
}
