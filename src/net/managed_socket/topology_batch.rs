use std::collections::TryReserveError;
use std::marker::PhantomData;

/// Unforgeable proof that one batch member is being completed by the
/// reverse-order transaction driver.
pub(in crate::net) struct TopologyBatchStep<'batch> {
    _batch: PhantomData<&'batch mut ()>,
}

pub(in crate::net) struct TopologyBatchOrder;

impl TopologyBatchOrder {
    pub(in crate::net) fn try_finish_reverse<Item, Source>(
        items: impl DoubleEndedIterator<Item = Item>,
        mut finish: impl FnMut(&TopologyBatchStep<'_>, Item) -> Result<(), Source>,
    ) -> Result<(), Source> {
        for item in items.rev() {
            let step = TopologyBatchStep {
                _batch: PhantomData::<&mut ()>,
            };
            finish(&step, item)?;
        }
        Ok(())
    }
}

/// Owns a topology-reservation acquisition stack until every resource is
/// consumed in exact reverse order.
///
/// The batch is deliberately consuming: callers cannot fetch an arbitrary
/// member or perform a forward-order terminal action. If one terminal action
/// fails, ownership of every not-yet-processed resource is returned for
/// reverse-order rollback.
pub(in crate::net) struct TopologyReservationBatch<Resource> {
    resources: Vec<Resource>,
}

pub(in crate::net) struct TopologyBatchFailure<Source, Resource> {
    pub(in crate::net) source: Source,
    pub(in crate::net) remaining: TopologyReservationBatch<Resource>,
}

impl<Resource> TopologyReservationBatch<Resource> {
    pub(in crate::net) fn try_with_capacity(capacity: usize) -> Result<Self, TryReserveError> {
        let mut resources = Vec::new();
        resources.try_reserve_exact(capacity)?;
        Ok(Self { resources })
    }

    pub(in crate::net) fn push(&mut self, resource: Resource) {
        self.resources.push(resource);
    }

    pub(in crate::net) fn try_finish_reverse<Source>(
        mut self,
        mut finish: impl FnMut(&TopologyBatchStep<'_>, Resource) -> Result<(), Source>,
    ) -> Result<(), TopologyBatchFailure<Source, Resource>> {
        while let Some(resource) = self.resources.pop() {
            let step = TopologyBatchStep {
                _batch: PhantomData::<&mut ()>,
            };
            if let Err(source) = finish(&step, resource) {
                return Err(TopologyBatchFailure {
                    source,
                    remaining: self,
                });
            }
        }
        Ok(())
    }

    pub(in crate::net) fn rollback_reverse<Source>(
        mut self,
        mut rollback: impl FnMut(&TopologyBatchStep<'_>, Resource) -> Result<(), Source>,
    ) -> Option<Source> {
        let mut first_error = None;
        while let Some(resource) = self.resources.pop() {
            let step = TopologyBatchStep {
                _batch: PhantomData::<&mut ()>,
            };
            if let Err(source) = rollback(&step, resource)
                && first_error.is_none()
            {
                first_error = Some(source);
            }
        }
        first_error
    }
}
