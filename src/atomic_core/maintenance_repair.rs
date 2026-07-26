use super::{AtomicBoolAuthority, AtomicU64Value};

pub(crate) struct MaintenanceRepairCore<'a, Epoch, Deadline, Owner> {
    published_epoch: &'a Epoch,
    deadline_hint: &'a Deadline,
    repair_owner: &'a Owner,
}

impl<'a, Epoch, Deadline, Owner> MaintenanceRepairCore<'a, Epoch, Deadline, Owner>
where
    Epoch: AtomicU64Value,
    Deadline: AtomicU64Value,
    Owner: AtomicBoolAuthority,
{
    pub(crate) const fn new(
        published_epoch: &'a Epoch,
        deadline_hint: &'a Deadline,
        repair_owner: &'a Owner,
    ) -> Self {
        Self {
            published_epoch,
            deadline_hint,
            repair_owner,
        }
    }

    pub(crate) fn try_begin(
        &self,
    ) -> Option<MaintenanceRepairTransaction<'a, Epoch, Deadline, Owner>> {
        self.repair_owner
            .claim_acqrel()
            .then_some(MaintenanceRepairTransaction {
                published_epoch: self.published_epoch,
                deadline_hint: self.deadline_hint,
                repair_owner: self.repair_owner,
                armed: true,
                _thread_bound: std::marker::PhantomData,
            })
    }
}

#[must_use = "maintenance repair ownership must be published or released"]
pub(crate) struct MaintenanceRepairTransaction<
    'a,
    Epoch: AtomicU64Value,
    Deadline: AtomicU64Value,
    Owner: AtomicBoolAuthority,
> {
    published_epoch: &'a Epoch,
    deadline_hint: &'a Deadline,
    repair_owner: &'a Owner,
    armed: bool,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<Epoch, Deadline, Owner> MaintenanceRepairTransaction<'_, Epoch, Deadline, Owner>
where
    Epoch: AtomicU64Value,
    Deadline: AtomicU64Value,
    Owner: AtomicBoolAuthority,
{
    pub(crate) fn publish(mut self, epoch: u64, deadline_tick: u64) {
        self.deadline_hint.store_release(deadline_tick);
        self.published_epoch.store_release(epoch);
        self.repair_owner.store_release(false);
        self.armed = false;
    }
}

impl<Epoch, Deadline, Owner> Drop for MaintenanceRepairTransaction<'_, Epoch, Deadline, Owner>
where
    Epoch: AtomicU64Value,
    Deadline: AtomicU64Value,
    Owner: AtomicBoolAuthority,
{
    fn drop(&mut self) {
        if self.armed {
            self.repair_owner.store_release(false);
            self.armed = false;
        }
    }
}
