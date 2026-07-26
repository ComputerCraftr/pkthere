#[cfg(any(test, feature = "authority-audit"))]
use super::{AtomicProtocolId, AuthorityId, OperationId, WaitId};
use std::io;

#[cfg(any(test, feature = "authority-audit"))]
use super::worker_audit_core::{
    AUDIT_ABANDONED, AUDIT_TERMINAL, AUDIT_UNCLAIMED, AuditSlotPayload, AuditSlotPublicationCore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum AuditDirection {
    ClientToUpstream,
    UpstreamToClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerAuditIdentity {
    pub(crate) worker: usize,
    pub(crate) direction: AuditDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "authority-audit"))]
pub(crate) struct AuditThreadRecord {
    pub(crate) identity: WorkerAuditIdentity,
    pub(crate) pipeline_stages: [u64; 8],
    pub(crate) allocations: u64,
    pub(crate) payload_copies: u64,
    pub(crate) endpoint_normalizations: u64,
    pub(crate) authority_acquisitions: [u64; AuthorityId::COUNT],
    pub(crate) operation_counts: [u64; OperationId::COUNT],
    pub(crate) shared_rmws: [u64; AuthorityId::COUNT],
    pub(crate) protocol_rmws: [u64; AtomicProtocolId::COUNT],
    pub(crate) wait_counts: [u64; WaitId::COUNT],
    pub(crate) forbidden_refcount_rmws: u64,
    pub(crate) forbidden_authority_acquisitions: u64,
    pub(crate) forbidden_shared_rmws: u64,
    pub(crate) allocation_violations_by_authority: [u64; AuthorityId::COUNT],
    pub(crate) violation_code: u64,
}

#[cfg(any(test, feature = "authority-audit"))]
impl AuditThreadRecord {
    pub(crate) fn receive_stage_count(&self) -> u64 {
        self.pipeline_stages[2]
    }

    pub(crate) fn send_stage_count(&self) -> u64 {
        self.pipeline_stages[6]
    }

    pub(crate) fn completed_packet_count(&self) -> u64 {
        self.pipeline_stages[7]
    }

    pub(crate) fn forbidden_authority_acquisition_count(&self) -> u64 {
        self.forbidden_authority_acquisitions
    }

    pub(crate) fn forbidden_shared_rmw_count(&self) -> u64 {
        self.forbidden_shared_rmws
    }

    pub(crate) fn refcount_operation_count(&self) -> u64 {
        self.forbidden_refcount_rmws
    }

    #[cfg(feature = "authority-audit")]
    pub(crate) fn allocation_authority_mask(&self) -> u64 {
        self.allocation_violations_by_authority
            .iter()
            .enumerate()
            .fold(0_u64, |mask, (index, count)| {
                if *count == 0 {
                    mask
                } else {
                    mask | (1_u64 << index)
                }
            })
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.violation_code != 0 {
            return Err("worker audit record contains an authority violation");
        }
        if self.refcount_operation_count() != 0 {
            return Err("worker audit record contains a forbidden refcount RMW");
        }
        if self.allocations != 0 {
            return Err("worker audit record contains an allocation under packet authority");
        }
        if self.payload_copies != 0 {
            return Err("worker audit record contains a payload copy under packet authority");
        }
        if self.endpoint_normalizations != 0 {
            return Err("worker audit record contains a redundant endpoint normalization");
        }
        if self.forbidden_authority_acquisition_count() != 0 {
            return Err("worker audit record contains a forbidden stable-path authority");
        }
        if self.forbidden_shared_rmw_count() != 0 {
            return Err("worker audit record contains a forbidden stable-path shared RMW");
        }
        if self.completed_packet_count() > self.send_stage_count()
            || self.send_stage_count() > self.receive_stage_count()
        {
            return Err("worker audit pipeline stage counts are inconsistent");
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "authority-audit"))]
struct AuditWorkerPayload {
    identity: Option<WorkerAuditIdentity>,
    record: Option<AuditThreadRecord>,
}

#[cfg(any(test, feature = "authority-audit"))]
struct AuditWorkerPayloadStore(
    super::AuthorityMutex<super::tags::RuntimeSupervisor, AuditWorkerPayload>,
);

#[cfg(any(test, feature = "authority-audit"))]
impl AuditSlotPayload<WorkerAuditIdentity, AuditThreadRecord> for AuditWorkerPayloadStore {
    fn install_identity(&self, identity: WorkerAuditIdentity) -> Result<(), &'static str> {
        let mut payload = self
            .0
            .lock()
            .map_err(|_| "worker audit identity lock was poisoned")?;
        if payload.identity.is_some() || payload.record.is_some() {
            return Err("worker audit slot payload was installed twice");
        }
        payload.identity = Some(identity);
        Ok(())
    }

    fn clear_identity(&self) {
        if let Ok(mut payload) = self.0.lock() {
            payload.identity = None;
        }
    }

    fn identity_matches(&self, identity: WorkerAuditIdentity) -> Result<bool, &'static str> {
        let payload = self
            .0
            .lock()
            .map_err(|_| "worker audit identity lock was poisoned")?;
        Ok(payload.identity == Some(identity) && payload.record.is_none())
    }

    fn install_record(&self, record: AuditThreadRecord) -> Result<(), &'static str> {
        let mut payload = self
            .0
            .lock()
            .map_err(|_| "worker audit record lock was poisoned")?;
        if payload.identity.is_none() || payload.record.replace(record).is_some() {
            return Err("worker audit record was published twice");
        }
        Ok(())
    }

    fn terminal_record(&self) -> Result<Option<AuditThreadRecord>, &'static str> {
        self.0
            .lock()
            .map_err(|_| "worker audit record lock was poisoned")
            .map(|payload| payload.record)
    }
}

#[cfg(any(test, feature = "authority-audit"))]
#[repr(align(128))]
struct AuditWorkerSlot {
    publication: AuditSlotPublicationCore<
        super::AuthorityAtomic<super::tags::RuntimeSupervisor, std::sync::atomic::AtomicU8>,
        AuditWorkerPayloadStore,
        WorkerAuditIdentity,
        AuditThreadRecord,
    >,
}

#[cfg(any(test, feature = "authority-audit"))]
impl AuditWorkerSlot {
    fn new() -> Self {
        let instance = super::AuthorityInstance::singleton(super::AuthorityId::RuntimeSupervisor);
        Self {
            publication: AuditSlotPublicationCore::new(
                super::AuthorityAtomic::new_u8(
                    AUDIT_UNCLAIMED,
                    super::AtomicProtocolId::AuditSlotPublication,
                ),
                AuditWorkerPayloadStore(super::AuthorityMutex::new(
                    AuditWorkerPayload {
                        identity: None,
                        record: None,
                    },
                    instance,
                )),
            ),
        }
    }
}

pub(crate) struct WorkerAuditRegistry {
    #[cfg(any(test, feature = "authority-audit"))]
    slots: Box<[AuditWorkerSlot]>,
}

impl WorkerAuditRegistry {
    pub(crate) fn new(capacity: usize) -> io::Result<Self> {
        #[cfg(any(test, feature = "authority-audit"))]
        {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(capacity)
                .map_err(|_| io::Error::other("could not allocate worker audit slots"))?;
            slots.resize_with(capacity, AuditWorkerSlot::new);
            Ok(Self {
                slots: slots.into_boxed_slice(),
            })
        }
        #[cfg(not(any(test, feature = "authority-audit")))]
        {
            let _capacity = capacity;
            Ok(Self {})
        }
    }

    pub(crate) fn register(
        &self,
        slot: usize,
        identity: WorkerAuditIdentity,
    ) -> Result<(), &'static str> {
        #[cfg(any(test, feature = "authority-audit"))]
        {
            let target = self.slots.get(slot).ok_or("worker audit slot is missing")?;
            target.publication.register(identity)?;
        }
        #[cfg(not(any(test, feature = "authority-audit")))]
        {
            let _ignored = (slot, identity);
        }
        Ok(())
    }

    pub(crate) fn begin(
        &self,
        slot: usize,
        identity: WorkerAuditIdentity,
    ) -> Result<(), &'static str> {
        #[cfg(any(test, feature = "authority-audit"))]
        {
            let target = self.slots.get(slot).ok_or("worker audit slot is missing")?;
            target.publication.begin(identity)?;
            super::audit::begin_worker(identity);
        }
        #[cfg(not(any(test, feature = "authority-audit")))]
        {
            let _ignored = (slot, identity);
        }
        Ok(())
    }

    pub(crate) fn seal(&self, slot: usize) -> Result<(), &'static str> {
        #[cfg(any(test, feature = "authority-audit"))]
        {
            let target = self.slots.get(slot).ok_or("worker audit slot is missing")?;
            let record = super::audit::seal_worker()?;
            target.publication.seal(record)?;
        }
        #[cfg(not(any(test, feature = "authority-audit")))]
        {
            let _slot = slot;
        }
        Ok(())
    }

    pub(crate) fn abandon(&self, slot: usize) {
        #[cfg(any(test, feature = "authority-audit"))]
        if let Some(target) = self.slots.get(slot) {
            target.publication.abandon();
        }
        #[cfg(not(any(test, feature = "authority-audit")))]
        let _slot = slot;
    }

    #[cfg(any(test, feature = "authority-audit"))]
    pub(crate) fn records(&self) -> Result<Vec<AuditThreadRecord>, &'static str> {
        #[cfg(any(test, feature = "authority-audit"))]
        {
            let mut records = Vec::new();
            records
                .try_reserve_exact(self.slots.len())
                .map_err(|_| "could not allocate merged worker audit records")?;
            for slot in &self.slots {
                let state = slot.publication.state();
                if state == AUDIT_UNCLAIMED || state == AUDIT_ABANDONED {
                    continue;
                }
                if state != AUDIT_TERMINAL {
                    return Err("registered worker audit slot is not terminal");
                }
                let record = slot
                    .publication
                    .terminal_record()?
                    .ok_or("terminal worker audit slot has no record")?;
                records.push(record);
            }
            Ok(records)
        }
    }
}
