use crate::atomic_core::AtomicU8Authority;

pub(crate) const AUDIT_UNCLAIMED: u8 = 0;
pub(crate) const AUDIT_REGISTERED: u8 = 1;
pub(crate) const AUDIT_RUNNING: u8 = 2;
pub(crate) const AUDIT_TERMINAL: u8 = 3;
pub(crate) const AUDIT_ABANDONED: u8 = 4;

pub(crate) trait AuditSlotPayload<Identity: Copy + Eq, Record: Copy> {
    fn install_identity(&self, identity: Identity) -> Result<(), &'static str>;
    fn clear_identity(&self);
    fn identity_matches(&self, identity: Identity) -> Result<bool, &'static str>;
    fn install_record(&self, record: Record) -> Result<(), &'static str>;
    fn terminal_record(&self) -> Result<Option<Record>, &'static str>;
}

pub(crate) struct AuditSlotPublicationCore<State, Payload, Identity, Record> {
    state: State,
    payload: Payload,
    _types: std::marker::PhantomData<fn(Identity) -> Record>,
}

impl<State, Payload, Identity, Record> AuditSlotPublicationCore<State, Payload, Identity, Record>
where
    State: AtomicU8Authority,
    Payload: AuditSlotPayload<Identity, Record>,
    Identity: Copy + Eq,
    Record: Copy,
{
    pub(crate) const fn new(state: State, payload: Payload) -> Self {
        Self {
            state,
            payload,
            _types: std::marker::PhantomData,
        }
    }

    pub(crate) fn register(&self, identity: Identity) -> Result<(), &'static str> {
        self.payload.install_identity(identity)?;
        if self
            .state
            .compare_release(AUDIT_UNCLAIMED, AUDIT_REGISTERED)
            .is_err()
        {
            self.payload.clear_identity();
            return Err("worker audit slot was registered twice");
        }
        Ok(())
    }

    pub(crate) fn begin(&self, identity: Identity) -> Result<(), &'static str> {
        if !self.payload.identity_matches(identity)? {
            return Err("worker audit identity changed before execution");
        }
        self.state
            .compare_acqrel(AUDIT_REGISTERED, AUDIT_RUNNING)
            .map(|_| ())
            .map_err(|_| "worker audit slot did not enter running state")
    }

    pub(crate) fn seal(&self, record: Record) -> Result<(), &'static str> {
        if self.state.load_acquire() != AUDIT_RUNNING {
            return Err("worker audit slot was not running at seal");
        }
        self.payload.install_record(record)?;
        self.state
            .compare_release(AUDIT_RUNNING, AUDIT_TERMINAL)
            .map(|_| ())
            .map_err(|_| "worker audit terminal publication lost ownership")
    }

    pub(crate) fn abandon(&self) {
        let _result = self
            .state
            .compare_release(AUDIT_REGISTERED, AUDIT_ABANDONED);
    }

    pub(crate) fn state(&self) -> u8 {
        self.state.load_acquire()
    }

    pub(crate) fn terminal_record(&self) -> Result<Option<Record>, &'static str> {
        if self.state() != AUDIT_TERMINAL {
            return Ok(None);
        }
        self.payload.terminal_record()
    }
}
