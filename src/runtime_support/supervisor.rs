use super::{
    RUNTIME_WAIT_FALLBACK, RuntimeFailure, ShutdownController, SupervisedThread, SupervisorEvent,
    ThreadOutcome, ThreadRole, ThreadSupervisor, panic_report,
};
use crossbeam_channel::RecvTimeoutError;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

impl ThreadSupervisor {
    pub(crate) fn new(
        shutdown: Arc<ShutdownController>,
        events: super::SupervisorEventReceiver,
    ) -> Self {
        Self {
            shutdown,
            events: events.0.transfer(),
            threads: Vec::new(),
            // Slot zero belongs to the main/supervisor control path.
            next_slot: 1,
        }
    }

    pub(crate) fn spawn(
        &mut self,
        role: ThreadRole,
        name: String,
        run: impl FnOnce() -> Result<(), RuntimeFailure> + Send + 'static,
    ) -> io::Result<()> {
        self.spawn_with_cleanup(role, name, None, (), move |()| run(), |()| {})
    }

    pub(crate) fn spawn_forwarder_with_stats(
        &mut self,
        role: ThreadRole,
        name: String,
        audit_identity: crate::authority::WorkerAuditIdentity,
        recorder: crate::stats::StatsRecorder,
        run: impl FnOnce(&mut crate::stats::StatsRecorder) -> Result<(), RuntimeFailure>
        + Send
        + 'static,
    ) -> io::Result<()> {
        let valid_role = matches!(
            (role, audit_identity.direction),
            (
                ThreadRole::ClientWorker,
                crate::authority::AuditDirection::ClientToUpstream
            ) | (
                ThreadRole::UpstreamWorker,
                crate::authority::AuditDirection::UpstreamToClient
            )
        );
        if !valid_role {
            return Err(io::Error::other(
                "forwarding worker role and audit direction disagree",
            ));
        }
        self.spawn_with_cleanup(
            role,
            name,
            Some(audit_identity),
            Some(recorder),
            move |recorder| {
                let recorder = recorder.as_mut().ok_or_else(|| {
                    RuntimeFailure::fatal(format_args!(
                        "{role:?} stats recorder was consumed before execution"
                    ))
                })?;
                run(recorder)
            },
            |recorder| {
                if let Some(recorder) = recorder.take() {
                    let generation = recorder.begin_final_flush();
                    match recorder.seal_until(
                        generation,
                        Instant::now() + crate::stats::STATS_FINAL_FLUSH_DEADLINE,
                    ) {
                        crate::stats::ProducerSealResult::Sealed => {}
                        crate::stats::ProducerSealResult::DeadlineExceeded
                        | crate::stats::ProducerSealResult::Failed => {}
                    }
                }
            },
        )
    }

    fn spawn_with_cleanup<Resource>(
        &mut self,
        role: ThreadRole,
        name: String,
        audit_identity: Option<crate::authority::WorkerAuditIdentity>,
        mut resource: Resource,
        run: impl FnOnce(&mut Resource) -> Result<(), RuntimeFailure> + Send + 'static,
        cleanup: impl FnOnce(&mut Resource) + Send + 'static,
    ) -> io::Result<()>
    where
        Resource: Send + 'static,
    {
        let slot = self.next_slot;
        let Some(next_slot) = self.next_slot.checked_add(1) else {
            let error = io::Error::other("supervised thread slot exhausted");
            self.shutdown
                .request_current_fatal(RuntimeFailure::fatal(format_args!(
                    "could not allocate {role:?} supervision slot: {error}"
                )));
            return Err(error);
        };
        self.next_slot = next_slot;
        if !self.shutdown.has_worker_slot(slot) {
            let error = io::Error::other("supervised thread capacity exhausted");
            self.shutdown
                .request_current_fatal(RuntimeFailure::fatal(format_args!(
                    "could not allocate {role:?} supervision outcome: {error}"
                )));
            return Err(error);
        }
        if let Some(identity) = audit_identity
            && let Err(error) = self.shutdown.audit_workers.register(slot, identity)
        {
            let error = io::Error::other(error);
            self.shutdown
                .request_current_fatal(RuntimeFailure::fatal(format_args!(
                    "could not register {role:?} worker audit slot: {error}"
                )));
            return Err(error);
        }
        let shutdown = Arc::clone(&self.shutdown);
        let thread_shutdown = Arc::clone(&shutdown);
        let handle = thread::Builder::new().name(name).spawn(move || {
            let begin_error = audit_identity
                .and_then(|identity| thread_shutdown.audit_workers.begin(slot, identity).err());
            let mut outcome = if let Some(error) = begin_error {
                ThreadOutcome::Failed(RuntimeFailure::fatal(format_args!(
                    "{role:?} worker audit startup failed: {error}"
                )))
            } else {
                match catch_unwind(AssertUnwindSafe(|| run(&mut resource))) {
                    Ok(Ok(())) => ThreadOutcome::Completed,
                    Ok(Err(error)) => ThreadOutcome::Failed(error),
                    Err(payload) => ThreadOutcome::Panicked(panic_report(payload.as_ref())),
                }
            };
            if audit_identity.is_some()
                && begin_error.is_none()
                && let Err(error) = thread_shutdown.audit_workers.seal(slot)
            {
                outcome = ThreadOutcome::Failed(RuntimeFailure::fatal(format_args!(
                    "{role:?} worker audit publication failed: {error}"
                )));
            };
            let terminal = thread_shutdown.begin_worker_termination(slot, role, outcome);
            terminal.complete(&mut resource, cleanup);
        });
        match handle {
            Ok(handle) => {
                self.threads.push(SupervisedThread {
                    slot,
                    role,
                    handle: Some(handle),
                });
                Ok(())
            }
            Err(error) => {
                if audit_identity.is_some() {
                    shutdown.audit_workers.abandon(slot);
                }
                shutdown.request_fatal(RuntimeFailure::fatal(format_args!(
                    "could not spawn {role:?}: {error}"
                )));
                Err(error)
            }
        }
    }

    pub(crate) fn finish(mut self, deadline: Instant) -> bool {
        while Instant::now() < deadline {
            let emergency_code = crate::authority::emergency_failure_code();
            if emergency_code != 0 && !self.shutdown.is_requested() {
                self.shutdown
                    .request_current_fatal(RuntimeFailure::fatal(format_args!(
                        "{}",
                        crate::authority::emergency_failure_report(emergency_code)
                    )));
            }
            let mut all_completed = true;
            for thread in &mut self.threads {
                if thread.handle.is_none() {
                    continue;
                }
                if self.shutdown.terminal_outcome(thread.slot).is_some()
                    && thread.handle.as_ref().is_some_and(JoinHandle::is_finished)
                {
                    if let Some(handle) = thread.handle.take() {
                        let _operation = crate::authority::audited_operation(
                            crate::authority::OperationId::ThreadJoin,
                        );
                        if handle.join().is_err() {
                            self.shutdown
                                .request_fatal(RuntimeFailure::fatal(format_args!(
                                    "{:?} panicked after publishing completion",
                                    thread.role
                                )));
                        }
                    }
                } else {
                    all_completed = false;
                }
            }
            if all_completed {
                #[cfg(any(test, feature = "authority-audit"))]
                match self.shutdown.audit_worker_records() {
                    Ok(records) => {
                        emit_worker_audit_records(&records);
                        if let Some((identity, error)) = records.iter().find_map(|record| {
                            record
                                .validate()
                                .err()
                                .map(|error| (record.identity, error))
                        }) {
                            eprintln!(
                                "worker audit aggregation failed for worker={} direction={:?}: {error}",
                                identity.worker, identity.direction
                            );
                            self.shutdown.request_current_fatal(RuntimeFailure::fatal(
                                format_args!(
                                    "worker audit aggregation failed for worker={} direction={:?}: {error}",
                                    identity.worker, identity.direction
                                ),
                            ));
                            return false;
                        }
                    }
                    Err(error) => {
                        eprintln!("worker audit aggregation failed: {error}");
                        self.shutdown
                            .request_current_fatal(RuntimeFailure::fatal(format_args!(
                                "worker audit aggregation failed: {error}"
                            )));
                        return false;
                    }
                }
                return true;
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO)
                .min(RUNTIME_WAIT_FALLBACK);
            let event = self.events.recv_timeout(remaining);
            match event {
                Ok(SupervisorEvent::ShutdownChanged) => {
                    self.shutdown
                        .shutdown_event_pending
                        .store(false, Ordering::Release);
                }
                Ok(SupervisorEvent::ThreadTerminal(_)) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    // Atomic outcome slots remain authoritative.
                }
            }
        }
        for thread in &self.threads {
            if thread.handle.is_some() {
                eprintln!(
                    "supervised {:?} thread did not stop before shutdown deadline",
                    thread.role
                );
            }
        }
        false
    }
}

#[cfg(feature = "authority-audit")]
fn emit_worker_audit_records(records: &[crate::authority::AuditThreadRecord]) {
    for record in records {
        eprintln!(
            "authority-worker-evidence worker={} direction={:?} receive={} send={} completed={} allocations={} allocation_authority_mask=0x{:x} payload_copies={} endpoint_normalizations={} forbidden_authorities={} forbidden_rmws={} refcount_rmws={} violation={}",
            record.identity.worker,
            record.identity.direction,
            record.receive_stage_count(),
            record.send_stage_count(),
            record.completed_packet_count(),
            record.allocations,
            record.allocation_authority_mask(),
            record.payload_copies,
            record.endpoint_normalizations,
            record.forbidden_authority_acquisition_count(),
            record.forbidden_shared_rmw_count(),
            record.refcount_operation_count(),
            record.violation_code,
        );
    }
}

#[cfg(all(test, not(feature = "authority-audit")))]
fn emit_worker_audit_records(records: &[crate::authority::AuditThreadRecord]) {
    let _records = records;
}
