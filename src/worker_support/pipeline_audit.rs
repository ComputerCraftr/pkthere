#[cfg(test)]
const TEST_BARRIER_TOKEN_SHIFT: u32 = 4;
#[cfg(test)]
const TEST_BARRIER_DIRECTION_BIT: u64 = 1 << 3;
#[cfg(test)]
const TEST_BARRIER_WAIT_SLICE: std::time::Duration = std::time::Duration::from_millis(2);
#[cfg(test)]
const TEST_PIPELINE_SUITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
static TEST_PIPELINE_SUITE_ACTIVE: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    std::sync::atomic::AtomicBool,
> = crate::authority::AuthorityAtomic::new_bool(
    false,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);

#[cfg(test)]
static NEXT_TEST_BARRIER_TOKEN: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    std::sync::atomic::AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    1,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);
#[cfg(test)]
static ARMED_TEST_BARRIER: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    std::sync::atomic::AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    0,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);
#[cfg(test)]
static ARRIVED_TEST_BARRIER: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    std::sync::atomic::AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    0,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);
#[cfg(test)]
static RELEASED_TEST_BARRIER: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    std::sync::atomic::AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    0,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PipelineStage {
    FlowLaneAcquired,
    SnapshotValidated,
    ReceiveCompleted,
    ReplayAdmitted,
    DestinationSocketAcquired,
    SequenceReserved,
    BeforeSend,
    AfterSend,
}

#[cfg(test)]
thread_local! {
    static TEST_PIPELINE_TOKEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn encoded_test_barrier(token: u64, c2u: bool, stage: PipelineStage) -> u64 {
    (token << TEST_BARRIER_TOKEN_SHIFT)
        | (u64::from(c2u) * TEST_BARRIER_DIRECTION_BIT)
        | stage as u64
}

#[cfg(test)]
fn pause_for_test_barrier(c2u: bool, stage: PipelineStage) {
    let token = TEST_PIPELINE_TOKEN.get();
    if token == 0 {
        return;
    }
    let encoded = encoded_test_barrier(token, c2u, stage);
    if ARMED_TEST_BARRIER.load(std::sync::atomic::Ordering::Acquire) != encoded {
        return;
    }
    ARRIVED_TEST_BARRIER.store(encoded, std::sync::atomic::Ordering::Release);
    while RELEASED_TEST_BARRIER.load(std::sync::atomic::Ordering::Acquire) != encoded {
        std::thread::park_timeout(TEST_BARRIER_WAIT_SLICE);
    }
}

#[cfg(test)]
pub(crate) struct TestPipelineThreadToken {
    previous: u64,
}

#[cfg(test)]
pub(crate) struct TestPipelineSuiteGuard;

#[cfg(test)]
impl TestPipelineSuiteGuard {
    pub(crate) fn acquire() -> Result<Self, &'static str> {
        let deadline = std::time::Instant::now() + TEST_PIPELINE_SUITE_TIMEOUT;
        loop {
            match TEST_PIPELINE_SUITE_ACTIVE.compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::park_timeout(TEST_BARRIER_WAIT_SLICE);
                }
                Err(_) => return Err("another pipeline audit test did not finish"),
            }
        }
    }
}

#[cfg(test)]
impl Drop for TestPipelineSuiteGuard {
    fn drop(&mut self) {
        TEST_PIPELINE_SUITE_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
impl TestPipelineThreadToken {
    pub(crate) fn install(token: u64) -> Self {
        let previous = TEST_PIPELINE_TOKEN.replace(token);
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for TestPipelineThreadToken {
    fn drop(&mut self) {
        TEST_PIPELINE_TOKEN.set(self.previous);
    }
}

#[cfg(test)]
pub(crate) struct TestPipelinePause {
    token: u64,
    encoded: u64,
    released: bool,
}

#[cfg(test)]
impl TestPipelinePause {
    pub(crate) fn arm(c2u: bool, stage: PipelineStage) -> Result<Self, &'static str> {
        let token = NEXT_TEST_BARRIER_TOKEN
            .try_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |token| token.checked_add(1),
            )
            .map_err(|_| "pipeline test barrier token exhausted")?;
        let encoded = encoded_test_barrier(token, c2u, stage);
        ARMED_TEST_BARRIER
            .compare_exchange(
                0,
                encoded,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| "one pipeline audit test armed overlapping barriers")?;
        ARRIVED_TEST_BARRIER.store(0, std::sync::atomic::Ordering::Release);
        RELEASED_TEST_BARRIER.store(0, std::sync::atomic::Ordering::Release);
        Ok(Self {
            token,
            encoded,
            released: false,
        })
    }

    pub(crate) const fn token(&self) -> u64 {
        self.token
    }

    pub(crate) fn wait_until_arrived(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if ARRIVED_TEST_BARRIER.load(std::sync::atomic::Ordering::Acquire) == self.encoded {
                return true;
            }
            std::thread::park_timeout(TEST_BARRIER_WAIT_SLICE);
        }
        false
    }

    pub(crate) fn release(&mut self) {
        if self.released {
            return;
        }
        RELEASED_TEST_BARRIER.store(self.encoded, std::sync::atomic::Ordering::Release);
        if ARMED_TEST_BARRIER
            .compare_exchange(
                self.encoded,
                0,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
            && !std::thread::panicking()
        {
            panic!("pipeline test barrier ownership changed before release");
        }
        self.released = true;
    }
}

#[cfg(test)]
impl Drop for TestPipelinePause {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(any(test, feature = "authority-audit"))]
#[inline]
pub(crate) fn checkpoint(c2u: bool, stage: PipelineStage) {
    crate::authority::record_pipeline_stage(c2u, stage as usize);
    let operation = crate::authority::AuditedOperationScope::enter(
        crate::authority::OperationId::PipelineBarrier,
    )
    .unwrap_or_else(|error| {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "pipeline audit stage {stage:?} rejected its held authorities: {error}"
        ))
    });
    #[cfg(test)]
    pause_for_test_barrier(c2u, stage);
    drop(operation);
}

#[cfg(not(any(test, feature = "authority-audit")))]
#[inline]
pub(crate) const fn checkpoint(_: bool, _: PipelineStage) {}
