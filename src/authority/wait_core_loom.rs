#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::wait_core::{WaitReacquireBackend, wait_reacquire};
use loom::sync::mpsc;
use loom::sync::{Arc, Condvar, Mutex, MutexGuard};
use loom::thread;
use std::time::Duration;

struct LoomWaitBackend<'a> {
    condition: &'a Condvar,
    released: bool,
    reacquired: bool,
}

impl<'a, T> WaitReacquireBackend<MutexGuard<'a, T>> for LoomWaitBackend<'a> {
    type Error = ();

    fn release_for_wait(&mut self) -> Result<(), Self::Error> {
        if self.released || self.reacquired {
            return Err(());
        }
        self.released = true;
        Ok(())
    }

    fn wait_timeout(
        &mut self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
    ) -> Result<(MutexGuard<'a, T>, bool), Self::Error> {
        let (guard, timeout) = self
            .condition
            .wait_timeout(guard, timeout)
            .map_err(|_| ())?;
        Ok((guard, timeout.timed_out()))
    }

    fn reacquire_after_wait(&mut self) -> Result<(), Self::Error> {
        if !self.released || self.reacquired {
            return Err(());
        }
        self.reacquired = true;
        Ok(())
    }
}

#[test]
fn production_wait_core_releases_waits_reacquires_and_rechecks_shutdown() {
    loom::model(|| {
        let state = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let (waiting, wait_until_waiting) = mpsc::channel();
        let waiter_state = Arc::clone(&state);
        let waiter = thread::spawn(move || {
            let (mutex, condition) = &*waiter_state;
            let mut state = mutex.lock().expect("wait predicate lock");
            let mut wake_count = 0_u8;
            while !state.0 && !state.1 {
                waiting.send(()).expect("announce production wait");
                let backend = LoomWaitBackend {
                    condition,
                    released: false,
                    reacquired: false,
                };
                let waited = wait_reacquire(backend, state, Duration::from_secs(1))
                    .expect("production wait lifecycle");
                let (backend, returned_state, _) = waited;
                state = returned_state;
                wake_count = wake_count.checked_add(1).expect("bounded model wakes");
                assert!(backend.released && backend.reacquired);
            }
            (state.0, state.1, wake_count)
        });

        let notifier_state = Arc::clone(&state);
        let notifier = thread::spawn(move || {
            wait_until_waiting
                .recv()
                .expect("waiter entered predicate loop");
            let (mutex, condition) = &*notifier_state;
            condition.notify_all();
            let mut state = mutex.lock().expect("publish shutdown predicate");
            state.1 = true;
            condition.notify_all();
        });

        notifier.join().expect("notifier actor");
        let (ready, shutdown, wake_count) = waiter.join().expect("waiter actor");
        assert!(ready || shutdown);
        assert!(wake_count >= 1);
    });
}

struct FailingWaitBackend {
    released: bool,
    reacquired: Arc<loom::sync::atomic::AtomicBool>,
}

impl WaitReacquireBackend<()> for FailingWaitBackend {
    type Error = &'static str;

    fn release_for_wait(&mut self) -> Result<(), Self::Error> {
        self.released = true;
        Ok(())
    }

    fn wait_timeout(&mut self, _guard: (), _timeout: Duration) -> Result<((), bool), Self::Error> {
        Err("poisoned")
    }

    fn reacquire_after_wait(&mut self) -> Result<(), Self::Error> {
        self.reacquired
            .store(true, loom::sync::atomic::Ordering::Release);
        Ok(())
    }
}

#[test]
fn production_wait_core_never_restores_authority_after_poison() {
    loom::model(|| {
        let reacquired = Arc::new(loom::sync::atomic::AtomicBool::new(false));
        let backend = FailingWaitBackend {
            released: false,
            reacquired: Arc::clone(&reacquired),
        };
        let result = wait_reacquire(backend, (), Duration::from_millis(1));
        assert!(matches!(result, Err("poisoned")));
        assert!(!reacquired.load(loom::sync::atomic::Ordering::Acquire));
    });
}

struct TimeoutWaitBackend {
    releases: u8,
    waits: u8,
    reacquires: u8,
}

impl WaitReacquireBackend<()> for TimeoutWaitBackend {
    type Error = ();

    fn release_for_wait(&mut self) -> Result<(), Self::Error> {
        self.releases = self.releases.checked_add(1).ok_or(())?;
        Ok(())
    }

    fn wait_timeout(&mut self, _guard: (), timeout: Duration) -> Result<((), bool), Self::Error> {
        if timeout != Duration::ZERO {
            return Err(());
        }
        self.waits = self.waits.checked_add(1).ok_or(())?;
        Ok(((), true))
    }

    fn reacquire_after_wait(&mut self) -> Result<(), Self::Error> {
        self.reacquires = self.reacquires.checked_add(1).ok_or(())?;
        Ok(())
    }
}

#[test]
fn production_wait_core_propagates_timeout_and_reacquires_once() {
    loom::model(|| {
        let backend = TimeoutWaitBackend {
            releases: 0,
            waits: 0,
            reacquires: 0,
        };
        let (backend, guard, timed_out) =
            wait_reacquire(backend, (), Duration::ZERO).expect("timeout lifecycle");
        assert_eq!((guard, timed_out), ((), true));
        assert_eq!(
            (backend.releases, backend.waits, backend.reacquires),
            (1, 1, 1)
        );
    });
}
