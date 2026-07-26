use std::time::Duration;

pub(super) trait WaitReacquireBackend<Guard> {
    type Error;

    fn release_for_wait(&mut self) -> Result<(), Self::Error>;
    fn wait_timeout(
        &mut self,
        guard: Guard,
        timeout: Duration,
    ) -> Result<(Guard, bool), Self::Error>;
    fn reacquire_after_wait(&mut self) -> Result<(), Self::Error>;
}

/// Production wait lifecycle shared by the standard and Loom backends.
///
/// The retained authority is removed before the blocking scope and restored
/// only after the mutex guard has been reacquired. Any error returns without
/// restoring the authority, so the raw guard is dropped exactly once.
pub(super) fn wait_reacquire<Backend, Guard>(
    mut backend: Backend,
    guard: Guard,
    timeout: Duration,
) -> Result<(Backend, Guard, bool), Backend::Error>
where
    Backend: WaitReacquireBackend<Guard>,
{
    backend.release_for_wait()?;
    let (guard, timed_out) = backend.wait_timeout(guard, timeout)?;
    backend.reacquire_after_wait()?;
    Ok((backend, guard, timed_out))
}
