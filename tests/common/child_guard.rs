use std::ops::{Deref, DerefMut};
use std::process::Child;

/// Ensures the spawned child is terminated on drop (e.g., when a test panics).
pub struct ChildGuard(Child);

impl ChildGuard {
    pub const fn new(child: Child) -> Self {
        Self(child)
    }
}

impl Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // If it's still running (or we can't tell), try to kill and wait.
        match self.0.try_wait() {
            Ok(Some(_status)) => {
                // already exited
            }
            Ok(None) | Err(_) => {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
}
