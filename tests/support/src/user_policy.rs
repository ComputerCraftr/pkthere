use std::process::Command;

#[cfg(unix)]
use nix::unistd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub fn apply_root_user_args(_cmd: &mut Command) {
    #[cfg(unix)]
    {
        let mut will_run_as_root = unistd::geteuid().is_root();

        if !will_run_as_root && let Ok(meta) = std::fs::metadata(_cmd.get_program()) {
            will_run_as_root = meta.uid() == 0 && (meta.mode() & 0o4000) != 0;
        }

        if will_run_as_root {
            // If testing on a system with raw ICMP privileges (setuid root or sudo),
            // we must specify --user to drop privileges after binding, otherwise the
            // forwarder enforces a security check and aborts.
            // We only add it if the user hasn't already provided it (so we don't
            // interfere with tests specifically testing the --user flag).
            let has_user = _cmd.get_args().any(|arg| arg == "--user");
            if !has_user {
                _cmd.arg("--user").arg(privilege_drop_user());
            }
        }
    }
}

#[cfg(unix)]
fn privilege_drop_user() -> String {
    let real_uid = unistd::getuid();
    let invoking_uid = if real_uid.is_root() {
        std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|uid| *uid != 0)
            .map(unistd::Uid::from_raw)
    } else {
        Some(real_uid)
    };
    invoking_uid
        .and_then(|uid| unistd::User::from_uid(uid).ok().flatten())
        .map(|user| user.name)
        // A genuinely root-owned container has no less-privileged invoking
        // identity to restore. Keep its explicit fallback deterministic.
        .unwrap_or_else(|| "nobody".to_string())
}

#[cfg(all(test, unix))]
mod tests;
