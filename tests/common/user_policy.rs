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
                _cmd.arg("--user").arg("nobody");
            }
        }
    }
}
