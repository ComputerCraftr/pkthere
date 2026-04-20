#[cfg(unix)]
use nix::unistd;

use crate::app_bin::find_app_bin;
use crate::core::{
    ChildGuard, MAX_WAIT_SECS, TIMEOUT_SECS, take_child_stdout, wait_for_listen_addr_from,
};

use std::net::SocketAddr;
use std::process::{ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketMode {
    Connected,
    Unconnected,
}

pub struct ForwarderConfig<'a> {
    pub mode: SocketMode,
    pub here: String,
    pub there: String,
    pub timeout_action: &'a str,
    pub max_payload: Option<usize>,
    pub fast_stats: bool,
    pub stats_interval_mins: Option<u32>,
}

pub struct ForwarderSession {
    pub child: ChildGuard,
    pub out: ChildStdout,
    pub listen_addr: SocketAddr,
}

impl SocketMode {
    pub fn apply(self, cmd: &mut Command) {
        if matches!(self, Self::Unconnected) {
            cmd.arg("--debug").arg("no-connect");
        }
    }
}

pub fn launch_forwarder(cfg: ForwarderConfig<'_>) -> ForwarderSession {
    let bin = find_app_bin().expect("could not find app binary");
    let mut cmd = Command::new(bin);
    cmd.arg("--here")
        .arg(&cfg.here)
        .arg("--there")
        .arg(&cfg.there)
        .arg("--timeout-secs")
        .arg(TIMEOUT_SECS.as_secs().to_string())
        .arg("--on-timeout")
        .arg(cfg.timeout_action)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if let Some(max_payload) = cfg.max_payload {
        cmd.arg("--max-payload").arg(max_payload.to_string());
    }
    if let Some(stats_interval_mins) = cfg.stats_interval_mins {
        cmd.arg("--stats-interval-mins")
            .arg(stats_interval_mins.to_string());
    }
    if cfg.fast_stats {
        cmd.arg("--debug").arg("fast-stats");
    }

    cfg.mode.apply(&mut cmd);

    #[cfg(unix)]
    if unistd::geteuid().is_root() {
        cmd.arg("--user").arg("nobody");
    }

    let mut child = ChildGuard::new(cmd.spawn().expect("spawn app binary"));
    let mut out = take_child_stdout(&mut child).expect("child stdout missing");
    let listen_addr = wait_for_listen_addr_from(&mut out, MAX_WAIT_SECS).expect(&format!(
        "did not see listening address line within {:?}",
        MAX_WAIT_SECS
    ));

    ForwarderSession {
        child,
        out,
        listen_addr,
    }
}

pub fn wait_for_child_exit_success(child: &mut ChildGuard, max_wait: Duration) {
    let start = Instant::now();
    while start.elapsed() < max_wait {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "forwarder did not exit cleanly: {status}");
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("wait error: {e}"),
        }
    }

    let status_opt = child
        .try_wait()
        .expect("wait error while checking forwarder exit status");
    match status_opt {
        Some(status) => assert!(status.success(), "forwarder did not exit cleanly: {status}"),
        None => panic!("forwarder did not exit within {:?}", max_wait),
    }
}
