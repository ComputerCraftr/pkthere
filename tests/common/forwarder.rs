use crate::app_bin::find_app_bin;
use crate::core::{ChildGuard, take_child_stdout, wait_for_listen_addr_from};
use crate::orchestrator::{MAX_WAIT_SECS, TIMEOUT_SECS};

use std::io::{self, Read};
use std::net::SocketAddr;
use std::process::{ChildStderr, ChildStdout, Command, Stdio};
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
    pub timeout_secs: Option<u64>,
    pub max_payload: Option<usize>,
    pub fast_stats: bool,
    pub stats_interval_mins: Option<u32>,
    pub icmp_sync_pps: Option<u32>,
    pub debug_logs: &'a [&'a str],
    pub capture_stderr: bool,
}

pub struct ForwarderSession {
    pub child: ChildGuard,
    pub out: ChildStdout,
    pub err: Option<ChildStderr>,
    pub listen_addr: SocketAddr,
}

impl SocketMode {
    pub fn apply(self, cmd: &mut Command) {
        if matches!(self, Self::Unconnected) {
            cmd.arg("--debug-no-connect");
        }
    }
}

pub fn launch_forwarder(cfg: ForwarderConfig<'_>) -> ForwarderSession {
    try_launch_forwarder(cfg).expect("could not launch forwarder")
}

pub fn try_launch_forwarder(cfg: ForwarderConfig<'_>) -> io::Result<ForwarderSession> {
    let bin = find_app_bin().expect("could not find app binary");
    let mut cmd = Command::new(&bin);
    cmd.arg("--here")
        .arg(&cfg.here)
        .arg("--there")
        .arg(&cfg.there)
        .arg("--timeout-secs")
        .arg(
            cfg.timeout_secs
                .unwrap_or(TIMEOUT_SECS.as_secs())
                .to_string(),
        )
        .arg("--on-timeout")
        .arg(cfg.timeout_action)
        .stdout(Stdio::piped())
        .stderr(if cfg.capture_stderr {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });

    if let Some(max_payload) = cfg.max_payload {
        cmd.arg("--max-payload").arg(max_payload.to_string());
    }
    if let Some(stats_interval_mins) = cfg.stats_interval_mins {
        cmd.arg("--stats-interval-mins")
            .arg(stats_interval_mins.to_string());
    }
    if let Some(icmp_sync_pps) = cfg.icmp_sync_pps {
        cmd.arg("--icmp-sync-pps").arg(icmp_sync_pps.to_string());
    }
    if cfg.fast_stats {
        cmd.arg("--debug-fast-stats");
    }
    for debug_log in cfg.debug_logs {
        cmd.arg("--debug-log").arg(debug_log);
    }

    cfg.mode.apply(&mut cmd);

    crate::orchestrator::user_policy::apply_root_user_args(&mut cmd);

    let mut child = ChildGuard::new(cmd.spawn()?);
    let mut out =
        take_child_stdout(&mut child).ok_or_else(|| io::Error::other("child stdout missing"))?;
    let err = child.stderr.take();
    let Some(listen_addr) = wait_for_listen_addr_from(&mut out, MAX_WAIT_SECS) else {
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "forwarder exited before listen with status {status}"
            )));
        }
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "did not see listening address line within {:?}",
                MAX_WAIT_SECS
            ),
        ));
    };

    Ok(ForwarderSession {
        child,
        out,
        err,
        listen_addr,
    })
}

pub fn collect_forwarder_output(session: &mut ForwarderSession) -> io::Result<(String, String)> {
    let mut stdout = String::new();
    session.out.read_to_string(&mut stdout)?;

    let mut stderr = String::new();
    if let Some(err) = session.err.as_mut() {
        err.read_to_string(&mut stderr)?;
    }

    Ok((stdout, stderr))
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
