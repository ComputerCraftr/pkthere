#![allow(dead_code)]

#[cfg(unix)]
use nix::unistd;

#[path = "runtime_asserts.rs"]
mod runtime_asserts;

use crate::app_bin::find_app_bin;
use crate::core::{
    ChildGuard, MAX_WAIT_SECS, TIMEOUT_SECS, take_child_stdout, wait_for_listen_addr_from,
};
#[allow(unused_imports)]
pub use runtime_asserts::{
    CLIENT_WAIT_MS, expect_no_echo, json_addr, send_until_locked, wait_for_locked_client_from,
    wait_for_stats_matching,
};

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::process::{ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub use crate::core::{IpFamily, bind_udp_client, random_unprivileged_port, spawn_udp_echo_server};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketMode {
    Connected,
    Unconnected,
}

pub const SOCKET_MODES: [SocketMode; 2] = [SocketMode::Connected, SocketMode::Unconnected];
pub const IPV4_ONLY_FAMILIES: [IpFamily; 1] = [IpFamily::V4];

#[derive(Clone, Copy, Debug)]
pub struct MatrixCase<'a> {
    pub family: IpFamily,
    pub proto: &'a str,
    pub mode: SocketMode,
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
}

pub struct ForwarderSession {
    pub child: ChildGuard,
    pub out: ChildStdout,
    pub listen_addr: SocketAddr,
}

impl IpFamily {
    pub fn bind_client(self) -> io::Result<UdpSocket> {
        bind_udp_client(self)
    }

    pub fn spawn_echo(self) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
        spawn_udp_echo_server(self)
    }

    pub const fn listen_arg(self) -> &'static str {
        match self {
            Self::V4 => "UDP:127.0.0.1:0",
            Self::V6 => "UDP:[::1]:0",
        }
    }

    pub const fn is_v6(self) -> bool {
        matches!(self, Self::V6)
    }
}

impl SocketMode {
    pub fn apply(self, cmd: &mut Command) {
        if matches!(self, Self::Unconnected) {
            cmd.arg("--debug").arg("no-connect");
        }
    }
}

pub fn run_matrix_cases<'a>(
    families: &'a [IpFamily],
    protos: &'a [&'a str],
    modes: &'a [SocketMode],
    mut run: impl FnMut(MatrixCase<'a>),
) {
    for &family in families {
        for &proto in protos {
            for &mode in modes {
                run(MatrixCase {
                    family,
                    proto,
                    mode,
                });
            }
        }
    }
}

pub fn bind_client_or_skip(family: IpFamily) -> Option<UdpSocket> {
    match family.bind_client() {
        Ok(sock) => Some(sock),
        Err(e) if family.is_v6() => {
            eprintln!("IPv6 loopback not available; skipping IPv6 test: {e}");
            None
        }
        Err(e) => panic!("IPv4 loopback not available: {e}"),
    }
}

pub fn spawn_echo_or_skip(family: IpFamily) -> Option<(SocketAddr, thread::JoinHandle<()>)> {
    match family.spawn_echo() {
        Ok(pair) => Some(pair),
        Err(e) if family.is_v6() => {
            eprintln!("IPv6 echo server could not bind; skipping IPv6 test: {e}");
            None
        }
        Err(e) => panic!("IPv4 echo server could not bind: {e}"),
    }
}

pub fn launch_forwarder(cfg: ForwarderConfig<'_>) -> ForwarderSession {
    try_launch_forwarder(cfg).expect("could not launch forwarder")
}

pub fn try_launch_forwarder(cfg: ForwarderConfig<'_>) -> io::Result<ForwarderSession> {
    let bin = find_app_bin().expect("could not find app binary");
    let mut cmd = Command::new(bin);
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
        .stderr(Stdio::inherit());

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
        cmd.arg("--debug").arg("fast-stats");
    }

    cfg.mode.apply(&mut cmd);

    #[cfg(unix)]
    if unistd::geteuid().is_root() {
        cmd.arg("--user").arg("nobody");
    }

    let mut child = ChildGuard::new(cmd.spawn()?);
    let mut out =
        take_child_stdout(&mut child).ok_or_else(|| io::Error::other("child stdout missing"))?;
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
        listen_addr,
    })
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
