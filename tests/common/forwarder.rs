use crate::app_bin::find_app_bin;
use crate::core::{ChildGuard, take_child_stdout, wait_for_listen_addr_from};
use crate::orchestrator::{MAX_WAIT_SECS, TIMEOUT_SECS};

use std::io::{self, Read};
use std::net::SocketAddr;
use std::process::{ChildStderr, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketMode {
    Connected,
    Unconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputCapture {
    Direct,
    Buffered,
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
    pub capture_mode: OutputCapture,
}

pub enum SessionStdout {
    Direct {
        stdout: ChildStdout,
        seen: Arc<Mutex<Vec<u8>>>,
    },
    Buffered,
}

impl Read for SessionStdout {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct { stdout, seen } => {
                let n = stdout.read(buf)?;
                if n > 0 {
                    seen.lock()
                        .expect("direct stdout capture lock")
                        .extend_from_slice(&buf[..n]);
                }
                Ok(n)
            }
            Self::Buffered => Err(io::Error::other(
                "buffered forwarder stdout is not readable directly; use captured output helpers",
            )),
        }
    }
}

struct CaptureHandle {
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stdout_thread: Option<JoinHandle<io::Result<()>>>,
    stderr_thread: Option<JoinHandle<io::Result<()>>>,
}

impl CaptureHandle {
    fn snapshot(&self) -> (String, String) {
        let stdout =
            String::from_utf8_lossy(&self.stdout.lock().expect("capture stdout lock")).into_owned();
        let stderr =
            String::from_utf8_lossy(&self.stderr.lock().expect("capture stderr lock")).into_owned();
        (stdout, stderr)
    }

    fn join(&mut self) -> io::Result<(String, String)> {
        if let Some(thread) = self.stdout_thread.take() {
            join_capture_thread(thread, "stdout")?;
        }
        if let Some(thread) = self.stderr_thread.take() {
            join_capture_thread(thread, "stderr")?;
        }
        Ok(self.snapshot())
    }
}

pub struct ForwarderSession {
    pub child: ChildGuard,
    pub out: SessionStdout,
    pub listen_addr: SocketAddr,
    direct_stdout: Option<Arc<Mutex<Vec<u8>>>>,
    capture: Option<CaptureHandle>,
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

    let (out, direct_stdout, capture) = match cfg.capture_mode {
        OutputCapture::Direct => {
            let seen = Arc::new(Mutex::new(Vec::new()));
            (
                SessionStdout::Direct {
                    stdout: out,
                    seen: Arc::clone(&seen),
                },
                Some(seen),
                None,
            )
        }
        OutputCapture::Buffered => (
            SessionStdout::Buffered,
            None,
            Some(spawn_capture_threads(out, err)),
        ),
    };

    Ok(ForwarderSession {
        child,
        out,
        listen_addr,
        direct_stdout,
        capture,
    })
}

pub fn collect_forwarder_output(session: &mut ForwarderSession) -> io::Result<(String, String)> {
    if let Some(capture) = session.capture.as_mut() {
        return capture.join();
    }

    let mut sink = String::new();
    session.out.read_to_string(&mut sink)?;
    snapshot_forwarder_output(session)
}

pub fn snapshot_forwarder_output(session: &ForwarderSession) -> io::Result<(String, String)> {
    match session.capture.as_ref() {
        Some(capture) => Ok(capture.snapshot()),
        None => match session.direct_stdout.as_ref() {
            Some(stdout) => Ok((
                String::from_utf8_lossy(&stdout.lock().expect("direct stdout capture lock"))
                    .into_owned(),
                String::new(),
            )),
            None => Err(io::Error::other(
                "forwarder session does not expose captured output",
            )),
        },
    }
}

pub fn snapshot_forwarder_output_tail(
    session: &ForwarderSession,
    max_lines: usize,
) -> io::Result<(String, String)> {
    let (stdout, stderr) = snapshot_forwarder_output(session)?;
    Ok((
        render_output_tail(&stdout, max_lines),
        render_output_tail(&stderr, max_lines),
    ))
}

pub fn terminate_forwarder(session: &mut ForwarderSession) {
    let _ = session.child.kill();
    let _ = session.child.wait();
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

fn spawn_capture_threads(out: ChildStdout, err: Option<ChildStderr>) -> CaptureHandle {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let stdout_thread = Some(spawn_capture_thread(out, Arc::clone(&stdout)));
    let stderr_thread = err.map(|err| spawn_capture_thread(err, Arc::clone(&stderr)));
    CaptureHandle {
        stdout,
        stderr,
        stdout_thread,
        stderr_thread,
    }
}

fn spawn_capture_thread<R: Read + Send + 'static>(
    mut reader: R,
    buffer: Arc<Mutex<Vec<u8>>>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(n) => buffer
                    .lock()
                    .expect("capture buffer lock")
                    .extend_from_slice(&chunk[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    })
}

fn join_capture_thread(thread: JoinHandle<io::Result<()>>, name: &str) -> io::Result<()> {
    match thread.join() {
        Ok(res) => res,
        Err(_) => Err(io::Error::other(format!("{name} capture thread panicked"))),
    }
}

fn render_output_tail(text: &str, max_lines: usize) -> String {
    let lines = text.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}
