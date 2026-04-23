//! Bounded child-process ownership and concurrent output capture for tests.

mod capture;

use capture::{CaptureBuffer, StreamKind, spawn_capture};
pub use capture::{CapturedOutput, OutputCursor};

use crate::timing::{
    CAPTURE_DRAIN_WAIT, CHILD_FORCED_REAP_WAIT, CHILD_TERMINATION_GRACE, TEST_POLL_INTERVAL,
};

use std::fmt;
use std::io;
#[cfg(unix)]
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessExit {
    pub success: bool,
    pub code: Option<i32>,
    #[cfg(unix)]
    pub signal: Option<i32>,
}

impl ProcessExit {
    fn from_status(status: ExitStatus) -> Self {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;

        Self {
            success: status.success(),
            code: status.code(),
            #[cfg(unix)]
            signal: status.signal(),
        }
    }
}

impl fmt::Display for ProcessExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(unix)]
        if let Some(signal) = self.signal {
            return write!(formatter, "signal {signal}");
        }
        match self.code {
            Some(code) => write!(formatter, "exit code {code}"),
            None => formatter.write_str("abnormal platform exit"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedChild {
    pub exit: ProcessExit,
    pub output: CapturedOutput,
}

#[derive(Debug)]
pub enum ChildHarnessError {
    Spawn {
        context: String,
        source: io::Error,
    },
    Wait {
        context: String,
        source: io::Error,
    },
    DeadlineExpired {
        context: String,
        output: CapturedOutput,
    },
    UnexpectedExit {
        context: String,
        exit: ProcessExit,
        output: CapturedOutput,
    },
    TerminationFailed {
        context: String,
        detail: String,
        output: CapturedOutput,
    },
    CaptureIncomplete {
        context: String,
        output: CapturedOutput,
    },
}

impl ChildHarnessError {
    pub fn output(&self) -> Option<&CapturedOutput> {
        match self {
            Self::Spawn { .. } | Self::Wait { .. } => None,
            Self::DeadlineExpired { output, .. }
            | Self::UnexpectedExit { output, .. }
            | Self::TerminationFailed { output, .. }
            | Self::CaptureIncomplete { output, .. } => Some(output),
        }
    }
}

impl fmt::Display for ChildHarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { context, source } => write!(formatter, "spawn {context}: {source}"),
            Self::Wait { context, source } => write!(formatter, "wait for {context}: {source}"),
            Self::DeadlineExpired { context, .. } => {
                write!(formatter, "deadline expired while waiting for {context}")
            }
            Self::UnexpectedExit { context, exit, .. } => {
                write!(
                    formatter,
                    "{context} exited before the expected event ({exit})"
                )
            }
            Self::TerminationFailed {
                context, detail, ..
            } => write!(formatter, "could not terminate {context}: {detail}"),
            Self::CaptureIncomplete { context, .. } => {
                write!(
                    formatter,
                    "output capture for {context} did not close by its deadline"
                )
            }
        }
    }
}

impl std::error::Error for ChildHarnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } | Self::Wait { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChildIdentity {
    pub context: String,
}

impl ChildIdentity {
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ChildLimits {
    pub poll_interval: Duration,
    pub termination_grace: Duration,
    pub forced_reap_wait: Duration,
    pub capture_drain_wait: Duration,
}

impl Default for ChildLimits {
    fn default() -> Self {
        Self {
            poll_interval: TEST_POLL_INTERVAL,
            termination_grace: CHILD_TERMINATION_GRACE,
            forced_reap_wait: CHILD_FORCED_REAP_WAIT,
            capture_drain_wait: CAPTURE_DRAIN_WAIT,
        }
    }
}

pub struct ManagedChild {
    child: Option<Child>,
    identity: ChildIdentity,
    limits: ChildLimits,
    capture: CaptureBuffer,
    capture_threads: Vec<thread::JoinHandle<()>>,
    exit: Option<ProcessExit>,
    process_tree: Option<ProcessTree>,
}

// The error deliberately owns complete diagnostic output so a failed lifecycle
// operation remains self-contained after the process owner is consumed.
#[allow(clippy::result_large_err)]
impl ManagedChild {
    pub fn spawn(
        command: &mut Command,
        identity: ChildIdentity,
        limits: ChildLimits,
    ) -> Result<Self, ChildHarnessError> {
        // Process creation is serialized only for the short spawn/containment window. This
        // prevents concurrently-created children from inheriting another child's transient
        // pipe or containment handles on platforms where inheritance setup is process-global.
        static CHILD_SPAWN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _spawn_guard = CHILD_SPAWN_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        configure_process_tree(command);
        let mut child = command.spawn().map_err(|source| ChildHarnessError::Spawn {
            context: identity.context.clone(),
            source,
        })?;
        let process_tree = match ProcessTree::new(&mut child) {
            Ok(process_tree) => process_tree,
            Err(source) => {
                abandon_spawned_child(
                    child,
                    None,
                    format!("{} after containment failure", identity.context),
                );
                return Err(ChildHarnessError::Spawn {
                    context: format!("{} process-tree containment", identity.context),
                    source,
                });
            }
        };
        let Some(stdout) = child.stdout.take() else {
            abandon_spawned_child(
                child,
                Some(process_tree),
                format!("{} after missing stdout pipe", identity.context),
            );
            return Err(ChildHarnessError::Spawn {
                context: identity.context.clone(),
                source: io::Error::other("managed child stdout pipe missing"),
            });
        };
        let Some(stderr) = child.stderr.take() else {
            abandon_spawned_child(
                child,
                Some(process_tree),
                format!("{} after missing stderr pipe", identity.context),
            );
            return Err(ChildHarnessError::Spawn {
                context: identity.context.clone(),
                source: io::Error::other("managed child stderr pipe missing"),
            });
        };
        let capture = CaptureBuffer::default();
        let stdout_capture = match spawn_capture(stdout, StreamKind::Stdout, capture.clone()) {
            Ok(thread) => thread,
            Err(source) => {
                abandon_spawned_child(
                    child,
                    Some(process_tree),
                    format!("{} after stdout capture failure", identity.context),
                );
                return Err(ChildHarnessError::Spawn {
                    context: format!("{} stdout capture", identity.context),
                    source,
                });
            }
        };
        let stderr_capture = match spawn_capture(stderr, StreamKind::Stderr, capture.clone()) {
            Ok(thread) => thread,
            Err(source) => {
                abandon_spawned_child(
                    child,
                    Some(process_tree),
                    format!("{} after stderr capture failure", identity.context),
                );
                drop(stdout_capture);
                return Err(ChildHarnessError::Spawn {
                    context: format!("{} stderr capture", identity.context),
                    source,
                });
            }
        };
        Ok(Self {
            child: Some(child),
            identity,
            limits,
            capture,
            capture_threads: vec![stdout_capture, stderr_capture],
            exit: None,
            process_tree: Some(process_tree),
        })
    }

    pub fn output_cursor(&self) -> OutputCursor {
        OutputCursor::default()
    }

    pub fn output_cursor_at_end(&self) -> OutputCursor {
        OutputCursor {
            stdout_offset: self.capture.snapshot().stdout.len(),
            partial_line: Vec::new(),
        }
    }

    pub fn output_snapshot(&self) -> CapturedOutput {
        self.capture.snapshot()
    }

    pub fn output_generation(&self) -> u64 {
        self.capture.generation()
    }

    pub fn try_status(&mut self) -> Result<Option<ProcessExit>, ChildHarnessError> {
        if let Some(exit) = &self.exit {
            return Ok(Some(exit.clone()));
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(self.exit.clone());
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                let exit = ProcessExit::from_status(status);
                self.exit = Some(exit.clone());
                self.child.take();
                Ok(Some(exit))
            }
            Ok(None) => Ok(None),
            Err(source) => Err(ChildHarnessError::Wait {
                context: self.identity.context.clone(),
                source,
            }),
        }
    }

    pub fn wait_for_line<T>(
        &mut self,
        cursor: &mut OutputCursor,
        deadline: Instant,
        event: &str,
        mut parser: impl FnMut(&str) -> Option<T>,
    ) -> Result<T, ChildHarnessError> {
        let mut observed_exit: Option<(ProcessExit, Instant)> = None;
        loop {
            let snapshot = self.capture.snapshot();
            for line in cursor.take_lines(&snapshot) {
                if let Some(value) = parser(&line) {
                    return Ok(value);
                }
            }

            if !snapshot.capture_errors.is_empty() {
                return Err(ChildHarnessError::CaptureIncomplete {
                    context: format!("{} while waiting for {event}", self.identity.context),
                    output: snapshot,
                });
            }
            if observed_exit.is_none()
                && let Some(exit) = self.try_status()?
            {
                observed_exit = Some((exit, Instant::now()));
                continue;
            }
            if let Some((exit, observed_at)) = &observed_exit {
                let drain_deadline = deadline.min(*observed_at + self.limits.capture_drain_wait);
                if snapshot.stdout_closed || Instant::now() >= drain_deadline {
                    return Err(ChildHarnessError::UnexpectedExit {
                        context: format!("{} while waiting for {event}", self.identity.context),
                        exit: exit.clone(),
                        output: self.capture.snapshot(),
                    });
                }
            }
            if Instant::now() >= deadline {
                return Err(ChildHarnessError::DeadlineExpired {
                    context: format!("{}: {event}", self.identity.context),
                    output: self.capture.snapshot(),
                });
            }
            let generation = self.capture.generation();
            self.capture
                .wait_for_change(generation, deadline, self.limits.poll_interval);
        }
    }

    pub fn wait_for_json_record<T>(
        &mut self,
        cursor: &mut OutputCursor,
        deadline: Instant,
        event: &str,
        mut parser: impl FnMut(&serde_json::Value) -> Option<T>,
    ) -> Result<T, ChildHarnessError> {
        self.wait_for_line(cursor, deadline, event, |line| {
            let record = serde_json::from_str(line.trim()).ok()?;
            parser(&record)
        })
    }

    pub fn wait_for_output_change(
        &mut self,
        generation: u64,
        deadline: Instant,
    ) -> Result<u64, ChildHarnessError> {
        loop {
            let snapshot = self.capture.snapshot();
            if !snapshot.capture_errors.is_empty() {
                return Err(ChildHarnessError::CaptureIncomplete {
                    context: format!("{} while waiting for output", self.identity.context),
                    output: snapshot,
                });
            }
            let current = self.capture.generation();
            if current != generation {
                return Ok(current);
            }
            if let Some(exit) = self.try_status()? {
                return Err(ChildHarnessError::UnexpectedExit {
                    context: format!("{} while waiting for output", self.identity.context),
                    exit,
                    output: self.capture.snapshot(),
                });
            }
            if Instant::now() >= deadline {
                return Err(ChildHarnessError::DeadlineExpired {
                    context: format!("{} output change", self.identity.context),
                    output: self.capture.snapshot(),
                });
            }
            self.capture
                .wait_for_change(current, deadline, self.limits.poll_interval);
        }
    }

    pub fn wait_until(mut self, deadline: Instant) -> Result<CompletedChild, ChildHarnessError> {
        if let Some(exit) = self.poll_for_exit(deadline)? {
            return self.complete(exit, deadline);
        }

        let context = self.identity.context.clone();
        let cleanup_deadline = Instant::now()
            + self
                .limits
                .termination_grace
                .saturating_add(self.limits.forced_reap_wait)
                .saturating_add(self.limits.capture_drain_wait);
        match self.terminate_and_reap(cleanup_deadline) {
            Ok(completed) => Err(ChildHarnessError::DeadlineExpired {
                context,
                output: completed.output,
            }),
            Err(error) => Err(error),
        }
    }

    pub fn terminate_and_reap(
        mut self,
        deadline: Instant,
    ) -> Result<CompletedChild, ChildHarnessError> {
        if let Some(exit) = self.try_status()? {
            return self.complete(exit, deadline);
        }

        let mut failures = Vec::new();
        if let Err(error) = self.signal_tree(TerminationKind::Graceful, deadline) {
            failures.push(error.to_string());
        }
        let graceful_deadline = deadline.min(Instant::now() + self.limits.termination_grace);
        if let Some(exit) = self.poll_for_exit(graceful_deadline)? {
            return self.complete(exit, deadline);
        }

        if let Err(error) = self.signal_tree(TerminationKind::Forced, deadline) {
            failures.push(error.to_string());
        }
        let forced_deadline = deadline.min(Instant::now() + self.limits.forced_reap_wait);
        if let Some(exit) = self.poll_for_exit(forced_deadline)? {
            return self.complete(exit, deadline);
        }

        self.transfer_to_reaper();
        Err(ChildHarnessError::TerminationFailed {
            context: self.identity.context.clone(),
            detail: if failures.is_empty() {
                "process remained alive through the forced-reap deadline".to_string()
            } else {
                failures.join("; ")
            },
            output: self.capture.snapshot(),
        })
    }

    fn poll_for_exit(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<ProcessExit>, ChildHarnessError> {
        loop {
            if let Some(exit) = self.try_status()? {
                return Ok(Some(exit));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(
                self.limits
                    .poll_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn complete(
        mut self,
        exit: ProcessExit,
        outer_deadline: Instant,
    ) -> Result<CompletedChild, ChildHarnessError> {
        let capture_deadline = outer_deadline.min(Instant::now() + self.limits.capture_drain_wait);
        loop {
            let output = self.capture.snapshot();
            if !output.capture_errors.is_empty() {
                self.force_remaining_process_tree();
                return Err(ChildHarnessError::CaptureIncomplete {
                    context: self.identity.context.clone(),
                    output,
                });
            }
            if output.stdout_closed && output.stderr_closed {
                for capture_thread in self.capture_threads.drain(..) {
                    if capture_thread.join().is_err() {
                        return Err(ChildHarnessError::CaptureIncomplete {
                            context: format!(
                                "{} because an output reader panicked",
                                self.identity.context
                            ),
                            output: self.capture.snapshot(),
                        });
                    }
                }
                return Ok(CompletedChild {
                    exit,
                    output: self.capture.snapshot(),
                });
            }
            if Instant::now() >= capture_deadline {
                self.force_remaining_process_tree();
                return Err(ChildHarnessError::CaptureIncomplete {
                    context: self.identity.context.clone(),
                    output,
                });
            }
            let generation = self.capture.generation();
            self.capture
                .wait_for_change(generation, capture_deadline, self.limits.poll_interval);
        }
    }

    fn force_remaining_process_tree(&mut self) {
        if let Some(process_tree) = &self.process_tree
            && let Err(error) = process_tree.terminate(TerminationKind::Forced)
        {
            eprintln!(
                "could not terminate descendants retaining capture pipes for {}: {error}",
                self.identity.context
            );
        }
    }

    fn signal_tree(&mut self, kind: TerminationKind, _deadline: Instant) -> io::Result<()> {
        let Some(process_tree) = self.process_tree.as_ref() else {
            return Ok(());
        };
        match process_tree.terminate(kind) {
            Ok(()) => Ok(()),
            #[cfg(unix)]
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                run_privileged_terminator(process_tree.process_group(), kind, _deadline)
            }
            Err(error) => Err(error),
        }
    }

    fn transfer_to_reaper(&mut self) {
        if let (Some(child), Some(process_tree)) = (self.child.take(), self.process_tree.take()) {
            reaper().send(ReaperItem {
                child,
                _process_tree: Some(process_tree),
                context: self.identity.context.clone(),
            });
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.child.is_none() {
            let output = self.capture.snapshot();
            if !output.stdout_closed || !output.stderr_closed {
                self.force_remaining_process_tree();
            }
            return;
        }
        let deadline =
            Instant::now() + self.limits.termination_grace + self.limits.forced_reap_wait;
        if let Err(error) = self.signal_tree(TerminationKind::Graceful, deadline) {
            eprintln!(
                "emergency graceful termination failed for {}: {error}",
                self.identity.context
            );
        }
        let exited = match self.poll_for_exit(Instant::now() + self.limits.termination_grace) {
            Ok(exit) => exit.is_some(),
            Err(error) => {
                eprintln!(
                    "emergency reap observation failed for {}: {error}",
                    self.identity.context
                );
                false
            }
        };
        if !exited {
            if let Err(error) = self.signal_tree(TerminationKind::Forced, deadline) {
                eprintln!(
                    "emergency forced termination failed for {}: {error}",
                    self.identity.context
                );
            }
            if let Err(error) = self.poll_for_exit(deadline) {
                eprintln!(
                    "emergency forced reap observation failed for {}: {error}",
                    self.identity.context
                );
            }
        }
        self.transfer_to_reaper();
    }
}

#[derive(Clone, Copy)]
enum TerminationKind {
    Graceful,
    Forced,
}

struct ReaperItem {
    child: Child,
    _process_tree: Option<ProcessTree>,
    context: String,
}

struct Reaper {
    sender: mpsc::Sender<ReaperItem>,
}

impl Reaper {
    fn send(&self, item: ReaperItem) {
        if let Err(error) = self.sender.send(item) {
            eprintln!("could not transfer child to background reaper: {error}");
        }
    }
}

fn reaper() -> &'static Reaper {
    static REAPER: OnceLock<Reaper> = OnceLock::new();
    REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<ReaperItem>();
        thread::Builder::new()
            .name("pkthere-test-child-reaper".to_string())
            .spawn(move || {
                let mut children = Vec::new();
                loop {
                    match receiver.recv_timeout(TEST_POLL_INTERVAL) {
                        Ok(item) => children.push(item),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) if children.is_empty() => return,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {}
                    }
                    children.retain_mut(|item| match item.child.try_wait() {
                        Ok(Some(_)) => false,
                        Ok(None) => true,
                        Err(error) => {
                            eprintln!("background reap failed for {}: {error}", item.context);
                            true
                        }
                    });
                }
            })
            .expect("spawn managed child reaper");
        Reaper { sender }
    })
}

fn abandon_spawned_child(mut child: Child, process_tree: Option<ProcessTree>, context: String) {
    let termination = if let Some(process_tree) = &process_tree {
        process_tree.terminate(TerminationKind::Forced)
    } else {
        child.kill()
    };
    if let Err(error) = termination {
        eprintln!("emergency termination failed for {context}: {error}");
    }
    reaper().send(ReaperItem {
        child,
        _process_tree: process_tree,
        context,
    });
}

#[cfg(unix)]
fn configure_process_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn configure_process_tree(_command: &mut Command) {}

#[cfg(not(any(unix, windows)))]
fn configure_process_tree(_command: &mut Command) {}

#[cfg(unix)]
struct ProcessTree {
    process_group: i32,
}

#[cfg(unix)]
impl ProcessTree {
    fn new(child: &mut Child) -> io::Result<Self> {
        let process_group = i32::try_from(child.id())
            .map_err(|_| io::Error::other("child process id exceeds i32"))?;
        Ok(Self { process_group })
    }

    fn terminate(&self, kind: TerminationKind) -> io::Result<()> {
        let signal = match kind {
            TerminationKind::Graceful => libc::SIGTERM,
            TerminationKind::Forced => libc::SIGKILL,
        };
        let result = unsafe { libc::kill(-self.process_group, signal) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn process_group(&self) -> i32 {
        self.process_group
    }
}

#[cfg(unix)]
fn run_privileged_terminator(
    process_group: i32,
    kind: TerminationKind,
    deadline: Instant,
) -> io::Result<()> {
    let signal = match kind {
        TerminationKind::Graceful => "-TERM",
        TerminationKind::Forced => "-KILL",
    };
    let mut command = Command::new("sudo");
    command
        .arg("-n")
        .arg("/bin/kill")
        .arg(signal)
        .arg("--")
        .arg(format!("-{process_group}"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                return Err(io::Error::other(format!(
                    "privileged terminator exited with {status}: {}",
                    stderr.trim()
                )));
            }
            None if Instant::now() < deadline => thread::sleep(
                TEST_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            ),
            None => {
                let kill_error = child.kill().err();
                reaper().send(ReaperItem {
                    child,
                    _process_tree: None,
                    context: "privileged process-tree terminator".to_string(),
                });
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    match kill_error {
                        Some(error) => format!(
                            "privileged terminator exceeded its deadline and kill failed: {error}"
                        ),
                        None => "privileged terminator exceeded its deadline".to_string(),
                    },
                ));
            }
        }
    }
}

#[cfg(windows)]
struct ProcessTree {
    job: isize,
}

#[cfg(windows)]
unsafe impl Send for ProcessTree {}

#[cfg(windows)]
impl ProcessTree {
    fn new(child: &mut Child) -> io::Result<Self> {
        use std::mem::{size_of, zeroed};
        use std::os::windows::io::AsRawHandle;
        use std::ptr::null;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &information as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        let assigned = configured != 0
            && unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) } != 0;
        if !assigned {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(job) };
            return Err(error);
        }
        Ok(Self { job: job as isize })
    }

    fn terminate(&self, _kind: TerminationKind) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if unsafe { TerminateJobObject(self.job as _, 1) } != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe { CloseHandle(self.job as _) };
    }
}

#[cfg(not(any(unix, windows)))]
struct ProcessTree;

#[cfg(not(any(unix, windows)))]
impl ProcessTree {
    fn new(_child: &mut Child) -> io::Result<Self> {
        Ok(Self)
    }

    fn terminate(&self, _kind: TerminationKind) -> io::Result<()> {
        Ok(())
    }
}
