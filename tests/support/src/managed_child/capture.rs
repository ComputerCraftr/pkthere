use std::io::{self, Read};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub capture_errors: Vec<String>,
}

impl CapturedOutput {
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Clone, Debug, Default)]
pub struct OutputCursor {
    pub(super) stdout_offset: usize,
    pub(super) partial_line: Vec<u8>,
}

impl OutputCursor {
    pub fn take_lines(&mut self, snapshot: &CapturedOutput) -> Vec<String> {
        if self.stdout_offset < snapshot.stdout.len() {
            self.partial_line
                .extend_from_slice(&snapshot.stdout[self.stdout_offset..]);
            self.stdout_offset = snapshot.stdout.len();
        }

        let mut lines = Vec::new();
        while let Some(newline) = self.partial_line.iter().position(|byte| *byte == b'\n') {
            let line = self.partial_line.drain(..=newline).collect::<Vec<_>>();
            lines.push(String::from_utf8_lossy(&line).into_owned());
        }
        if snapshot.stdout_closed && !self.partial_line.is_empty() {
            lines.push(String::from_utf8_lossy(&self.partial_line).into_owned());
            self.partial_line.clear();
        }
        lines
    }
}

#[derive(Default)]
struct StreamCapture {
    bytes: Vec<u8>,
    closed: bool,
}

#[derive(Default)]
struct CaptureState {
    stdout: StreamCapture,
    stderr: StreamCapture,
    errors: Vec<String>,
    generation: u64,
}

#[derive(Clone, Default)]
pub(super) struct CaptureBuffer {
    inner: Arc<(Mutex<CaptureState>, Condvar)>,
}

#[derive(Clone, Copy)]
pub(super) enum StreamKind {
    Stdout,
    Stderr,
}

impl CaptureBuffer {
    fn push(&self, stream: StreamKind, bytes: &[u8]) {
        let (lock, changed) = &*self.inner;
        let mut state = lock.lock().expect("managed child capture lock");
        match stream {
            StreamKind::Stdout => state.stdout.bytes.extend_from_slice(bytes),
            StreamKind::Stderr => state.stderr.bytes.extend_from_slice(bytes),
        }
        state.generation = state.generation.wrapping_add(1);
        changed.notify_all();
    }

    fn close(&self, stream: StreamKind, error: Option<String>) {
        let (lock, changed) = &*self.inner;
        let mut state = lock.lock().expect("managed child capture lock");
        match stream {
            StreamKind::Stdout => state.stdout.closed = true,
            StreamKind::Stderr => state.stderr.closed = true,
        }
        if let Some(error) = error {
            state.errors.push(error);
        }
        state.generation = state.generation.wrapping_add(1);
        changed.notify_all();
    }

    pub(super) fn snapshot(&self) -> CapturedOutput {
        let (lock, _) = &*self.inner;
        let state = lock.lock().expect("managed child capture lock");
        CapturedOutput {
            stdout: state.stdout.bytes.clone(),
            stderr: state.stderr.bytes.clone(),
            stdout_closed: state.stdout.closed,
            stderr_closed: state.stderr.closed,
            capture_errors: state.errors.clone(),
        }
    }

    pub(super) fn wait_for_change(&self, generation: u64, deadline: Instant, poll: Duration) {
        let (lock, changed) = &*self.inner;
        let state = lock.lock().expect("managed child capture lock");
        if state.generation != generation {
            return;
        }
        let wait = poll.min(deadline.saturating_duration_since(Instant::now()));
        if !wait.is_zero() {
            drop(
                changed
                    .wait_timeout(state, wait)
                    .expect("managed child capture wait"),
            );
        }
    }

    pub(super) fn generation(&self) -> u64 {
        let (lock, _) = &*self.inner;
        lock.lock().expect("managed child capture lock").generation
    }
}

pub(super) fn spawn_capture<R: Read + Send + 'static>(
    mut reader: R,
    stream: StreamKind,
    capture: CaptureBuffer,
) -> io::Result<thread::JoinHandle<()>> {
    let stream_name = match stream {
        StreamKind::Stdout => "stdout",
        StreamKind::Stderr => "stderr",
    };
    thread::Builder::new()
        .name(format!("pkthere-test-capture-{stream_name}"))
        .spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        capture.close(stream, None);
                        return;
                    }
                    Ok(count) => capture.push(stream, &chunk[..count]),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        capture.close(stream, Some(error.to_string()));
                        return;
                    }
                }
            }
        })
}
