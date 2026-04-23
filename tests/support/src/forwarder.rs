use crate::app_bin::find_app_bin;
use crate::managed_child::{
    CapturedOutput, ChildHarnessError, ChildIdentity, ChildLimits, CompletedChild, ManagedChild,
    OutputCursor, ProcessExit,
};
use crate::runtime_io::{parse_listen_addr, strip_log_prefix};
use crate::timing::MAX_WAIT_SECS;

use std::io;
use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

pub struct ForwarderConfig<'a> {
    pub debug_client_unconnected: bool,
    pub debug_upstream_unconnected: bool,
    pub debug_icmp_kernel_echo_self_handshake: bool,
    pub debug_force_raw_icmp_wildcard_upstream: bool,
    pub here: String,
    pub there: String,
    pub here_source_id: Option<u16>,
    pub here_reply_id: Option<u16>,
    pub there_source_id: Option<u16>,
    pub there_reply_id: Option<u16>,
    pub timeout_action: &'a str,
    pub timeout_secs: Option<u64>,
    pub max_payload: Option<usize>,
    pub fast_stats: bool,
    pub stats_interval_mins: Option<u32>,
    pub icmp_sync_pps: Option<u32>,
    pub debug_logs: &'a [&'a str],
    pub diagnostic_label: Option<&'a str>,
    pub icmp_handshake_timeout_secs: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct CompletedForwarder {
    pub child: CompletedChild,
    pub listen_addr: SocketAddr,
    pub command_arguments: Vec<String>,
    pub command_line: String,
    pub diagnostic_label: String,
}

pub struct ForwarderSession {
    child: Option<ManagedChild>,
    completed: Option<CompletedChild>,
    stdout_cursor: OutputCursor,
    pub listen_addr: SocketAddr,
    command_arguments: Vec<String>,
    command_line: String,
    diagnostic_label: String,
}

impl ForwarderSession {
    pub fn command_arguments(&self) -> &[String] {
        &self.command_arguments
    }

    pub fn output_snapshot(&self) -> CapturedOutput {
        if let Some(child) = &self.child {
            child.output_snapshot()
        } else {
            self.completed
                .as_ref()
                .map(|completed| completed.output.clone())
                .unwrap_or_default()
        }
    }

    pub fn diagnostic_snapshot(&self, max_lines: usize) -> String {
        let output = self.output_snapshot();
        render_session_diagnostics(
            &self.diagnostic_label,
            &self.command_line,
            Some(self.listen_addr),
            &output.stdout_lossy(),
            &output.stderr_lossy(),
            max_lines,
        )
    }

    pub fn try_status(&mut self) -> io::Result<Option<ProcessExit>> {
        if let Some(completed) = &self.completed {
            return Ok(Some(completed.exit.clone()));
        }
        self.child_mut()?.try_status().map_err(child_error)
    }

    pub fn is_running(&mut self) -> io::Result<bool> {
        self.try_status().map(|status| status.is_none())
    }

    pub fn wait_for_output(
        &mut self,
        deadline: Instant,
        event: &str,
        mut predicate: impl FnMut(&CapturedOutput) -> bool,
    ) -> io::Result<CapturedOutput> {
        loop {
            let snapshot = self.output_snapshot();
            if predicate(&snapshot) {
                return Ok(snapshot);
            }
            let Some(child) = self.child.as_mut() else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("forwarder completed before {event}"),
                ));
            };
            let generation = child.output_generation();
            match child.wait_for_output_change(generation, deadline) {
                Ok(_) => {}
                Err(error) => return Err(child_error(error)),
            }
        }
    }

    pub fn wait_for_stdout_line<T>(
        &mut self,
        deadline: Instant,
        event: &str,
        parser: impl FnMut(&str) -> Option<T>,
    ) -> io::Result<T> {
        let mut cursor = std::mem::take(&mut self.stdout_cursor);
        let result = if self.child.is_some() {
            self.child_mut()?
                .wait_for_line(&mut cursor, deadline, event, parser)
                .map_err(child_error)
        } else {
            let snapshot = self.output_snapshot();
            let mut parser = parser;
            cursor
                .take_lines(&snapshot)
                .into_iter()
                .find_map(|line| parser(&line))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("forwarder completed before {event}"),
                    )
                })
        };
        self.stdout_cursor = cursor;
        result
    }

    pub fn wait_for_exit_success(&mut self, max_wait: Duration) -> io::Result<ProcessExit> {
        let exit = self
            .wait_for_completion(Instant::now() + max_wait)?
            .exit
            .clone();
        if exit.success {
            Ok(exit)
        } else {
            Err(io::Error::other(format!(
                "forwarder did not exit cleanly: {}\n{}",
                exit,
                self.diagnostic_snapshot(40)
            )))
        }
    }

    pub fn terminate(&mut self, deadline: Instant) -> io::Result<&CompletedChild> {
        if self.completed.is_none() {
            let child = self
                .child
                .take()
                .ok_or_else(|| io::Error::other("forwarder child missing"))?;
            self.completed = Some(child.terminate_and_reap(deadline).map_err(child_error)?);
        }
        Ok(self.completed.as_ref().expect("completed forwarder child"))
    }

    pub fn wait_for_completion(&mut self, deadline: Instant) -> io::Result<&CompletedChild> {
        if self.completed.is_none() {
            let child = self
                .child
                .take()
                .ok_or_else(|| io::Error::other("forwarder child missing"))?;
            self.completed = Some(child.wait_until(deadline).map_err(child_error)?);
        }
        Ok(self.completed.as_ref().expect("completed forwarder child"))
    }

    pub fn finish(mut self, deadline: Instant) -> io::Result<CompletedForwarder> {
        self.terminate(deadline)?;
        Ok(self.take_completed_forwarder())
    }

    pub fn wait_until(mut self, deadline: Instant) -> io::Result<CompletedForwarder> {
        self.wait_for_completion(deadline)?;
        Ok(self.take_completed_forwarder())
    }

    fn take_completed_forwarder(&mut self) -> CompletedForwarder {
        let child = self
            .completed
            .take()
            .expect("completed forwarder must own a completed child");
        CompletedForwarder {
            child,
            listen_addr: self.listen_addr,
            command_arguments: std::mem::take(&mut self.command_arguments),
            command_line: std::mem::take(&mut self.command_line),
            diagnostic_label: std::mem::take(&mut self.diagnostic_label),
        }
    }

    fn child_mut(&mut self) -> io::Result<&mut ManagedChild> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("forwarder child is already complete"))
    }
}

pub fn launch_forwarder(config: ForwarderConfig<'_>) -> ForwarderSession {
    try_launch_forwarder(config)
        .unwrap_or_else(|error| panic!("could not launch forwarder:\n{error}"))
}

pub fn try_launch_forwarder(config: ForwarderConfig<'_>) -> io::Result<ForwarderSession> {
    try_launch_forwarder_with_extra_args(config, &[])
}

pub fn launch_forwarder_with_extra_args(
    config: ForwarderConfig<'_>,
    extra_args: &[String],
) -> ForwarderSession {
    try_launch_forwarder_with_extra_args(config, extra_args)
        .unwrap_or_else(|error| panic!("could not launch forwarder:\n{error}"))
}

fn try_launch_forwarder_with_extra_args(
    config: ForwarderConfig<'_>,
    extra_args: &[String],
) -> io::Result<ForwarderSession> {
    let binary = find_app_bin().expect("could not find app binary");
    let mut command = Command::new(&binary);
    command
        .arg("--here")
        .arg(&config.here)
        .arg("--there")
        .arg(&config.there);
    if let Some(id) = config.here_source_id {
        command.arg("--here-source-id").arg(id.to_string());
    }
    if let Some(id) = config.here_reply_id {
        command.arg("--here-reply-id").arg(id.to_string());
    }
    if let Some(id) = config.there_source_id {
        command.arg("--there-source-id").arg(id.to_string());
    }
    if let Some(id) = config.there_reply_id {
        command.arg("--there-reply-id").arg(id.to_string());
    }
    command
        .arg("--timeout-secs")
        .arg(
            config
                .timeout_secs
                .unwrap_or(crate::timing::TIMEOUT_SECS.as_secs())
                .to_string(),
        )
        .arg("--on-timeout")
        .arg(config.timeout_action);
    if let Some(max_payload) = config.max_payload {
        command.arg("--max-payload").arg(max_payload.to_string());
    }
    if let Some(seconds) = config.icmp_handshake_timeout_secs {
        command
            .arg("--icmp-handshake-timeout-secs")
            .arg(seconds.to_string());
    }
    if let Some(minutes) = config.stats_interval_mins {
        command
            .arg("--stats-interval-mins")
            .arg(minutes.to_string());
    }
    if let Some(pps) = config.icmp_sync_pps {
        command.arg("--icmp-sync-pps").arg(pps.to_string());
    }
    if config.fast_stats {
        command.arg("--debug-fast-stats");
    }
    for debug_log in config.debug_logs {
        command.arg("--debug-log").arg(debug_log);
    }
    if config.debug_client_unconnected {
        command.arg("--debug-client-unconnected");
    }
    if config.debug_upstream_unconnected {
        command.arg("--debug-upstream-unconnected");
    }
    if config.debug_icmp_kernel_echo_self_handshake {
        command.arg("--debug-icmp-kernel-echo-self-handshake");
    }
    if config.debug_force_raw_icmp_wildcard_upstream {
        command.arg("--debug-force-raw-icmp-wildcard-upstream");
    }
    command.args(extra_args);

    crate::user_policy::apply_root_user_args(&mut command);
    let command_arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let command_line = render_command(&command);
    let diagnostic_label = config.diagnostic_label.unwrap_or("forwarder").to_string();
    let mut child = ManagedChild::spawn(
        &mut command,
        ChildIdentity::new(diagnostic_label.clone()),
        ChildLimits::default(),
    )
    .map_err(child_error)?;
    let mut cursor = child.output_cursor();
    let listen_result = child.wait_for_line(
        &mut cursor,
        Instant::now() + MAX_WAIT_SECS,
        "listening address",
        parse_listen_addr,
    );
    let listen_addr = match listen_result {
        Ok(address) => address,
        Err(error) => {
            let termination_deadline = Instant::now() + crate::timing::CHILD_CLEANUP_WAIT;
            let final_output = match child.terminate_and_reap(termination_deadline) {
                Ok(completed) => completed.output,
                Err(termination_error) => termination_error
                    .output()
                    .cloned()
                    .or_else(|| error.output().cloned())
                    .unwrap_or_default(),
            };
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{error}\n{}",
                    render_session_diagnostics(
                        &diagnostic_label,
                        &command_line,
                        None,
                        &final_output.stdout_lossy(),
                        &final_output.stderr_lossy(),
                        80,
                    )
                ),
            ));
        }
    };

    Ok(ForwarderSession {
        child: Some(child),
        completed: None,
        stdout_cursor: cursor,
        listen_addr,
        command_arguments,
        command_line,
        diagnostic_label,
    })
}

fn child_error(error: ChildHarnessError) -> io::Error {
    let kind = match error {
        ChildHarnessError::DeadlineExpired { .. } | ChildHarnessError::CaptureIncomplete { .. } => {
            io::ErrorKind::TimedOut
        }
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

fn render_command(command: &Command) -> String {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|argument| quote_command_arg(&argument.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_command_arg(argument: &str) -> String {
    if argument.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/' | ':' | '=')
    }) {
        argument.to_string()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn render_session_diagnostics(
    label: &str,
    command_line: &str,
    listen_addr: Option<SocketAddr>,
    stdout: &str,
    stderr: &str,
    max_lines: usize,
) -> String {
    let last_stats = last_stats_json(stdout)
        .map(|stats| stats.to_string())
        .unwrap_or_else(|| "<none>".to_string());
    format!(
        "=== forwarder diagnostics: {label} ===\n\
         command: {command_line}\n\
         listen_addr: {}\n\
         last stats: {last_stats}\n\
         === stdout tail ===\n{}\n\
         === stderr tail ===\n{}",
        listen_addr
            .map(|address| address.to_string())
            .unwrap_or_else(|| "<unknown>".to_string()),
        render_output_tail(stdout, max_lines),
        render_output_tail(stderr, max_lines)
    )
}

fn last_stats_json(stdout: &str) -> Option<serde_json::Value> {
    stdout.lines().rev().find_map(|line| {
        let line = strip_log_prefix(line);
        (line.starts_with('{') && line.ends_with('}'))
            .then(|| serde_json::from_str::<serde_json::Value>(line).ok())
            .flatten()
    })
}

pub fn snapshot_forwarder_output(session: &ForwarderSession) -> io::Result<(String, String)> {
    let output = session.output_snapshot();
    Ok((output.stdout_lossy(), output.stderr_lossy()))
}

pub fn snapshot_forwarder_output_tail(
    session: &ForwarderSession,
    max_lines: usize,
) -> io::Result<(String, String)> {
    let output = session.output_snapshot();
    Ok((
        render_output_tail(&output.stdout_lossy(), max_lines),
        render_output_tail(&output.stderr_lossy(), max_lines),
    ))
}

fn render_output_tail(text: &str, max_lines: usize) -> String {
    let lines = text.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::render_session_diagnostics;

    #[test]
    fn diagnostics_include_latest_stats_and_both_output_tails() {
        let rendered = render_session_diagnostics(
            "node-a",
            "pkthere --here UDP:127.0.0.1:0",
            None,
            "boot\n[INFO] {\"locked\":true}\nlast stdout",
            "first stderr\nlast stderr",
            2,
        );
        assert!(rendered.contains("node-a"));
        assert!(rendered.contains("{\"locked\":true}"));
        assert!(rendered.contains("last stdout"));
        assert!(rendered.contains("last stderr"));
    }
}
