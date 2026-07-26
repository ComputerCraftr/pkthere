use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering as AtomOrdering};

static STDOUT_BROKEN: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    AtomicBool,
> = crate::authority::AuthorityAtomic::new_bool(
    false,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);

#[doc(hidden)]
pub(crate) const fn log_dir_label(c2u: bool) -> &'static str {
    if c2u { "c2u" } else { "u2c" }
}

#[doc(hidden)]
pub(crate) fn emit_stdout(args: fmt::Arguments<'_>) {
    // Independent sticky hint: this flag publishes no associated output data;
    // a stale false can only cause one extra best-effort write.
    if STDOUT_BROKEN.load(AtomOrdering::Relaxed) {
        return;
    }

    let mut stdout = io::stdout().lock();
    if let Err(e) = writeln!(stdout, "{args}")
        && e.kind() == io::ErrorKind::BrokenPipe
    {
        STDOUT_BROKEN.store(true, AtomOrdering::Relaxed);
    }
}

#[doc(hidden)]
pub(crate) fn emit_stderr(args: fmt::Arguments<'_>) {
    if writeln!(io::stderr().lock(), "{args}").is_err() {
        // Stderr diagnostics are best-effort and must not affect forwarding.
    }
}

#[doc(hidden)]
pub(crate) fn enter_logging_scope(
    source_file: &'static str,
    source_line: u32,
) -> crate::authority::AuditedOperationScope {
    crate::authority::AuditedOperationScope::enter(crate::authority::OperationId::Logging)
        .unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "logging conflict {error} at {}:{}",
                source_file, source_line,
            ))
        })
}

#[macro_export]
macro_rules! __log_emit_plain {
    (stdout, $level:literal, $($arg:tt)*) => {{
        let _logging_scope = $crate::logging::enter_logging_scope(file!(), line!());
        $crate::logging::emit_stdout(::std::format_args!(
            "[{}] {}",
            $level,
            ::std::format_args!($($arg)*)
        ));
    }};
    (stderr, $level:literal, $($arg:tt)*) => {{
        let _logging_scope = $crate::logging::enter_logging_scope(file!(), line!());
        $crate::logging::emit_stderr(::std::format_args!(
            "[{}] {}",
            $level,
            ::std::format_args!($($arg)*)
        ));
    }};
}

#[macro_export]
macro_rules! __log_emit_dir {
    (stdout, $level:literal, $worker:expr, $c2u:expr, $($arg:tt)*) => {{
        let _logging_scope = $crate::logging::enter_logging_scope(file!(), line!());
        $crate::logging::emit_stdout(::std::format_args!(
            "[{}][worker {}][{}] {}",
            $level,
            $worker,
            $crate::logging::log_dir_label($c2u),
            ::std::format_args!($($arg)*)
        ));
    }};
    (stderr, $level:literal, $worker:expr, $c2u:expr, $($arg:tt)*) => {{
        let _logging_scope = $crate::logging::enter_logging_scope(file!(), line!());
        $crate::logging::emit_stderr(::std::format_args!(
            "[{}][worker {}][{}] {}",
            $level,
            $worker,
            $crate::logging::log_dir_label($c2u),
            ::std::format_args!($($arg)*)
        ));
    }};
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::__log_emit_plain!(stdout, "INFO", $($arg)*);
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::__log_emit_plain!(stderr, "WARN", $($arg)*);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::__log_emit_plain!(stderr, "ERROR", $($arg)*);
    };
}

#[macro_export]
macro_rules! log_debug {
    ($enabled:expr, $($arg:tt)*) => {
        if $enabled {
            $crate::__log_emit_plain!(stderr, "DEBUG", $($arg)*);
        }
    };
}

#[macro_export]
macro_rules! log_info_dir {
    ($worker:expr, $c2u:expr, $($arg:tt)*) => {
        $crate::__log_emit_dir!(stdout, "INFO", $worker, $c2u, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_warn_dir {
    ($worker:expr, $c2u:expr, $($arg:tt)*) => {
        $crate::__log_emit_dir!(stderr, "WARN", $worker, $c2u, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_error_dir {
    ($worker:expr, $c2u:expr, $($arg:tt)*) => {
        $crate::__log_emit_dir!(stderr, "ERROR", $worker, $c2u, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_debug_dir {
    ($enabled:expr, $worker:expr, $c2u:expr, $($arg:tt)*) => {
        if $enabled {
            $crate::__log_emit_dir!(stderr, "DEBUG", $worker, $c2u, $($arg)*);
        }
    };
}

#[macro_export]
macro_rules! result_or_log_continue {
    ($res:expr, $log_macro:ident, $($args:tt)*) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                $log_macro!($($args)*, e);
                continue;
            }
        }
    };
}
