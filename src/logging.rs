use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering as AtomOrdering};

#[doc(hidden)]
pub(crate) const fn log_dir_label(c2u: bool) -> &'static str {
    if c2u { "c2u" } else { "u2c" }
}

static STDOUT_BROKEN: AtomicBool = AtomicBool::new(false);

#[doc(hidden)]
pub(crate) fn emit_stdout(args: fmt::Arguments<'_>) {
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
    let _ = writeln!(io::stderr().lock(), "{args}");
}

#[macro_export]
macro_rules! __log_emit_plain {
    (stdout, $level:literal, $($arg:tt)*) => {
        $crate::logging::emit_stdout(::std::format_args!(
            "[{}] {}",
            $level,
            ::std::format_args!($($arg)*)
        ));
    };
    (stderr, $level:literal, $($arg:tt)*) => {
        $crate::logging::emit_stderr(::std::format_args!(
            "[{}] {}",
            $level,
            ::std::format_args!($($arg)*)
        ));
    };
}

#[macro_export]
macro_rules! __log_emit_dir {
    (stdout, $level:literal, $worker:expr, $c2u:expr, $($arg:tt)*) => {
        $crate::logging::emit_stdout(::std::format_args!(
            "[{}][worker {}][{}] {}",
            $level,
            $worker,
            $crate::logging::log_dir_label($c2u),
            ::std::format_args!($($arg)*)
        ));
    };
    (stderr, $level:literal, $worker:expr, $c2u:expr, $($arg:tt)*) => {
        $crate::logging::emit_stderr(::std::format_args!(
            "[{}][worker {}][{}] {}",
            $level,
            $worker,
            $crate::logging::log_dir_label($c2u),
            ::std::format_args!($($arg)*)
        ));
    };
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
