#[doc(hidden)]
pub const fn log_dir_label(c2u: bool) -> &'static str {
    if c2u { "c2u" } else { "u2c" }
}

#[macro_export]
macro_rules! __log_emit_plain {
    (stdout, $level:literal, $($arg:tt)*) => {
        ::std::println!("[{}] {}", $level, ::std::format_args!($($arg)*));
    };
    (stderr, $level:literal, $($arg:tt)*) => {
        ::std::eprintln!("[{}] {}", $level, ::std::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! __log_emit_dir {
    (stdout, $level:literal, $worker:expr, $c2u:expr, $($arg:tt)*) => {
        ::std::println!(
            "[{}][worker {}][{}] {}",
            $level,
            $worker,
            $crate::logging::log_dir_label($c2u),
            ::std::format_args!($($arg)*)
        );
    };
    (stderr, $level:literal, $worker:expr, $c2u:expr, $($arg:tt)*) => {
        ::std::eprintln!(
            "[{}][worker {}][{}] {}",
            $level,
            $worker,
            $crate::logging::log_dir_label($c2u),
            ::std::format_args!($($arg)*)
        );
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
