use pkthere_test_support::raw_icmp::acquire_raw_icmp_lock;
use pkthere_test_support::timing::{CAPTURE_DRAIN_WAIT, RAW_ICMP_LOCK_WAIT, TEST_RETRY_INTERVAL};

use std::io::{self, Write};
use std::process::Command;
use std::time::Instant;

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("missing harness-child mode"));
    match mode.as_str() {
        "pipe-flood" => pipe_flood(),
        "final-line-on-term" => final_line_on_term(),
        "hold-raw-lock" => hold_raw_lock(),
        "spawn-descendant" => spawn_descendant(),
        "spawn-escaped-pipe" => spawn_escaped_pipe(),
        "escaped-pipe-descendant" => {
            std::thread::sleep(CAPTURE_DRAIN_WAIT * 3);
        }
        "json-record" => json_record(),
        "delayed-exit" => {
            std::thread::sleep(TEST_RETRY_INTERVAL * 2);
            println!("delayed-final");
        }
        "ignore-term" => ignore_term(),
        "exit-error" => std::process::exit(23),
        "sleep" => loop {
            println!("pid={}", std::process::id());
            io::stdout().flush().expect("flush sleeping pid");
            std::thread::park();
        },
        _ => panic!("unknown harness-child mode {mode}"),
    }
}

fn pipe_flood() {
    const OUTPUT_BYTES: usize = 256 * 1024;
    let stdout_payload = vec![b'o'; OUTPUT_BYTES];
    let stderr_payload = vec![b'e'; OUTPUT_BYTES];
    io::stdout()
        .write_all(&stdout_payload)
        .expect("write stdout flood");
    io::stderr()
        .write_all(&stderr_payload)
        .expect("write stderr flood");
}

fn final_line_on_term() {
    ctrlc::set_handler(|| {
        eprintln!("final-line-during-termination");
        std::process::exit(0);
    })
    .expect("install termination handler");
    println!("ready");
    io::stdout().flush().expect("flush ready line");
    loop {
        std::thread::park();
    }
}

fn hold_raw_lock() {
    let _guard = acquire_raw_icmp_lock(
        Instant::now() + RAW_ICMP_LOCK_WAIT,
        "harness_child_lock_holder",
    )
    .expect("acquire harness-child RAW ICMP lock");
    println!("lock-ready");
    io::stdout().flush().expect("flush lock-ready line");
    loop {
        std::thread::park();
    }
}

fn spawn_descendant() {
    let executable = std::env::current_exe().expect("current harness-child executable");
    let descendant = Command::new(executable)
        .arg("sleep")
        .spawn()
        .expect("spawn descendant");
    println!("descendant={}", descendant.id());
    io::stdout().flush().expect("flush descendant pid");
    drop(descendant);
    loop {
        std::thread::park();
    }
}

#[cfg(unix)]
fn spawn_escaped_pipe() {
    use std::os::unix::process::CommandExt;

    let executable = std::env::current_exe().expect("current harness-child executable");
    let mut command = Command::new(executable);
    command.arg("escaped-pipe-descendant").process_group(0);
    let descendant = command.spawn().expect("spawn escaped pipe descendant");
    println!("escaped={}", descendant.id());
    io::stdout().flush().expect("flush escaped descendant pid");
    drop(descendant);
    loop {
        std::thread::park();
    }
}

#[cfg(not(unix))]
fn spawn_escaped_pipe() {
    panic!("escaped pipe helper is Unix-only");
}

fn json_record() {
    println!("not-json");
    println!(r#"{{"ready":true,"sequence":7}}"#);
    io::stdout().flush().expect("flush JSON record");
    loop {
        std::thread::park();
    }
}

fn ignore_term() {
    ctrlc::set_handler(|| {}).expect("install ignored termination handler");
    println!("pid={}", std::process::id());
    io::stdout().flush().expect("flush ignored-termination pid");
    loop {
        std::thread::park();
    }
}
