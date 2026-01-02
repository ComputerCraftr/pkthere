#[path = "app_bin.rs"]
mod app_bin;

use std::io::Read;
use std::process::{Command, Stdio};

pub fn run_cli_args(args: &[&str]) -> (Option<i32>, String) {
    let bin = app_bin::find_app_bin().expect("could not find app binary");
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failed");

    let status = child.wait().expect("wait failed");
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code(), err)
}
