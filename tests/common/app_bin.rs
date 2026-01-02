use std::env;
use std::path::{Path, PathBuf};

/// Try to locate the built forwarder binary across platforms (Linux/macOS/Windows).
pub fn find_app_bin() -> Option<String> {
    // Optional explicit override for CI or local runs.
    // e.g. TEST_APP_BIN=/path/to/bin cargo test
    if let Ok(override_path) = env::var("TEST_APP_BIN") {
        if Path::new(&override_path).exists() {
            return Some(override_path);
        }
    }

    // Helper: add .exe on Windows
    fn with_ext(name: &str) -> String {
        if cfg!(windows) && !name.ends_with(".exe") {
            format!("{name}.exe")
        } else {
            name.to_string()
        }
    }

    // Helper: return the first existing path from candidates
    fn first_existing(paths: impl IntoIterator<Item = PathBuf>) -> Option<String> {
        for p in paths {
            if p.exists() {
                return Some(p.to_string_lossy().to_string());
            }
        }
        None
    }

    // 1) Prefer Cargo's CARGO_BIN_EXE_* variables. This is the most accurate because it
    //    contains the actual, resolved path(s) for bin targets built for this package.
    //    We don't assume the bin name; instead we scan all env vars with that prefix,
    //    and pick the one that exists on disk.
    let mut candidates: Vec<(String, String)> = Vec::new();
    for (k, v) in env::vars() {
        if k.starts_with("CARGO_BIN_EXE_") && Path::new(&v).exists() {
            candidates.push((k, v));
        }
    }

    // If exactly one candidate exists, use it.
    if candidates.len() == 1 {
        return Some(candidates.remove(0).1);
    }

    // If multiple exist (multi-bin workspace), try to pick the one that matches the package name.
    if candidates.len() > 1 {
        if let Ok(pkg) = env::var("CARGO_PKG_NAME") {
            let want1 = pkg.replace('-', "_");
            let want2 = pkg.clone();
            if let Some((_k, v)) = candidates.iter().find(|(k, _)| {
                k == &format!("CARGO_BIN_EXE_{want1}") || k == &format!("CARGO_BIN_EXE_{want2}")
            }) {
                return Some(v.clone());
            }
        }
        // Otherwise, just take the first existing one deterministically (sorted by key).
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        return Some(candidates.remove(0).1);
    }

    // 2) No CARGO_BIN_EXE_* variables were exported (or they didn't exist on disk).
    //    Fall back to guessing from the package name and common target locations.
    let pkg = env::var("CARGO_PKG_NAME").unwrap_or_else(|_| String::from("app"));
    let exe_name = with_ext(&pkg);

    // Try next to the test executable: prefer release, then debug
    if let Ok(mut exe) = env::current_exe() {
        // .../target/{profile}/deps/<test_exe>
        if exe.pop() && exe.pop() {
            // Now at .../target/{profile}
            let target_root = exe.parent().map(Path::to_path_buf);
            // Check release first, then the current profile dir
            if let Some(root) = target_root {
                let candidates = [
                    root.join("release").join(&exe_name),
                    exe.join(&exe_name),
                    root.join("debug").join(&exe_name),
                ];
                if let Some(found) = first_existing(candidates.into_iter()) {
                    return Some(found);
                }
            }
        }
    }

    // Try under CARGO_TARGET_DIR if set.
    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        let target = PathBuf::from(target_dir);
        let paths = ["release", "debug"]
            .into_iter()
            .map(|p| target.join(p).join(&exe_name));
        if let Some(p) = first_existing(paths) {
            return Some(p);
        }
    }

    // Fallback to standard target/<profile>/<exe_name> under the manifest dir.
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let md = PathBuf::from(manifest_dir);
        let paths = ["release", "debug"]
            .into_iter()
            .map(|p| md.join("target").join(p).join(&exe_name));
        if let Some(p) = first_existing(paths) {
            return Some(p);
        }
    }

    None
}
