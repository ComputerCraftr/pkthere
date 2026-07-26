use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub fn platform_executable_name(base: &str) -> OsString {
    #[cfg(windows)]
    if !base.ends_with(".exe") {
        return OsString::from(format!("{base}.exe"));
    }

    OsString::from(base)
}

pub fn render_test_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn render_repo_relative_path(repo_root: &Path, path: &Path) -> String {
    let canonical_root = repo_root.canonicalize().ok();
    let canonical_path = path.canonicalize().ok();
    let rel = path.strip_prefix(repo_root).ok().or_else(|| {
        canonical_root
            .as_deref()
            .zip(canonical_path.as_deref())
            .and_then(|(root, candidate)| candidate.strip_prefix(root).ok())
    });
    let rel = rel.unwrap_or(path);
    render_test_path(rel)
}

pub fn join_test_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    path
}

#[cfg(test)]
mod tests;
