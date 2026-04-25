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
    let rel = path.strip_prefix(repo_root).unwrap_or(path);
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
mod tests {
    use super::{
        join_test_path, platform_executable_name, render_repo_relative_path, render_test_path,
    };
    use std::path::Path;

    #[test]
    fn render_test_path_normalizes_separators() {
        let path = join_test_path(&["tmp", "folder", "file.txt"]);
        let rendered = render_test_path(&path);
        assert!(!rendered.contains('\\'));
        assert!(rendered.ends_with("tmp/folder/file.txt") || rendered == "tmp/folder/file.txt");
    }

    #[test]
    fn render_repo_relative_path_uses_repo_relative_view() {
        let repo_root = join_test_path(&["repo"]);
        let child = join_test_path(&["repo", "tests", "common", "policy.rs"]);
        assert_eq!(
            render_repo_relative_path(&repo_root, &child),
            "tests/common/policy.rs"
        );
    }

    #[test]
    fn platform_executable_name_matches_current_platform_policy() {
        let exe = platform_executable_name("pkthere");
        #[cfg(windows)]
        assert_eq!(exe, "pkthere.exe");

        #[cfg(not(windows))]
        assert_eq!(exe, "pkthere");
    }

    #[test]
    fn render_repo_relative_path_falls_back_to_full_path_when_outside_repo() {
        let repo_root = Path::new("/repo");
        let outside = Path::new("/tmp/file.txt");
        assert_eq!(
            render_repo_relative_path(repo_root, outside),
            "/tmp/file.txt"
        );
    }
}
