use std::collections::BTreeMap;

use std::env;
use std::path::{Path, PathBuf};

const APP_BIN_NAME: &str = "pkthere";

fn with_ext(name: &str) -> String {
    if cfg!(windows) && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn alternate_profile(profile: &str) -> Option<&'static str> {
    match profile {
        "debug" => Some("release"),
        "release" => Some("debug"),
        _ => None,
    }
}

fn profile_candidates_from_current_exe(
    current_exe: &Path,
    exe_name: &str,
) -> impl Iterator<Item = PathBuf> {
    let mut candidates = Vec::new();

    if let Some(deps_dir) = current_exe.parent() {
        if deps_dir.file_name() == Some(std::ffi::OsStr::new("deps")) {
            if let Some(profile_dir) = deps_dir.parent() {
                candidates.push(profile_dir.join(exe_name));
                if let Some(profile) = profile_dir.file_name().and_then(|n| n.to_str()) {
                    if let Some(other) = alternate_profile(profile) {
                        if let Some(target_dir) = profile_dir.parent() {
                            candidates.push(target_dir.join(other).join(exe_name));
                        }
                    }
                }
            }
        }
    }

    candidates.into_iter()
}

fn resolve_app_bin_with(
    env_map: &BTreeMap<String, String>,
    current_exe: Option<PathBuf>,
    exists: impl Fn(&Path) -> bool,
) -> Option<String> {
    if let Some(override_path) = env_map.get("TEST_APP_BIN") {
        let path = PathBuf::from(override_path);
        if exists(&path) {
            return Some(path.to_string_lossy().to_string());
        }
    }

    let exe_name = with_ext(APP_BIN_NAME);
    let cargo_bin_key = format!("CARGO_BIN_EXE_{}", APP_BIN_NAME.replace('-', "_"));
    if let Some(exact_path) = env_map.get(&cargo_bin_key) {
        let path = PathBuf::from(exact_path);
        if exists(&path) {
            return Some(path.to_string_lossy().to_string());
        }
    }

    if let Some(current_exe) = current_exe {
        for candidate in profile_candidates_from_current_exe(&current_exe, &exe_name) {
            if exists(&candidate) {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    let target_dir = env_map
        .get("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env_map
                .get("CARGO_MANIFEST_DIR")
                .map(|dir| PathBuf::from(dir).join("target"))
        });

    if let Some(target_dir) = target_dir {
        let current_profile = env_map
            .get("PROFILE")
            .map(String::as_str)
            .filter(|profile| !profile.is_empty())
            .unwrap_or("debug");

        let mut profiles = vec![current_profile];
        if let Some(other) = alternate_profile(current_profile) {
            profiles.push(other);
        }

        for profile in profiles {
            let candidate = target_dir.join(profile).join(&exe_name);
            if exists(&candidate) {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    None
}

/// Locate the pkthere test binary for the current cargo invocation.
#[allow(dead_code)]
pub fn find_app_bin() -> Option<String> {
    let env_map = env::vars().collect::<BTreeMap<_, _>>();
    let current_exe = env::current_exe().ok();
    resolve_app_bin_with(&env_map, current_exe, |path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::{resolve_app_bin_with, with_ext};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn mock_path(parts: &[&str]) -> String {
        let mut p = PathBuf::new();
        for part in parts {
            p.push(part);
        }
        p.to_string_lossy().to_string()
    }

    fn resolve_with(
        env_pairs: &[(&str, &str)],
        current_exe: Option<&str>,
        existing: &[&str],
    ) -> Option<String> {
        let env_map = env_pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();
        let existing = existing.iter().map(PathBuf::from).collect::<BTreeSet<_>>();

        resolve_app_bin_with(&env_map, current_exe.map(PathBuf::from), |path: &Path| {
            existing.contains(path)
        })
    }

    #[test]
    fn prefers_test_app_bin_override() {
        let path = mock_path(&["/", "tmp", "custom-pkthere"]);
        let found = resolve_with(&[("TEST_APP_BIN", &path)], None, &[&path]);
        assert_eq!(found.as_deref(), Some(path.as_str()));
    }

    #[test]
    fn prefers_exact_cargo_bin_exe_for_pkthere() {
        let path = mock_path(&["/", "tmp", "pkthere"]);
        let other = mock_path(&["/", "tmp", "other"]);
        let found = resolve_with(
            &[
                ("CARGO_BIN_EXE_other", &other),
                ("CARGO_BIN_EXE_pkthere", &path),
            ],
            None,
            &[&other, &path],
        );
        assert_eq!(found.as_deref(), Some(path.as_str()));
    }

    #[test]
    fn prefers_current_profile_over_opposite_profile() {
        let bin = mock_path(&["/", "repo", "target", "debug", &with_ext("pkthere")]);
        let alt = mock_path(&["/", "repo", "target", "release", &with_ext("pkthere")]);
        let current_exe =
            mock_path(&["/", "repo", "target", "debug", "deps", "integration-abc123"]);
        let found = resolve_with(&[], Some(&current_exe), &[&alt, &bin]);
        assert_eq!(found, Some(bin));
    }

    #[test]
    fn ignores_non_matching_cargo_bin_candidates() {
        let bin = mock_path(&["/", "repo", "target", "debug", &with_ext("pkthere")]);
        let other = mock_path(&["/", "tmp", "other"]);
        let current_exe =
            mock_path(&["/", "repo", "target", "debug", "deps", "integration-abc123"]);
        let found = resolve_with(
            &[("CARGO_BIN_EXE_other", &other)],
            Some(&current_exe),
            &[&other, &bin],
        );
        assert_eq!(found, Some(bin));
    }

    #[test]
    fn falls_back_to_profile_env_before_opposite_profile() {
        let bin = mock_path(&["/", "repo", "target", "release", &with_ext("pkthere")]);
        let alt = mock_path(&["/", "repo", "target", "debug", &with_ext("pkthere")]);
        let target_dir = mock_path(&["/", "repo", "target"]);
        let found = resolve_with(
            &[("CARGO_TARGET_DIR", &target_dir), ("PROFILE", "release")],
            None,
            &[&alt, &bin],
        );
        assert_eq!(found, Some(bin));
    }
}
