#[path = "path_policy.rs"]
mod path_policy;

use std::collections::BTreeMap;

use std::env;
use std::path::{Path, PathBuf};

const APP_BIN_NAME: &str = "pkthere";

fn alternate_profile(profile: &str) -> Option<&'static str> {
    match profile {
        "debug" => Some("release"),
        "release" => Some("debug"),
        _ => None,
    }
}

fn profile_candidates_from_current_exe(
    current_exe: &Path,
    exe_name: &Path,
) -> impl Iterator<Item = PathBuf> {
    let mut candidates = Vec::new();

    if let Some(deps_dir) = current_exe.parent()
        && deps_dir.file_name() == Some(std::ffi::OsStr::new("deps"))
        && let Some(profile_dir) = deps_dir.parent()
    {
        candidates.push(profile_dir.join(exe_name));
        if let Some(profile) = profile_dir.file_name().and_then(|n| n.to_str())
            && let Some(other) = alternate_profile(profile)
            && let Some(target_dir) = profile_dir.parent()
        {
            candidates.push(target_dir.join(other).join(exe_name));
        }
    }

    candidates.into_iter()
}

fn resolve_app_bin_with(
    env_map: &BTreeMap<String, String>,
    current_exe: Option<PathBuf>,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some(override_path) = env_map.get("TEST_APP_BIN") {
        let path = PathBuf::from(override_path);
        if exists(&path) {
            return Some(path);
        }
    }

    let exe_name = PathBuf::from(path_policy::platform_executable_name(APP_BIN_NAME));
    let cargo_bin_key = format!("CARGO_BIN_EXE_{}", APP_BIN_NAME.replace('-', "_"));
    if let Some(exact_path) = env_map.get(&cargo_bin_key) {
        let path = PathBuf::from(exact_path);
        if exists(&path) {
            return Some(path);
        }
    }

    if let Some(current_exe) = current_exe {
        for candidate in profile_candidates_from_current_exe(&current_exe, &exe_name) {
            if exists(&candidate) {
                return Some(candidate);
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
                return Some(candidate);
            }
        }
    }

    None
}

/// Locate the pkthere test binary for the current cargo invocation.
pub fn find_app_bin() -> Option<PathBuf> {
    let env_map = env::vars().collect::<BTreeMap<_, _>>();
    let current_exe = env::current_exe().ok();
    resolve_app_bin_with(&env_map, current_exe, |path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::{path_policy, resolve_app_bin_with};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn mock_path(parts: &[&str]) -> PathBuf {
        path_policy::join_test_path(parts)
    }

    fn resolve_with(
        env_pairs: &[(&str, &str)],
        current_exe: Option<&Path>,
        existing: &[&Path],
    ) -> Option<PathBuf> {
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
        let rendered = path_policy::render_test_path(&path);
        let found = resolve_with(&[("TEST_APP_BIN", &rendered)], None, &[path.as_path()]);
        assert_eq!(found.as_deref(), Some(path.as_path()));
    }

    #[test]
    fn prefers_exact_cargo_bin_exe_for_pkthere() {
        let path = mock_path(&["/", "tmp", "pkthere"]);
        let other = mock_path(&["/", "tmp", "other"]);
        let other_rendered = path_policy::render_test_path(&other);
        let path_rendered = path_policy::render_test_path(&path);
        let found = resolve_with(
            &[
                ("CARGO_BIN_EXE_other", &other_rendered),
                ("CARGO_BIN_EXE_pkthere", &path_rendered),
            ],
            None,
            &[other.as_path(), path.as_path()],
        );
        assert_eq!(found.as_deref(), Some(path.as_path()));
    }

    #[test]
    fn prefers_current_profile_over_opposite_profile() {
        let exe_name = PathBuf::from(path_policy::platform_executable_name("pkthere"));
        let bin = mock_path(&["/", "repo", "target", "debug"]).join(&exe_name);
        let alt = mock_path(&["/", "repo", "target", "release"]).join(&exe_name);
        let current_exe =
            mock_path(&["/", "repo", "target", "debug", "deps", "integration-abc123"]);
        let found = resolve_with(
            &[],
            Some(current_exe.as_path()),
            &[alt.as_path(), bin.as_path()],
        );
        assert_eq!(found, Some(bin));
    }

    #[test]
    fn ignores_non_matching_cargo_bin_candidates() {
        let exe_name = PathBuf::from(path_policy::platform_executable_name("pkthere"));
        let bin = mock_path(&["/", "repo", "target", "debug"]).join(&exe_name);
        let other = mock_path(&["/", "tmp", "other"]);
        let current_exe =
            mock_path(&["/", "repo", "target", "debug", "deps", "integration-abc123"]);
        let other_rendered = path_policy::render_test_path(&other);
        let found = resolve_with(
            &[("CARGO_BIN_EXE_other", &other_rendered)],
            Some(current_exe.as_path()),
            &[other.as_path(), bin.as_path()],
        );
        assert_eq!(found, Some(bin));
    }

    #[test]
    fn falls_back_to_profile_env_before_opposite_profile() {
        let exe_name = PathBuf::from(path_policy::platform_executable_name("pkthere"));
        let bin = mock_path(&["/", "repo", "target", "release"]).join(&exe_name);
        let alt = mock_path(&["/", "repo", "target", "debug"]).join(&exe_name);
        let target_dir = mock_path(&["/", "repo", "target"]);
        let target_dir_rendered = path_policy::render_test_path(&target_dir);
        let found = resolve_with(
            &[
                ("CARGO_TARGET_DIR", &target_dir_rendered),
                ("PROFILE", "release"),
            ],
            None,
            &[alt.as_path(), bin.as_path()],
        );
        assert_eq!(found, Some(bin));
    }

    #[test]
    fn renders_paths_for_diagnostics_through_shared_policy() {
        let path = mock_path(&["/", "tmp", "pkthere"]);
        assert_eq!(path_policy::render_test_path(&path), "/tmp/pkthere");
    }
}
