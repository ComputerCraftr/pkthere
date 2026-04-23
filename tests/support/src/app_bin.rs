use crate::test_paths as path_policy;

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
    workspace_root: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some(override_path) = env_map.get("TEST_APP_BIN") {
        let path = PathBuf::from(override_path);
        if exists(&path) {
            return Some(path);
        }
        if path.is_relative()
            && let Some(workspace_root) = workspace_root
        {
            let workspace_path = workspace_root.join(&path);
            if exists(&workspace_path) {
                return Some(workspace_path);
            }
        }
        // An explicit override is authoritative. Falling back to an
        // unprivileged profile binary silently changes RAW test semantics.
        return None;
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
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    resolve_app_bin_with(&env_map, current_exe, Some(&workspace_root), |path| {
        path.exists()
    })
    .map(|path| path.canonicalize().unwrap_or(path))
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
        workspace_root: Option<&Path>,
        existing: &[&Path],
    ) -> Option<PathBuf> {
        let env_map = env_pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();
        let existing = existing.iter().map(PathBuf::from).collect::<BTreeSet<_>>();

        resolve_app_bin_with(
            &env_map,
            current_exe.map(PathBuf::from),
            workspace_root,
            |path: &Path| existing.contains(path),
        )
    }

    #[test]
    fn prefers_test_app_bin_override() {
        let path = mock_path(&["/", "tmp", "custom-pkthere"]);
        let rendered = path_policy::render_test_path(&path);
        let found = resolve_with(
            &[("TEST_APP_BIN", &rendered)],
            None,
            None,
            &[path.as_path()],
        );
        assert_eq!(found.as_deref(), Some(path.as_path()));
    }

    #[test]
    fn resolves_relative_test_app_bin_from_workspace_root() {
        let workspace = mock_path(&["/", "repo"]);
        let relative = mock_path(&["target", "debug", "pkthere-priv"]);
        let absolute = workspace.join(&relative);
        let rendered = path_policy::render_test_path(&relative);
        let found = resolve_with(
            &[("TEST_APP_BIN", &rendered)],
            None,
            Some(&workspace),
            &[absolute.as_path()],
        );
        assert_eq!(found, Some(absolute));
    }

    #[test]
    fn missing_explicit_test_app_bin_does_not_fall_back() {
        let missing = mock_path(&["target", "debug", "missing-privileged"]);
        let fallback = mock_path(&["/", "repo", "target", "debug", "pkthere"]);
        let current_exe = mock_path(&["/", "repo", "target", "debug", "deps", "support-tests"]);
        let rendered = path_policy::render_test_path(&missing);
        let found = resolve_with(
            &[("TEST_APP_BIN", &rendered)],
            Some(&current_exe),
            Some(Path::new("/repo")),
            &[fallback.as_path()],
        );
        assert_eq!(found, None);
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
            None,
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
            None,
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
