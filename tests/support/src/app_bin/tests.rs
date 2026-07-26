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
    let current_exe = mock_path(&["/", "repo", "target", "debug", "deps", "integration-abc123"]);
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
    let current_exe = mock_path(&["/", "repo", "target", "debug", "deps", "integration-abc123"]);
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
    let path = std::env::temp_dir().join("pkthere");
    assert_eq!(
        path_policy::render_test_path(&path),
        path.to_string_lossy().replace('\\', "/")
    );
}
