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
mod tests;
