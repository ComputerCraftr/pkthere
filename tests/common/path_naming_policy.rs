use pkthere_test_support::managed_child::{ChildIdentity, ChildLimits, ManagedChild};
use pkthere_test_support::timing::MAX_WAIT_SECS;

use std::path::{Component, Path};
use std::process::Command;
use std::time::Instant;

const CONVENTIONAL_FILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "Cross.toml",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "__init__.py",
];
const SOURCE_PATH_INVENTORY_ARGS: &[&str] = &["ls-files", "--cached", "-z"];

pub fn assert_source_paths_follow_naming_policy() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new("git");
    command
        .current_dir(repo_root)
        .args(SOURCE_PATH_INVENTORY_ARGS);
    let child = ManagedChild::spawn(
        &mut command,
        ChildIdentity::new("source path inventory"),
        ChildLimits::default(),
    )
    .expect("spawn source path inventory");
    let completed = child
        .wait_until(Instant::now() + MAX_WAIT_SECS)
        .expect("collect source path inventory");
    assert!(
        completed.exit.success,
        "git source path inventory failed: {}",
        String::from_utf8_lossy(&completed.output.stderr)
    );

    let mut violations = String::new();
    for raw_path in completed.output.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative =
            Path::new(std::str::from_utf8(raw_path).expect("repository paths must be valid UTF-8"));
        if !repo_root.join(relative).is_file() {
            continue;
        }
        for component in relative.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            let name = component
                .to_str()
                .expect("repository path components must be valid UTF-8");
            if name.starts_with('.') || CONVENTIONAL_FILE_NAMES.contains(&name) {
                continue;
            }
            let stem = Path::new(name)
                .file_stem()
                .and_then(|value| value.to_str())
                .expect("source path component stem");
            if !is_snake_case(stem) {
                violations.push_str(&format!(
                    "\n{}: component '{name}' must use snake_case",
                    relative.display()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "internal source paths must use snake_case; conventional ecosystem names are allowlisted:{violations}"
    );
}

fn is_snake_case(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::SOURCE_PATH_INVENTORY_ARGS;

    #[test]
    fn source_inventory_is_limited_to_committed_paths() {
        assert_eq!(
            SOURCE_PATH_INVENTORY_ARGS,
            ["ls-files", "--cached", "-z"],
            "runtime logs and other untracked outputs are not repository source"
        );
    }
}
