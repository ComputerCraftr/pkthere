use super::source_layout_policy;
use std::path::{Component, Path};

const CONVENTIONAL_FILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "Cross.toml",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "__init__.py",
    "__main__.py",
];
pub fn assert_source_paths_follow_naming_policy() {
    let repo_root = super::policy::repository_root();
    let mut violations = String::new();
    for absolute in source_layout_policy::tracked_repository_paths() {
        let relative = absolute
            .strip_prefix(&repo_root)
            .expect("tracked inventory path remains inside the repository");
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
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !value.as_bytes().windows(2).any(|pair| pair == b"__")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests;
