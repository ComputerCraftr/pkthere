use super::{WorkspaceInventory, read};

const CROSS_IMAGE: &str = "ghcr.io/cross-rs/aarch64-unknown-linux-musl@sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83";

pub(super) struct DockerfilePolicy {
    instructions: Vec<(String, String)>,
}

impl DockerfilePolicy {
    pub(super) fn parse(source: &str) -> Self {
        let mut instructions = Vec::new();
        let mut continued = String::new();
        for physical in source.lines() {
            let line = physical.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let continuation = line.ends_with('\\');
            let fragment = line.strip_suffix('\\').unwrap_or(line).trim_end();
            if !continued.is_empty() {
                continued.push(' ');
            }
            continued.push_str(fragment);
            if continuation {
                continue;
            }
            let (instruction, arguments) = continued
                .split_once(char::is_whitespace)
                .map_or((continued.as_str(), ""), |(instruction, arguments)| {
                    (instruction, arguments.trim_start())
                });
            instructions.push((instruction.to_ascii_uppercase(), arguments.to_string()));
            continued.clear();
        }
        if !continued.is_empty() {
            instructions.push((continued.to_ascii_uppercase(), String::new()));
        }
        Self { instructions }
    }

    pub(super) fn contains(&self, expected: &str) -> bool {
        self.instructions
            .iter()
            .any(|(instruction, arguments)| instruction == expected || arguments.contains(expected))
    }
}

pub(super) fn assert_configuration(inventory: &WorkspaceInventory) {
    assert!(
        !inventory.has_custom_build_target,
        "workspace build.rs targets are forbidden; runtime capabilities belong in reality tests"
    );

    let cargo_config: toml::Value =
        toml::from_str(&read(&inventory.repo_root.join(".cargo/config.toml")))
            .expect("parse .cargo/config.toml");
    let targets = cargo_config
        .get("target")
        .and_then(toml::Value::as_table)
        .expect("Cargo config target table");
    assert_eq!(
        targets.len(),
        1,
        "only the exact x86_64 musl linker is committed"
    );
    let x86 = targets
        .get("x86_64-unknown-linux-musl")
        .and_then(toml::Value::as_table)
        .expect("x86_64 musl target config");
    assert_eq!(x86.len(), 1);
    assert_eq!(
        x86.get("linker").and_then(toml::Value::as_str),
        Some("musl-gcc")
    );
    for manifest in &inventory.manifests {
        let parsed: toml::Value =
            toml::from_str(&read(manifest)).expect("parse workspace Cargo manifest");
        assert!(
            !toml_has_key(&parsed, "rustflags") && !toml_has_key(&parsed, "rustdocflags"),
            "workspace manifests must not commit target-specific compiler flags: {}",
            manifest.display()
        );
    }

    let cross: toml::Value =
        toml::from_str(&read(&inventory.repo_root.join("Cross.toml"))).expect("parse Cross.toml");
    assert_eq!(
        cross
            .get("target")
            .and_then(|value| value.get("aarch64-unknown-linux-musl"))
            .and_then(|value| value.get("image"))
            .and_then(toml::Value::as_str),
        Some(CROSS_IMAGE)
    );

    let workflow: serde_yaml_ng::Value = serde_yaml_ng::from_str(&read(
        &inventory.repo_root.join(".github/workflows/rust.yml"),
    ))
    .expect("parse Rust workflow YAML");
    let job = workflow["jobs"]["aarch64-musl"]
        .as_mapping()
        .expect("aarch64-musl job");
    assert_eq!(
        job.get(serde_yaml_ng::Value::from("timeout-minutes"))
            .and_then(serde_yaml_ng::Value::as_u64),
        Some(30)
    );
    assert_eq!(
        super::workflow_policy::active_command_count(&workflow, "ci.pkthere_ci aarch64-musl"),
        1,
        "AArch64 artifact construction must use the canonical CI command plan"
    );
    assert!(
        super::workflow_policy::active_command_count(&workflow, "ci.pkthere_ci msrv") == 1,
        "MSRV verification must use the canonical CI command plan"
    );

    let native_builder = DockerfilePolicy::parse(&read(
        &inventory
            .repo_root
            .join("docker/alpine/portable_builder.Dockerfile"),
    ));
    assert!(
        native_builder.contains(
            "rust:1.97.1-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900"
        ),
        "native AArch64 builder must pin the workspace MSRV toolchain image"
    );
    assert!(
        native_builder.contains("target=/usr/local/cargo/registry")
            && native_builder.contains("target=/usr/local/cargo/git")
            && native_builder.contains("target=/workspace/target"),
        "native AArch64 builder must preserve the official Rust image caches"
    );
    let container_builder = DockerfilePolicy::parse(&read(
        &inventory.repo_root.join("docker/rust_build/Dockerfile"),
    ));
    for required in [
        "rust:1.97.1-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900",
        "BUILD_PROFILE=portable",
        "TARGET_CPU=generic",
        "portable builds require TARGET_CPU=generic",
        "cpu_tuned builds require an explicit non-generic TARGET_CPU",
        "target-feature=+crt-static",
        "cargo build --locked --release --target",
        "aarch64-unknown-linux-musl",
        "x86_64-unknown-linux-musl",
        "target=/usr/local/cargo/registry",
        "target=/usr/local/cargo/git",
        "readelf -hW",
        "readelf -lW",
        "readelf -dW",
        "(NEEDED)",
        "INTERP",
    ] {
        assert!(
            container_builder.contains(required),
            "container musl builder omits {required}"
        );
    }
    for forbidden in [
        "docker.alpine.portable_build",
        "alpine_test_builder",
        "alpine_test_export",
        "/artifacts/alpine",
    ] {
        assert!(
            !container_builder.contains(forbidden),
            "CPU-tuned application builder must not duplicate portable test-artifact authority: {forbidden}"
        );
    }

    let native_adapter = DockerfilePolicy::parse(&read(
        &inventory
            .repo_root
            .join("docker/alpine/portable_builder.Dockerfile"),
    ));
    assert!(native_adapter.contains("docker.alpine.portable_build"));
    assert!(native_adapter.contains("PORTABLE_ARCHITECTURE"));
    assert!(native_adapter.contains("--backend native-container"));
    assert!(
        !native_adapter.contains("cargo build") && !native_adapter.contains("cargo test"),
        "native AArch64 adapter must delegate artifact inventory to portable_build.py"
    );

    for retired in [
        "build-aarch64-musl.sh",
        "build-x86_64-musl-artifacts.sh",
        "portable-build-env.sh",
        "verify-static-musl-elf.sh",
        "build_artifacts.py",
    ] {
        assert!(
            !inventory
                .repo_root
                .join(".github/scripts")
                .join(retired)
                .exists()
                && !inventory
                    .repo_root
                    .join("docker/alpine")
                    .join(retired)
                    .exists(),
            "retired duplicate portable builder returned: {retired}"
        );
    }
}

fn toml_has_key(value: &toml::Value, expected: &str) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            toml::Value::Table(table) => {
                if table.contains_key(expected) {
                    return true;
                }
                pending.extend(table.values());
            }
            toml::Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    false
}
