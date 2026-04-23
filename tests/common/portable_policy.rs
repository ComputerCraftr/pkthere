use super::{WorkspaceInventory, build_surface_paths, read, relative};

const CROSS_COMMIT: &str = "88f49ff79e777bef6d3564531636ee4d3cc2f8d2";
const CROSS_IMAGE: &str = "ghcr.io/cross-rs/aarch64-unknown-linux-musl@sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83";

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

    let workflow_text = read(&inventory.repo_root.join(".github/workflows/rust.yml"));
    let workflow: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&workflow_text).expect("parse Rust workflow YAML");
    let job = workflow["jobs"]["aarch64-musl"]
        .as_mapping()
        .expect("aarch64-musl job");
    assert_eq!(
        job.get(serde_yaml_ng::Value::from("timeout-minutes"))
            .and_then(serde_yaml_ng::Value::as_u64),
        Some(30)
    );
    let runs = job
        .get(serde_yaml_ng::Value::from("steps"))
        .and_then(serde_yaml_ng::Value::as_sequence)
        .expect("aarch64-musl steps")
        .iter()
        .filter_map(|step| step.get("run").and_then(serde_yaml_ng::Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(runs.contains(CROSS_COMMIT));
    assert!(runs.contains("docker.alpine.portable_build aarch64"));
    assert!(workflow_text.contains("cargo check --locked"));

    let forbidden = build_surface_paths(inventory)
        .iter()
        .filter(|path| read(path).contains("target-cpu=native"))
        .map(|path| relative(&inventory.repo_root, path))
        .collect::<Vec<_>>();
    assert!(
        forbidden.is_empty(),
        "committed build surfaces must not select the build host CPU: {}",
        forbidden.join(", ")
    );

    let portable_builder = read(&inventory.repo_root.join("docker/alpine/portable_build.py"));
    for variable in [
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_*_RUSTFLAGS",
        "CARGO_TARGET_*_RUSTDOCFLAGS",
        "CARGO_TARGET_*_LINKER",
        "CARGO_TARGET_*_RUNNER",
        "HOST_CC",
        "TARGET_CC",
        "CC_*",
    ] {
        assert!(
            portable_builder.contains(variable),
            "portable sanitizer omits {variable}"
        );
    }

    for required in [
        "\"readelf\", \"-hW\"",
        "\"readelf\", \"-lW\"",
        "\"readelf\", \"-dW\"",
        "(NEEDED)",
        "INTERP",
    ] {
        assert!(
            portable_builder.contains(required),
            "ELF verifier omits {required}"
        );
    }

    assert!(
        portable_builder.contains("\"musl-gcc\"")
            && portable_builder.contains("cargo_executables")
            && portable_builder.contains("\"--locked\"")
    );
    assert!(
        portable_builder.contains("ghcr.io/cross-rs/aarch64-unknown-linux-musl@")
            && portable_builder.contains(
                "sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83"
            )
    );

    let container_builder = read(&inventory.repo_root.join("docker/rust_build/Dockerfile"));
    for required in [
        "BUILD_PROFILE=portable",
        "TARGET_CPU=generic",
        "portable builds require TARGET_CPU=generic",
        "cpu_tuned builds require an explicit non-generic TARGET_CPU",
        "target-feature=+crt-static",
        "cargo build --locked --release -p pkthere --bin pkthere",
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
