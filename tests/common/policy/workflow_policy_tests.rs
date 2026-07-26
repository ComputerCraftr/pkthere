use serde_yaml_ng::Value;

use super::workflow_policy::{
    active_command_count, canonical_workflow_paths, unauthorized_process_count,
};

#[test]
fn alternate_hidden_and_reusable_workflows_fail_the_canonical_owner_invariant() {
    for alternate in [
        ".github/workflows/freebsd.yml",
        ".github/workflows/.disabled.yml",
        ".github/workflows/reusable.yaml",
    ] {
        assert_eq!(
            canonical_workflow_paths(&[".github/workflows/rust.yml", alternate]),
            Err("WORKFLOW-CANONICAL-OWNER-001")
        );
    }
}

#[test]
fn comments_and_literal_dead_steps_cannot_satisfy_executable_semantics() {
    let fixture: Value = serde_yaml_ng::from_str(
        r#"
jobs:
  test:
    steps:
      - run: |
          # required-command
          actual-command
      - if: false
        run: required-command
      - if: "false"
        run: required-command
"#,
    )
    .expect("parse workflow mutation fixture");
    assert_eq!(active_command_count(&fixture, "required-command"), 0);
    assert_eq!(active_command_count(&fixture, "actual-command"), 1);
}

#[test]
fn action_run_inputs_cannot_bypass_canonical_process_ownership() {
    let fixture: Value = serde_yaml_ng::from_str(
        r#"
jobs:
  test:
    steps:
      - uses: example/action@v1
        with:
          run: cargo test --workspace
      - uses: example/action@v1
        with:
          run: python3.13 -m ci.pkthere_ci platform-ci-vm
      - uses: example/action@v1
        with:
          prepare: pkg install -y rust
"#,
    )
    .expect("parse action-run fixture");
    assert_eq!(active_command_count(&fixture, "cargo test"), 1);
    assert_eq!(unauthorized_process_count(&fixture), 2);
}
