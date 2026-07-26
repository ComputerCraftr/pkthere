# Testing procedures

Run source checks and ordinary tests from the repository root:

```text
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --test policy -- --nocapture
cargo test --locked --workspace --lib --bins --tests
```

Use the existing CI runner and Alpine entry points for platform and privileged
profiles. Test selection remains centralized in
`ci/pkthere_ci/test_manifest.py`.

## Local evidence

Machine-specific audits, command logs, capability measurements, hashes,
profiles, and release-closure overlays are local evidence. Write them below an
ignored artifact directory such as `.artifacts/`, `docker-artifacts/`,
`cross-artifacts/`, or `macos-profile-artifacts/`. Do not add those records to
source control: they can contain host paths, toolchain details, privilege
configuration, and other system-specific information.

Only reusable procedures and source-enforced invariants belong in the
repository. Before committing, verify that tracked files contain no generated
evidence:

```text
git status --short
git ls-files .artifacts docker-artifacts cross-artifacts macos-profile-artifacts
```
