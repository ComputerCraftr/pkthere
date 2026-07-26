# Source layout policy

Repository policy derives one null-delimited inventory from the tracked Git
index. It governs Rust, Python, shell files, and extensionless scripts whose
shebang selects a supported Python or shell interpreter. Generated outputs,
local evidence, and ignored artifacts are not release source.

Every governed file is limited to 1,000 physical lines. Rust functions are
limited to 300 physical lines and structs to 24 fields. There is no minimum
file size and no module-count target; cohesion and sibling fan-out remain code
review concerns.

Rust modules use ordinary module resolution, stay within their Cargo-owned
source root, and use no more than two module directories below that root.
`lib.rs` and `mod.rs` are semantic facades: documentation, attributes,
bodyless module declarations, imports/re-exports, `extern crate`, and type
aliases are permitted; implementation-bearing items are rejected.

## Move procedure

Before moving source, record all occurrences of:

- `module_path!`, `file!`, `include_str!`, and `include_bytes!`;
- restricted visibility paths, `$crate`, and `type_name`;
- intra-doc links, snapshots, golden files, and data paths;
- Cargo target paths and exact test filters;
- Python imports and shell source paths;
- CI or script references to exact filenames.

For each occurrence, record the old path, semantic dependency, destination,
required edit, and validation. Keep candidate-specific results in ignored
artifacts; only this reusable procedure belongs in the repository.

After each cohesive move, run formatting, workspace checks, Clippy, focused
tests, and the repository policy test. After a completed migration, run the
full platform suite because module movement can alter target discovery and
conditional compilation even when the local build succeeds.
