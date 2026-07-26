use pkthere_test_support::managed_child::{ChildIdentity, ChildLimits, ManagedChild};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use syn::spanned::Spanned;
use syn::visit::Visit;

const MAX_FILE_LINES: usize = 1_000;
const MAX_FUNCTION_LINES: usize = 300;
const MAX_STRUCT_FIELDS: usize = 24;
const MAX_COMMAND_WAIT: Duration = pkthere_test_support::timing::MAX_WAIT_SECS;
const LFS_POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/v1";
const GOVERNED_EXTENSIONS: &[&str] = &["rs", "py", "pyi", "sh", "bash", "dash", "ksh", "zsh"];
const SCRIPT_INTERPRETERS: &[&str] = &["python", "python3", "sh", "bash", "dash", "ksh", "zsh"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceKind {
    Rust,
    Python,
    Shell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustSourceClass {
    Src,
    Tests,
    Benches,
    Examples,
    Build,
}

#[derive(Clone, Debug)]
struct TrackedEntry {
    relative: PathBuf,
    absolute: PathBuf,
    kind: SourceKind,
    bytes: Vec<u8>,
}

struct TrackedInventory {
    entries: Vec<TrackedEntry>,
    regular_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
struct PackageRecord {
    root: PathBuf,
    edition: String,
    targets: Vec<TargetRecord>,
}

#[derive(Clone, Debug)]
struct TargetRecord {
    source: PathBuf,
    kinds: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct RustOwnership {
    package_root: PathBuf,
    source_root: PathBuf,
    class: RustSourceClass,
    edition: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LayoutViolation {
    path: PathBuf,
    detail: String,
}

impl LayoutViolation {
    pub(super) fn render(&self) -> String {
        format!("{}: {}", self.path.display(), self.detail)
    }
}

mod fixtures;
pub(crate) use fixtures::assert_engine_fixtures;

pub(super) fn repository_violations() -> Vec<LayoutViolation> {
    let root = repository_root();
    let mut violations = Vec::new();
    let entries = tracked_inventory(&root, &mut violations).entries;
    let governed_paths = entries
        .iter()
        .map(|entry| entry.relative.clone())
        .collect::<BTreeSet<_>>();
    let packages = cargo_packages(&root, &mut violations);
    let tracked_rust = entries
        .iter()
        .filter(|entry| entry.kind == SourceKind::Rust)
        .map(|entry| entry.absolute.clone())
        .collect::<BTreeSet<_>>();
    let mut reachable = BTreeSet::new();

    for entry in &entries {
        let display = entry.relative.to_string_lossy();
        let lines = physical_line_count(&entry.bytes);
        if lines > MAX_FILE_LINES {
            violations.push(violation(
                &entry.relative,
                format!("has {lines} physical lines; maximum is {MAX_FILE_LINES}"),
            ));
        }
        if entry.kind != SourceKind::Rust {
            if entry.kind == SourceKind::Shell {
                match std::str::from_utf8(&entry.bytes) {
                    Ok(source) => violations.extend(shell_source_violations(
                        &entry.relative,
                        source,
                        &governed_paths,
                    )),
                    Err(error) => violations
                        .push(violation(&entry.relative, format!("is not UTF-8: {error}"))),
                }
            }
            continue;
        }
        let source = match std::str::from_utf8(&entry.bytes) {
            Ok(source) => source,
            Err(error) => {
                violations.push(violation(&entry.relative, format!("is not UTF-8: {error}")));
                continue;
            }
        };
        let syntax = match syn::parse_file(source) {
            Ok(syntax) => syntax,
            Err(error) => {
                violations.push(violation(
                    &entry.relative,
                    format!("is not a complete Rust source file: {error}"),
                ));
                continue;
            }
        };
        let Some(owner) = rust_owner(&entry.absolute, &packages, &mut violations) else {
            continue;
        };
        let depth = module_directory_depth(&entry.absolute, &owner.source_root);
        if depth > 2 {
            violations.push(violation(
                &entry.relative,
                format!("has module-directory depth {depth}; maximum is 2"),
            ));
        }
        if matches!(
            entry.absolute.file_name().and_then(|name| name.to_str()),
            Some("lib.rs" | "mod.rs")
        ) {
            violations.extend(
                facade_violations(&display, source)
                    .into_iter()
                    .map(|detail| violation(&entry.relative, detail)),
            );
        }
        violations.extend(
            function_violations(&display, source)
                .into_iter()
                .map(|detail| violation(&entry.relative, detail)),
        );
        violations.extend(
            struct_violations(&display, &syntax)
                .into_iter()
                .map(|detail| violation(&entry.relative, detail)),
        );
        violations.extend(
            module_bypass_violations(&display, &syntax)
                .into_iter()
                .map(|detail| violation(&entry.relative, detail)),
        );
        let _ = (&owner.package_root, owner.class, &owner.edition);
    }

    for package in &packages {
        for target in &package.targets {
            walk_module_graph(
                &root,
                &target.source,
                target.source.parent().unwrap_or(&package.root),
                &tracked_rust,
                &mut reachable,
                &mut violations,
            );
        }
    }
    for source in tracked_rust.difference(&reachable) {
        violations.push(violation(
            source.strip_prefix(&root).unwrap_or(source),
            "is not reachable through ordinary module resolution".to_string(),
        ));
    }
    violations.sort_by(|left, right| (&left.path, &left.detail).cmp(&(&right.path, &right.detail)));
    violations.dedup();
    violations
}

pub(super) fn assert_repository_valid() {
    let violations = repository_violations();
    assert!(
        violations.is_empty(),
        "repository-wide source layout and complexity violations:\n{}",
        violations
            .iter()
            .map(LayoutViolation::render)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

pub(super) fn governed_source_paths(kind: Option<SourceKind>) -> Vec<PathBuf> {
    let root = repository_root();
    let mut violations = Vec::new();
    let inventory = tracked_inventory(&root, &mut violations);
    assert!(
        violations.is_empty(),
        "tracked source inventory is invalid: {violations:?}"
    );
    inventory
        .entries
        .into_iter()
        .filter(|entry| kind.is_none_or(|expected| entry.kind == expected))
        .map(|entry| entry.absolute)
        .collect()
}

pub(super) fn rust_source_paths_under(roots: &[PathBuf]) -> Vec<PathBuf> {
    governed_source_paths(Some(SourceKind::Rust))
        .into_iter()
        .filter(|source| roots.iter().any(|root| source.starts_with(root)))
        .collect()
}

pub(super) fn production_rust_source_paths_under(roots: &[PathBuf]) -> Vec<PathBuf> {
    rust_source_paths_under(roots)
        .into_iter()
        .filter(|path| {
            !path.components().any(|component| {
                matches!(
                    component.as_os_str().to_str(),
                    Some("tests" | "benches" | "examples")
                )
            }) && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    matches!(name, "tests.rs" | "test_support.rs") || name.ends_with("_tests.rs")
                })
        })
        .filter(|path| {
            let source = fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let syntax = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
            !crate::common::rust_semantics::attrs_are_test_context(&syntax.attrs)
        })
        .collect()
}

pub(super) fn tracked_repository_paths() -> Vec<PathBuf> {
    let root = repository_root();
    let mut violations = Vec::new();
    let inventory = tracked_inventory(&root, &mut violations);
    assert!(
        violations.is_empty(),
        "tracked source inventory is invalid: {violations:?}"
    );
    inventory.regular_paths
}

fn tracked_inventory(root: &Path, violations: &mut Vec<LayoutViolation>) -> TrackedInventory {
    let deleted = bounded_output(
        root,
        "git candidate source deletions",
        &["diff", "--name-only", "--diff-filter=D", "-z"],
    )
    .split(|byte| *byte == 0)
    .filter(|path| !path.is_empty())
    .filter_map(|path| std::str::from_utf8(path).ok().map(PathBuf::from))
    .collect::<BTreeSet<_>>();
    let output = bounded_output(
        root,
        "git candidate source inventory",
        &[
            "ls-files",
            "-z",
            "-s",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    );
    let mut entries = Vec::new();
    let mut regular_paths = Vec::new();
    let mut folded = BTreeMap::<String, PathBuf>::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let (mode, path_bytes) = if let Some(tab) = record.iter().position(|byte| *byte == b'\t') {
            let header = String::from_utf8_lossy(&record[..tab]);
            let mut fields = header.split_ascii_whitespace();
            let mode = fields
                .next()
                .and_then(|value| u32::from_str_radix(value, 8).ok())
                .unwrap_or_default();
            (mode, &record[tab + 1..])
        } else {
            // `--stage --others` emits index metadata for tracked entries and
            // bare NUL-delimited paths for non-ignored untracked entries.
            (0o100644, record)
        };
        let relative = match std::str::from_utf8(path_bytes) {
            Ok(path) => PathBuf::from(path),
            Err(error) => {
                violations.push(violation(
                    Path::new("<git-index>"),
                    format!("non-UTF-8 tracked path: {error}"),
                ));
                continue;
            }
        };
        if deleted.contains(&relative) {
            continue;
        }
        if mode == 0o160000 {
            violations.push(violation(
                &relative,
                "gitlinks/submodules are prohibited".to_string(),
            ));
            continue;
        }
        let absolute = root.join(&relative);
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) => {
                violations.push(violation(
                    &relative,
                    format!("tracked path is unreadable: {error}"),
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || mode == 0o120000 {
            if governed_kind_from_extension(&relative).is_some() {
                violations.push(violation(
                    &relative,
                    "governed source symlinks are prohibited".to_string(),
                ));
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let path_text = relative.to_string_lossy();
        if !path_text.is_ascii()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            violations.push(violation(
                &relative,
                "source path must be relative, normalized ASCII".to_string(),
            ));
            continue;
        }
        regular_paths.push(absolute.clone());
        let bytes = match fs::read(&absolute) {
            Ok(bytes) => bytes,
            Err(error) => {
                violations.push(violation(&relative, format!("cannot read source: {error}")));
                continue;
            }
        };
        let Some(kind) = governed_kind(&relative, &bytes) else {
            continue;
        };
        if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
            violations.push(violation(&relative, "UTF-8 BOM is prohibited".to_string()));
        }
        if bytes.starts_with(LFS_POINTER_PREFIX) {
            violations.push(violation(
                &relative,
                "Git LFS pointers are prohibited for governed source".to_string(),
            ));
        }
        let folded_path = path_text.to_ascii_lowercase();
        if let Some(previous) = folded.insert(folded_path, relative.clone()) {
            violations.push(violation(
                &relative,
                format!("case-folded path collides with {}", previous.display()),
            ));
        }
        entries.push(TrackedEntry {
            relative,
            absolute,
            kind,
            bytes,
        });
    }
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    for path in lfs_filter_paths(root, &entries) {
        violations.push(violation(
            &path,
            "filter=lfs is prohibited for governed source".to_string(),
        ));
    }
    regular_paths.sort();
    TrackedInventory {
        entries,
        regular_paths,
    }
}

fn lfs_filter_paths(root: &Path, entries: &[TrackedEntry]) -> Vec<PathBuf> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args(["check-attr", "-z", "filter", "--"])
        .args(entries.iter().map(|entry| &entry.relative));
    let output = bounded_command_output(command, "git LFS source attributes");
    let fields = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    fields
        .chunks_exact(3)
        .filter_map(|record| {
            (record[1] == b"filter" && record[2] == b"lfs")
                .then(|| std::str::from_utf8(record[0]).ok().map(PathBuf::from))
                .flatten()
        })
        .collect()
}

fn cargo_packages(root: &Path, violations: &mut Vec<LayoutViolation>) -> Vec<PackageRecord> {
    let output = bounded_output(
        root,
        "cargo metadata",
        &["metadata", "--locked", "--format-version", "1", "--no-deps"],
    );
    let metadata: JsonValue = match serde_json::from_slice(&output) {
        Ok(value) => value,
        Err(error) => {
            violations.push(violation(
                Path::new("Cargo.toml"),
                format!("invalid cargo metadata: {error}"),
            ));
            return Vec::new();
        }
    };
    let members = metadata["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .collect::<BTreeSet<_>>();
    let mut packages = Vec::new();
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let Some(id) = package["id"].as_str() else {
            continue;
        };
        if !members.contains(id) {
            continue;
        }
        let Some(manifest) = package["manifest_path"].as_str() else {
            continue;
        };
        let Some(package_root) = Path::new(manifest).parent() else {
            continue;
        };
        let root_path = match package_root.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                violations.push(violation(
                    Path::new(manifest),
                    format!("cannot canonicalize workspace package root: {error}"),
                ));
                continue;
            }
        };
        let edition = package["edition"].as_str().unwrap_or("2024").to_string();
        let targets = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|target| {
                let source = PathBuf::from(target["src_path"].as_str()?)
                    .canonicalize()
                    .ok()?;
                let kinds = target["kind"]
                    .as_array()?
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_string)
                    .collect();
                Some(TargetRecord { source, kinds })
            })
            .collect();
        if !root_path.starts_with(root) {
            violations.push(violation(
                Path::new(manifest),
                "workspace package escapes repository".to_string(),
            ));
            continue;
        }
        packages.push(PackageRecord {
            root: root_path,
            edition,
            targets,
        });
    }
    packages.sort_by(|left, right| left.root.cmp(&right.root));
    packages
}

fn rust_owner(
    path: &Path,
    packages: &[PackageRecord],
    violations: &mut Vec<LayoutViolation>,
) -> Option<RustOwnership> {
    let mut owners = packages
        .iter()
        .filter(|package| path.starts_with(&package.root))
        .collect::<Vec<_>>();
    owners.sort_by_key(|package| std::cmp::Reverse(package.root.components().count()));
    let owner = owners.first().copied();
    if owners.get(1).is_some_and(|other| {
        other.root.components().count() == owner.map_or(0, |item| item.root.components().count())
    }) {
        violations.push(violation(
            path,
            "has ambiguous nearest package ownership".to_string(),
        ));
        return None;
    }
    let Some(package) = owner else {
        violations.push(violation(
            path,
            "belongs to no workspace package".to_string(),
        ));
        return None;
    };
    let relative = path.strip_prefix(&package.root).ok()?;
    let first = relative.components().next()?.as_os_str().to_str()?;
    let (class, source_root) = match first {
        "src" => (RustSourceClass::Src, package.root.join("src")),
        "tests" => (RustSourceClass::Tests, package.root.join("tests")),
        "benches" => (RustSourceClass::Benches, package.root.join("benches")),
        "examples" => (RustSourceClass::Examples, package.root.join("examples")),
        "build.rs" if relative.components().count() == 1 => {
            (RustSourceClass::Build, package.root.clone())
        }
        "build_support"
            if package
                .targets
                .iter()
                .any(|target| target.kinds.contains("custom-build")) =>
        {
            (RustSourceClass::Build, package.root.clone())
        }
        _ => {
            violations.push(violation(
                path,
                "is outside src/tests/benches/examples/build-script roots".to_string(),
            ));
            return None;
        }
    };
    Some(RustOwnership {
        package_root: package.root.clone(),
        source_root,
        class,
        edition: package.edition.clone(),
    })
}

fn walk_module_graph(
    root: &Path,
    source: &Path,
    search: &Path,
    tracked: &BTreeSet<PathBuf>,
    reachable: &mut BTreeSet<PathBuf>,
    violations: &mut Vec<LayoutViolation>,
) {
    let mut pending_files = vec![(source.to_path_buf(), search.to_path_buf())];
    while let Some((current_source, current_search)) = pending_files.pop() {
        if !tracked.contains(&current_source) || !reachable.insert(current_source.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&current_source) else {
            continue;
        };
        let Ok(file) = syn::parse_file(&text) else {
            continue;
        };
        let mut pending_items = vec![(&file.items[..], current_search)];
        while let Some((items, item_search)) = pending_items.pop() {
            for item in items {
                let syn::Item::Mod(module) = item else {
                    continue;
                };
                let stem = module.ident.to_string();
                let child_search = item_search.join(&stem);
                if let Some((_, nested_items)) = &module.content {
                    pending_items.push((nested_items, child_search));
                    continue;
                }
                let flat = item_search.join(format!("{stem}.rs"));
                let nested = child_search.join("mod.rs");
                match (flat.is_file(), nested.is_file()) {
                    (true, true) => violations.push(violation(
                        flat.strip_prefix(root).unwrap_or(&flat),
                        format!("module {stem} has both file and mod.rs forms"),
                    )),
                    (true, false) => pending_files.push((flat, child_search)),
                    (false, true) => pending_files.push((nested, child_search)),
                    (false, false) => violations.push(violation(
                        item_search.strip_prefix(root).unwrap_or(&item_search),
                        format!("module {stem} has no ordinary-resolution source"),
                    )),
                }
            }
        }
    }
}

fn facade_violations(path: &str, source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => return vec![format!("cannot parse facade {path}: {error}")],
    };
    file.items
        .iter()
        .filter_map(|item| {
            let allowed = matches!(
                item,
                syn::Item::Use(_)
                    | syn::Item::ExternCrate(_)
                    | syn::Item::Type(_)
                    | syn::Item::Mod(syn::ItemMod { content: None, .. })
            );
            (!allowed).then(|| {
                format!(
                    "default-deny facade rejects {} at byte {}",
                    item_kind(item),
                    item.span().byte_range().start
                )
            })
        })
        .collect()
}

fn function_violations(path: &str, source: &str) -> Vec<String> {
    let Ok(file) = syn::parse_file(source) else {
        return Vec::new();
    };
    let mut visitor = FunctionLengthVisitor {
        path,
        source,
        violations: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.violations
}

struct FunctionLengthVisitor<'a> {
    path: &'a str,
    source: &'a str,
    violations: Vec<String>,
}

impl FunctionLengthVisitor<'_> {
    fn check(&mut self, name: &syn::Ident, attrs: &[syn::Attribute], span: proc_macro2::Span) {
        let mut range = span.byte_range();
        if let Some(start) = attrs
            .iter()
            .map(|attr| attr.span().byte_range().start)
            .min()
        {
            range.start = range.start.min(start);
        }
        let Some(bytes) = self.source.as_bytes().get(range.clone()) else {
            return;
        };
        let lines = physical_line_count(bytes);
        if lines > MAX_FUNCTION_LINES {
            self.violations.push(format!(
                "{} function {name} has {lines} physical lines",
                self.path
            ));
        }
    }
}

impl<'ast> Visit<'ast> for FunctionLengthVisitor<'_> {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.check(&item.sig.ident, &item.attrs, item.span());
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.check(&item.sig.ident, &item.attrs, item.span());
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if item.default.is_some() {
            self.check(&item.sig.ident, &item.attrs, item.span());
        }
        syn::visit::visit_trait_item_fn(self, item);
    }
}

pub(super) fn struct_violations(path: &str, file: &syn::File) -> Vec<String> {
    struct Visitor<'a> {
        path: &'a str,
        violations: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if item.fields.len() > MAX_STRUCT_FIELDS {
                self.violations.push(format!(
                    "{} struct {} has {} fields",
                    self.path,
                    item.ident,
                    item.fields.len()
                ));
            }
            syn::visit::visit_item_struct(self, item);
        }

        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            for variant in &item.variants {
                if variant.fields.len() > MAX_STRUCT_FIELDS {
                    self.violations.push(format!(
                        "{} enum {}::{} has {} fields",
                        self.path,
                        item.ident,
                        variant.ident,
                        variant.fields.len()
                    ));
                }
            }
            syn::visit::visit_item_enum(self, item);
        }
    }
    let mut visitor = Visitor {
        path,
        violations: Vec::new(),
    };
    visitor.visit_file(file);
    visitor.violations
}

fn module_bypass_violations(path: &str, file: &syn::File) -> Vec<String> {
    struct Visitor<'a> {
        path: &'a str,
        violations: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Visitor<'_> {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.attrs.iter().any(|attr| attr.path().is_ident("path")) {
                self.violations.push(format!(
                    "{} uses prohibited #[path] module indirection",
                    self.path
                ));
            }
            if item.content.is_some() {
                self.violations.push(format!(
                    "{} uses an inline module instead of ordinary module resolution",
                    self.path
                ));
            }
            syn::visit::visit_item_mod(self, item);
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("include") {
                self.violations
                    .push(format!("{} uses prohibited Rust include!", self.path));
            }
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut visitor = Visitor {
        path,
        violations: Vec::new(),
    };
    visitor.visit_file(file);
    visitor.violations
}

fn governed_kind(path: &Path, bytes: &[u8]) -> Option<SourceKind> {
    governed_kind_from_extension(path).or_else(|| {
        path.extension()
            .is_none()
            .then(|| shebang_kind(bytes))
            .flatten()
    })
}

fn governed_kind_from_extension(path: &Path) -> Option<SourceKind> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rs") => Some(SourceKind::Rust),
        Some("py" | "pyi") => Some(SourceKind::Python),
        Some("sh" | "bash" | "dash" | "ksh" | "zsh") => Some(SourceKind::Shell),
        Some(extension) if GOVERNED_EXTENSIONS.contains(&extension) => unreachable!(),
        None => None,
        _ => None,
    }
}

fn shebang_kind(bytes: &[u8]) -> Option<SourceKind> {
    let first = bytes.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(first).ok()?.strip_prefix("#!")?.trim();
    let mut words = line.split_ascii_whitespace();
    let executable = Path::new(words.next()?).file_name()?.to_str()?;
    let interpreter = if executable == "env" {
        let mut next = words.next()?;
        if next == "-S" {
            next = words.next()?;
        }
        Path::new(next).file_name()?.to_str()?
    } else {
        executable
    };
    if !SCRIPT_INTERPRETERS.contains(&interpreter) {
        return None;
    }
    if interpreter.starts_with("python") {
        Some(SourceKind::Python)
    } else {
        Some(SourceKind::Shell)
    }
}

fn shell_source_violations(
    path: &Path,
    source: &str,
    governed: &BTreeSet<PathBuf>,
) -> Vec<LayoutViolation> {
    let mut violations = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let command = line.trim_start();
        let argument = command
            .strip_prefix("source ")
            .or_else(|| command.strip_prefix(". "));
        let Some(argument) = argument else {
            continue;
        };
        let token = argument
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .trim_matches(['\'', '"']);
        if token.is_empty()
            || token.contains(['$', '`', '*', '?', '[', ']'])
            || argument.trim_start().starts_with("$(")
        {
            violations.push(violation(
                path,
                format!("line {} uses a dynamic shell source path", line_index + 1),
            ));
            continue;
        }
        let resolved = lexical_normalize(path.parent().unwrap_or(Path::new("")).join(token));
        let shell_extension = resolved
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "sh" | "bash" | "dash" | "ksh" | "zsh"));
        if !shell_extension || !governed.contains(&resolved) {
            violations.push(violation(
                path,
                format!(
                    "line {} sources untracked or ungoverned {}",
                    line_index + 1,
                    resolved.display()
                ),
            ));
        }
    }
    violations
}

fn lexical_normalize(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
            Component::Prefix(_) | Component::RootDir => return path,
        }
    }
    normalized
}

fn physical_line_count(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let lf = bytes.iter().filter(|byte| **byte == b'\n').count();
    lf + usize::from(bytes.last() != Some(&b'\n'))
}

fn module_directory_depth(path: &Path, root: &Path) -> usize {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::parent)
        .map_or(0, |parent| parent.components().count())
}

fn item_kind(item: &syn::Item) -> &'static str {
    match item {
        syn::Item::Const(_) => "const",
        syn::Item::Enum(_) => "enum",
        syn::Item::ExternCrate(_) => "extern crate",
        syn::Item::Fn(_) => "function",
        syn::Item::ForeignMod(_) => "foreign block",
        syn::Item::Impl(_) => "impl",
        syn::Item::Macro(_) => "macro",
        syn::Item::Mod(_) => "inline module",
        syn::Item::Static(_) => "static",
        syn::Item::Struct(_) => "struct",
        syn::Item::Trait(_) => "trait",
        syn::Item::TraitAlias(_) => "trait alias",
        syn::Item::Type(_) => "type alias",
        syn::Item::Union(_) => "union",
        syn::Item::Use(_) => "use",
        _ => "other item",
    }
}

fn bounded_output(root: &Path, label: &'static str, arguments: &[&str]) -> Vec<u8> {
    let program = if arguments.first() == Some(&"metadata") {
        env!("CARGO")
    } else {
        "git"
    };
    let mut command = Command::new(program);
    command.current_dir(root).args(arguments);
    bounded_command_output(command, label)
}

fn bounded_command_output(mut command: Command, label: &'static str) -> Vec<u8> {
    let child = ManagedChild::spawn(
        &mut command,
        ChildIdentity::new(label),
        ChildLimits::default(),
    )
    .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    let completed = child
        .wait_until(Instant::now() + MAX_COMMAND_WAIT)
        .unwrap_or_else(|error| panic!("wait for {label}: {error}"));
    assert!(
        completed.exit.success,
        "{label} failed: {}",
        String::from_utf8_lossy(&completed.output.stderr)
    );
    completed.output.stdout
}

fn repository_root() -> PathBuf {
    super::policy::repository_root()
}

fn violation(path: &Path, detail: String) -> LayoutViolation {
    LayoutViolation {
        path: path.to_path_buf(),
        detail,
    }
}
