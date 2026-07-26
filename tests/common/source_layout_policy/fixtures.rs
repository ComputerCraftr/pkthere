use super::{
    MAX_FILE_LINES, MAX_FUNCTION_LINES, facade_violations, function_violations,
    module_bypass_violations, physical_line_count, repository_violations, shebang_kind,
    shell_source_violations, struct_violations,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) fn assert_engine_fixtures() {
    assert_eq!(physical_line_count(b""), 0);
    assert_eq!(physical_line_count(b"x"), 1);
    assert_eq!(physical_line_count(b"x\n"), 1);
    assert_eq!(physical_line_count(b"x\r\n"), 1);
    assert_eq!(
        physical_line_count(&vec![b'\n'; MAX_FILE_LINES]),
        MAX_FILE_LINES
    );
    assert_eq!(
        physical_line_count(&vec![b'\n'; MAX_FILE_LINES + 1]),
        MAX_FILE_LINES + 1
    );

    for accepted in [
        "#!/usr/bin/python3\n",
        "#!/bin/sh\n",
        "#!/usr/bin/env bash\n",
        "#!/usr/bin/env -S python3 -u\n",
    ] {
        assert!(shebang_kind(accepted.as_bytes()).is_some(), "{accepted}");
    }
    assert_eq!(shebang_kind(b"#!/usr/bin/perl\n"), None);

    let enum_fields = (0..25)
        .map(|index| format!("field_{index}: u8"))
        .collect::<Vec<_>>()
        .join(",");
    let enum_source = format!("enum Oversized {{ Variant {{ {enum_fields} }} }}");
    let enum_syntax = syn::parse_file(&enum_source).expect("parse enum-variant fixture");
    assert_eq!(struct_violations("fixture.rs", &enum_syntax).len(), 1);

    let governed_shell = BTreeSet::from([PathBuf::from("scripts/common.sh")]);
    assert!(
        shell_source_violations(
            Path::new("scripts/run.sh"),
            ". ./common.sh\n",
            &governed_shell,
        )
        .is_empty()
    );
    assert!(
        !shell_source_violations(
            Path::new("scripts/run.sh"),
            "source \"$HELPER\"\n",
            &governed_shell,
        )
        .is_empty()
    );

    for source in [
        "//! docs\nmod child;\n",
        "#![deny(warnings)]\npub use child::Thing;\nmod child;\n",
        "extern crate core;\ntype Alias = u64;\n",
    ] {
        assert!(facade_violations("lib.rs", source).is_empty(), "{source}");
    }
    for source in [
        "fn work() {}\n",
        "struct State;\n",
        "const VALUE: u8 = 1;\n",
        "macro_rules! generated { () => {} }\n",
        "cfg_if::cfg_if! { if #[cfg(unix)] { fn work() {} } }\n",
        "mod child { fn work() {} }\n",
        "include!(\"child.rs\");\n",
    ] {
        assert!(!facade_violations("lib.rs", source).is_empty(), "{source}");
    }

    let exact = format!(
        "fn measured() {{\n{}}}\n",
        "// x\n".repeat(MAX_FUNCTION_LINES - 2)
    );
    assert!(function_violations("fixture.rs", &exact).is_empty());
    let too_long = format!(
        "#[test]\nfn measured() {{\n{}}}\n",
        "// x\n".repeat(MAX_FUNCTION_LINES - 1)
    );
    assert!(!function_violations("fixture.rs", &too_long).is_empty());

    let ordinary = syn::parse_file("mod child;").expect("parse ordinary module");
    assert!(module_bypass_violations("fixture.rs", &ordinary).is_empty());
    for source in [
        "#[path = \"elsewhere.rs\"] mod child;",
        "mod child { fn work() {} }",
        "include!(\"child.rs\");",
    ] {
        let parsed = syn::parse_file(source).expect("parse bypass fixture");
        assert!(!module_bypass_violations("fixture.rs", &parsed).is_empty());
    }

    let violations = repository_violations();
    if std::env::var_os("PKTHERE_SOURCE_LAYOUT_REPORT").is_some() {
        for violation in &violations {
            eprintln!("{}: {}", violation.path.display(), violation.detail);
        }
        eprintln!("source-layout violations: {}", violations.len());
    }
    assert!(
        violations.is_empty(),
        "repository-wide source-layout violations:\n{}",
        violations
            .iter()
            .map(|violation| format!("{}: {}", violation.path.display(), violation.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
