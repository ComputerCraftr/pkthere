#[path = "path_policy.rs"]
mod path_policy;

use std::fs;
use std::path::{Path, PathBuf};

const MAX_SOURCE_LINES_EXCLUSIVE: usize = 1000;
const BLANKET_ALLOW_ATTR_ALLOWLIST: &[&str] = &["tests/common/orchestrator.rs"];
const DUPLICATE_FUNCTION_BODY_MIN_LEN: usize = 80;
const DUPLICATE_TEST_BODY_MIN_LEN: usize = 80;

fn collect_sources_with_exts(root: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()))
        .map(|entry| entry.unwrap())
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_sources_with_exts(&path, exts, out);
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| exts.iter().any(|want| ext == *want))
        {
            out.push(path);
        }
    }
}

pub fn assert_rust_source_files_stay_under_1000_lines() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = repo_root.join("src");
    let mut sources = Vec::new();
    collect_sources_with_exts(&src_root, &["rs"], &mut sources);

    let mut offenders = Vec::new();
    for path in sources {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let line_count = contents.lines().count();
        if line_count >= MAX_SOURCE_LINES_EXCLUSIVE {
            offenders.push(format!(
                "{} has {} lines",
                path_policy::render_repo_relative_path(repo_root, &path),
                line_count
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "Rust source files must stay under {} lines:\n{}",
        MAX_SOURCE_LINES_EXCLUSIVE,
        offenders.join("\n")
    );
}

fn sanitize_rust_source(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        let nxt = bytes.get(i + 1).copied().map(char::from).unwrap_or('\0');

        if ch == '/' && nxt == '/' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < bytes.len() && bytes[i] as char != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        if ch == '/' && nxt == '*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] as char == '*' && bytes[i + 1] as char == '/') {
                out.push(if bytes[i] as char == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(' ');
                out.push(' ');
                i += 2;
            }
            continue;
        }

        if ch == '"' || ch == '\'' {
            let quote = ch;
            out.push(' ');
            i += 1;
            while i < bytes.len() {
                let cur = bytes[i] as char;
                if cur == '\\' && i + 1 < bytes.len() {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if cur == quote {
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(if cur == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }

        out.push(ch);
        i += 1;
    }

    out
}

fn find_matching_brace(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text.char_indices() {
        if index < open_index {
            continue;
        }
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_ident_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'_'
}

fn starts_with_keyword(text: &[u8], idx: usize, keyword: &str) -> bool {
    let kw = keyword.as_bytes();
    if idx + kw.len() > text.len() || &text[idx..idx + kw.len()] != kw {
        return false;
    }
    let before_ok = idx == 0 || !is_ident_char(text[idx - 1]);
    let after_ok = idx + kw.len() == text.len() || !is_ident_char(text[idx + kw.len()]);
    before_ok && after_ok
}

fn find_function_defs(text: &str) -> Vec<(usize, String, usize)> {
    let bytes = text.as_bytes();
    let mut defs = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if !starts_with_keyword(bytes, i, "fn") {
            i += 1;
            continue;
        }

        i += 2; // skip "fn"
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            continue;
        }

        let name_start = i;
        i += 1;
        while i < bytes.len() && is_ident_char(bytes[i]) {
            i += 1;
        }
        let name = &text[name_start..i];

        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'(' {
            continue;
        }

        let mut paren_depth = 0usize;
        let mut k = j;
        while k < bytes.len() {
            match bytes[k] as char {
                '(' => paren_depth += 1,
                ')' => {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        k += 1;
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        if paren_depth != 0 {
            continue;
        }

        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b'{' {
            continue;
        }

        defs.push((name_start, name.to_string(), k));
        i = k + 1;
    }

    defs
}

fn contains_call(body: &str, name: &str) -> bool {
    let body_bytes = body.as_bytes();
    let name_bytes = name.as_bytes();
    let mut i = 0usize;

    while i + name_bytes.len() < body_bytes.len() {
        if &body_bytes[i..i + name_bytes.len()] == name_bytes {
            let before_ok = i == 0 || !is_ident_char(body_bytes[i - 1]);
            let mut j = i + name_bytes.len();
            while j < body_bytes.len() && body_bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let after_ok = j < body_bytes.len() && body_bytes[j] == b'(';
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }

    false
}

fn strip_cfg_test_items(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = text.to_string();
    let mut i = 0usize;

    while i < bytes.len() {
        if !starts_with_keyword(bytes, i, "#") {
            i += 1;
            continue;
        }

        let Some(rest) = text.get(i..) else {
            break;
        };
        if !rest.starts_with("#[cfg(test)]") {
            i += 1;
            continue;
        }

        let item_start = i;
        i += "#[cfg(test)]".len();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        while i < bytes.len()
            && (starts_with_keyword(bytes, i, "pub")
                || starts_with_keyword(bytes, i, "const")
                || starts_with_keyword(bytes, i, "unsafe")
                || starts_with_keyword(bytes, i, "async"))
        {
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }

        if i >= bytes.len() {
            break;
        }

        let item_end = if starts_with_keyword(bytes, i, "fn")
            || starts_with_keyword(bytes, i, "mod")
            || starts_with_keyword(bytes, i, "impl")
        {
            let Some(open_rel) = text[i..].find('{') else {
                i += 1;
                continue;
            };
            let open = i + open_rel;
            let Some(close) = find_matching_brace(text, open) else {
                i += 1;
                continue;
            };
            close + 1
        } else {
            let Some(end_rel) = text[i..].find(';') else {
                i += 1;
                continue;
            };
            i + end_rel + 1
        };

        for idx in item_start..item_end {
            let ch = out.as_bytes()[idx] as char;
            out.replace_range(idx..idx + 1, if ch == '\n' { "\n" } else { " " });
        }
        i = item_end;
    }

    out
}

fn normalize_function_body(body: &str) -> String {
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn detect_duplicate_function_sources_in_rust_text(text: &str) -> Vec<(usize, String, String)> {
    let sanitized = sanitize_rust_source(text);
    let production_only = strip_cfg_test_items(&sanitized);
    let mut defs_by_body = std::collections::BTreeMap::<String, Vec<(usize, String)>>::new();

    for (name_start, name, body_open) in find_function_defs(&production_only) {
        let Some(body_close) = find_matching_brace(&production_only, body_open) else {
            continue;
        };
        let body = normalize_function_body(&production_only[body_open + 1..body_close]);
        if body.len() < DUPLICATE_FUNCTION_BODY_MIN_LEN {
            continue;
        }
        let line = production_only[..name_start]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1;
        defs_by_body.entry(body).or_default().push((line, name));
    }

    defs_by_body
        .into_iter()
        .filter(|(_, defs)| defs.len() > 1)
        .flat_map(|(body, defs)| {
            defs.into_iter()
                .map(move |(line, name)| (line, name, body.clone()))
        })
        .collect()
}

fn collect_preceding_attrs(text: &str, name_start: usize) -> Vec<String> {
    let mut attrs = Vec::new();
    let line_start = text[..name_start]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let head = &text[..line_start];
    let mut lines = head.lines().collect::<Vec<_>>();

    while let Some(line) = lines.pop() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("#[") {
            attrs.push(trimmed.to_string());
            continue;
        }
        break;
    }

    attrs.reverse();
    attrs
}

fn is_test_function(path: &Path, attrs: &[String]) -> bool {
    let rel = path.to_string_lossy();
    rel.contains("tests/")
        && attrs
            .iter()
            .any(|attr| attr.contains("test") || attr.contains("cfg_attr") && attr.contains("test"))
}

fn detect_duplicate_test_bodies_in_rust_text(
    path: &Path,
    text: &str,
) -> Vec<(usize, String, String)> {
    let sanitized = sanitize_rust_source(text);
    let mut defs_by_body = std::collections::BTreeMap::<String, Vec<(usize, String)>>::new();

    for (name_start, name, body_open) in find_function_defs(&sanitized) {
        let attrs = collect_preceding_attrs(text, name_start);
        if !is_test_function(path, &attrs) {
            continue;
        }
        let Some(body_close) = find_matching_brace(&sanitized, body_open) else {
            continue;
        };
        let body = normalize_function_body(&sanitized[body_open + 1..body_close]);
        if body.len() < DUPLICATE_TEST_BODY_MIN_LEN {
            continue;
        }
        let line = sanitized[..name_start]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1;
        defs_by_body.entry(body).or_default().push((line, name));
    }

    defs_by_body
        .into_iter()
        .filter(|(_, defs)| defs.len() > 1)
        .flat_map(|(body, defs)| {
            defs.into_iter()
                .map(move |(line, name)| (line, name, body.clone()))
        })
        .collect()
}

fn detect_direct_recursion_in_rust_text(text: &str) -> Vec<(usize, String)> {
    let sanitized = sanitize_rust_source(text);
    let mut violations = Vec::new();

    for (name_start, name, body_open) in find_function_defs(&sanitized) {
        let Some(body_close) = find_matching_brace(&sanitized, body_open) else {
            continue;
        };
        let body = &sanitized[body_open + 1..body_close];
        if contains_call(body, &name) {
            let line = sanitized[..name_start]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1;
            violations.push((line, name));
        }
    }

    violations
}

pub fn assert_no_direct_recursion_in_rust_sources() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = repo_root.join("src");
    let mut sources = Vec::new();
    collect_sources_with_exts(&src_root, &["rs"], &mut sources);

    let mut violations = Vec::new();
    for path in sources {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for (line, name) in detect_direct_recursion_in_rust_text(&contents) {
            violations.push(format!(
                "{}:{}: direct recursion in {}()",
                path_policy::render_repo_relative_path(repo_root, &path),
                line,
                name
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Direct recursion is forbidden in Rust sources:\n{}",
        violations.join("\n")
    );
}

pub fn assert_blanket_dead_code_and_unused_import_allows_are_scoped() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    collect_sources_with_exts(&repo_root.join("src"), &["rs"], &mut sources);
    collect_sources_with_exts(&repo_root.join("tests"), &["rs"], &mut sources);

    let mut violations = Vec::new();
    for path in sources {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let rel = path_policy::render_repo_relative_path(repo_root, &path);

        // Standardize the content to make detection more robust against formatting/multi-line
        let content_no_spaces = contents
            .replace(' ', "")
            .replace('\n', "")
            .replace('\r', "")
            .replace('\t', "");

        let allow_prefix = "allow(";
        let has_forbidden_blanket_allow = content_no_spaces
            .contains(format!("{allow_prefix}dead_code").as_str())
            || content_no_spaces.contains(format!("{allow_prefix}unused_imports").as_str())
            || content_no_spaces.contains(format!("{allow_prefix}unused").as_str())
            || content_no_spaces.contains(format!("{allow_prefix}unused_variables").as_str());

        if has_forbidden_blanket_allow
            && !BLANKET_ALLOW_ATTR_ALLOWLIST
                .iter()
                .any(|allowed| *allowed == rel)
        {
            violations.push(rel);
        }
    }

    assert!(
        violations.is_empty(),
        "Blanket allow on (dead_code)/(unused_imports) is only permitted in {:?}:\n{}",
        BLANKET_ALLOW_ATTR_ALLOWLIST,
        violations.join("\n")
    );
}

pub fn assert_no_duplicate_function_sources_in_scoped_rust_sources() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    collect_sources_with_exts(&repo_root.join("src"), &["rs"], &mut sources);
    collect_sources_with_exts(&repo_root.join("build_support"), &["rs"], &mut sources);

    let mut body_to_defs =
        std::collections::BTreeMap::<String, Vec<(String, usize, String)>>::new();

    for path in sources {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let rel = path_policy::render_repo_relative_path(repo_root, &path);
        for (line, name, body) in detect_duplicate_function_sources_in_rust_text(&contents) {
            body_to_defs
                .entry(body)
                .or_default()
                .push((rel.clone(), line, name));
        }
    }

    let mut violations = Vec::new();
    for defs in body_to_defs.into_values() {
        if defs.len() < 2 {
            continue;
        }
        let joined = defs
            .into_iter()
            .map(|(path, line, name)| format!("{path}:{line}: {name}()"))
            .collect::<Vec<_>>()
            .join("\n  ");
        violations.push(format!("duplicate function body:\n  {joined}"));
    }

    assert!(
        violations.is_empty(),
        "Duplicate non-test function bodies are forbidden in scoped Rust sources:\n{}",
        violations.join("\n")
    );
}

pub fn assert_no_duplicate_test_bodies_in_scoped_rust_sources() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    collect_sources_with_exts(&repo_root.join("tests"), &["rs"], &mut sources);

    let mut body_to_defs =
        std::collections::BTreeMap::<String, Vec<(String, usize, String)>>::new();

    for path in sources {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let rel = path_policy::render_repo_relative_path(repo_root, &path);
        for (line, name, body) in detect_duplicate_test_bodies_in_rust_text(&path, &contents) {
            body_to_defs
                .entry(body)
                .or_default()
                .push((rel.clone(), line, name));
        }
    }

    let mut violations = Vec::new();
    for defs in body_to_defs.into_values() {
        if defs.len() < 2 {
            continue;
        }
        let joined = defs
            .into_iter()
            .map(|(path, line, name)| format!("{path}:{line}: {name}()"))
            .collect::<Vec<_>>()
            .join("\n  ");
        violations.push(format!("duplicate test body:\n  {joined}"));
    }

    assert!(
        violations.is_empty(),
        "Duplicate long #[test] bodies are forbidden in scoped Rust tests:\n{}",
        violations.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::{
        detect_direct_recursion_in_rust_text, detect_duplicate_function_sources_in_rust_text,
        detect_duplicate_test_bodies_in_rust_text, sanitize_rust_source, strip_cfg_test_items,
    };
    use std::path::Path;

    #[test]
    fn sanitize_rust_source_strips_comments_and_literals() {
        let text = r#"
        // comment
        let s = "hello";
        /* block */
        let value = 'x';
        "#;
        let sanitized = sanitize_rust_source(text);
        assert!(!sanitized.contains("comment"));
        assert!(!sanitized.contains("hello"));
    }

    #[test]
    fn detects_direct_recursion_in_simple_function() {
        let src = r#"
        fn foo(x: i32) {
            foo(x - 1);
        }
        "#;
        let violations = detect_direct_recursion_in_rust_text(src);
        assert_eq!(violations, vec![(2, "foo".to_string())]);
    }

    #[test]
    fn ignores_self_name_in_comments_and_strings() {
        let src = r#"
        fn foo() {
            // foo();
            let s = "foo()";
        }
        "#;
        assert!(detect_direct_recursion_in_rust_text(src).is_empty());
    }

    #[test]
    fn ignores_control_keywords_that_look_like_defs() {
        let src = r#"
        fn foo(x: i32) {
            if x > 0 { return; }
        }
        "#;
        assert!(detect_direct_recursion_in_rust_text(src).is_empty());
    }

    #[test]
    fn strip_cfg_test_items_removes_test_only_functions() {
        let src = r#"
        fn prod() { real_work(); }

        #[cfg(test)]
        fn test_only() { duplicate_work(); }
        "#;
        let stripped = strip_cfg_test_items(src);
        assert!(stripped.contains("prod"));
        assert!(!stripped.contains("test_only"));
    }

    #[test]
    fn detects_duplicate_nontrivial_function_bodies() {
        let src = r#"
        fn alpha() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
        }

        fn beta() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
        }
        "#;

        let violations = detect_duplicate_function_sources_in_rust_text(src);
        assert_eq!(violations.len(), 2);
        assert!(violations.iter().any(|(_, name, _)| name == "alpha"));
        assert!(violations.iter().any(|(_, name, _)| name == "beta"));
    }

    #[test]
    fn ignores_duplicate_functions_inside_cfg_test_scope() {
        let src = r#"
        fn prod() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
        }

        #[cfg(test)]
        mod tests {
            fn helper_a() {
                let mut sum = 0;
                for i in 0..16 {
                    sum += i;
                }
                if sum > 10 {
                    do_work(sum);
                }
                let adjusted = sum * 2;
                if adjusted > 40 {
                    report(adjusted);
                }
            }

            fn helper_b() {
                let mut sum = 0;
                for i in 0..16 {
                    sum += i;
                }
                if sum > 10 {
                    do_work(sum);
                }
                let adjusted = sum * 2;
                if adjusted > 40 {
                    report(adjusted);
                }
            }
        }
        "#;

        let violations = detect_duplicate_function_sources_in_rust_text(src);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn detects_duplicate_long_test_bodies() {
        let src = r#"
        #[test]
        fn alpha() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
            let final_value = adjusted + 7;
            if final_value > 50 {
                publish(final_value);
            }
        }

        #[test]
        fn beta() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
            let final_value = adjusted + 7;
            if final_value > 50 {
                publish(final_value);
            }
        }
        "#;

        let violations =
            detect_duplicate_test_bodies_in_rust_text(Path::new("tests/sample.rs"), src);
        assert_eq!(violations.len(), 2);
        assert!(violations.iter().any(|(_, name, _)| name == "alpha"));
        assert!(violations.iter().any(|(_, name, _)| name == "beta"));
    }

    #[test]
    fn ignores_non_test_helpers_for_duplicate_test_body_policy() {
        let src = r#"
        fn helper_a() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
            let final_value = adjusted + 7;
            if final_value > 50 {
                publish(final_value);
            }
        }

        fn helper_b() {
            let mut sum = 0;
            for i in 0..16 {
                sum += i;
            }
            if sum > 10 {
                do_work(sum);
            }
            let adjusted = sum * 2;
            if adjusted > 40 {
                report(adjusted);
            }
            let final_value = adjusted + 7;
            if final_value > 50 {
                publish(final_value);
            }
        }
        "#;

        let violations =
            detect_duplicate_test_bodies_in_rust_text(Path::new("tests/sample.rs"), src);
        assert_eq!(violations.len(), 0);
    }
}
