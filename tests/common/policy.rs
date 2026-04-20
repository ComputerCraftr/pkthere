use std::fs;
use std::path::{Path, PathBuf};

const MAX_SOURCE_LINES_EXCLUSIVE: usize = 1000;

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
                path.strip_prefix(repo_root).unwrap().display(),
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
            let rel = path.strip_prefix(repo_root).unwrap();
            violations.push(format!(
                "{}:{}: direct recursion in {}()",
                rel.display(),
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

#[cfg(test)]
mod tests {
    use super::{detect_direct_recursion_in_rust_text, sanitize_rust_source};

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
}
