//! Field escaping for the snapshot TSV format (RIG.md §2).
//!
//! In text fields `\` TAB LF CR NUL are written as `\\` `\t` `\n` `\r` `\0`.

/// Append `s` escaped to `out`.
pub fn escape_into(s: &str, out: &mut String) {
    // Fast path: nothing to escape.
    if !s.bytes().any(|b| matches!(b, b'\\' | b'\t' | b'\n' | b'\r' | 0)) {
        out.push_str(s);
        return;
    }
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
}

pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    escape_into(s, &mut o);
    o
}

/// Reverse of [`escape`]. Unknown escapes are kept literally (backslash and char).
pub fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut o = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            o.push(c);
            continue;
        }
        match it.next() {
            Some('\\') => o.push('\\'),
            Some('t') => o.push('\t'),
            Some('n') => o.push('\n'),
            Some('r') => o.push('\r'),
            Some('0') => o.push('\0'),
            Some(x) => {
                o.push('\\');
                o.push(x);
            }
            None => o.push('\\'),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let cases = [
            "",
            "plain",
            "C:\\Program Files\\x",
            "a\tb\nc\rd\0e",
            "\\\\server\\share\\",
            "trail\\",
            "\\0 literal backslash-zero",
            "unicode \u{00e9}\u{4e2d}\t\u{1f600}",
        ];
        for c in cases {
            let e = escape(c);
            assert!(!e.contains('\t') && !e.contains('\n') && !e.contains('\r') && !e.contains('\0'));
            assert_eq!(unescape(&e), c, "case {c:?} -> {e:?}");
        }
    }

    #[test]
    fn exact_forms() {
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("x\0y"), "x\\0y");
        assert_eq!(escape("t\tn\nr\r"), "t\\tn\\nr\\r");
    }
}
