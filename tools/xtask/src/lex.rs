//! Minimal lexers that pull string literals out of Rust and C# source.
//!
//! They only need to tell strings apart from comments, char literals and lifetimes; everything else is
//! skipped. Escapes are decoded so the literal compares as the text a user would see.

/// A string literal and the 1-based line it starts on.
#[derive(Debug, PartialEq, Eq)]
pub struct Literal {
    pub line: usize,
    pub text: String,
}

struct Cursor {
    chars: Vec<char>,
    pos: usize,
    line: usize,
}

impl Cursor {
    fn new(src: &str) -> Self {
        Cursor {
            chars: src.chars().collect(),
            pos: 0,
            line: 1,
        }
    }
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek(0) == Some(c) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn skip_line(&mut self) {
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }
    /// Skips a `/* */` comment whose opening `/*` was already consumed.
    fn skip_block_comment(&mut self, nested: bool) {
        let mut depth = 1;
        while let Some(c) = self.bump() {
            if c == '*' && self.eat('/') {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            } else if nested && c == '/' && self.eat('*') {
                depth += 1;
            }
        }
    }
    /// Reads a backslash escape (the `\` already consumed) shared by Rust and C#.
    fn escape(&mut self, out: &mut String) {
        let Some(c) = self.bump() else { return };
        match c {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            'u' | 'x' | 'U' => {
                // Rust `\u{..}` / `\x..`, C# `\uXXXX` / `\xX..` / `\UXXXXXXXX`.
                let braced = self.eat('{');
                let max = match (braced, c) {
                    (true, _) => 6,
                    (false, 'U') => 8,
                    (false, 'u') => 4,
                    _ => 2,
                };
                let mut hex = String::new();
                while let Some(h) = self.peek(0) {
                    if !h.is_ascii_hexdigit() || hex.len() == max {
                        break;
                    }
                    hex.push(h);
                    self.bump();
                }
                if braced {
                    self.eat('}');
                }
                if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            '\n' => {
                // Rust line continuation: skip the newline and leading whitespace.
                while matches!(self.peek(0), Some(w) if w.is_whitespace()) {
                    self.bump();
                }
            }
            other => out.push(other),
        }
    }
}

/// String literals of a Rust source file: `"…"`, `b"…"`, `c"…"`, `r#"…"#` and friends.
pub fn rust_literals(src: &str) -> Vec<Literal> {
    let mut cur = Cursor::new(src);
    let mut out = Vec::new();
    while let Some(c) = cur.peek(0) {
        let line = cur.line;
        if c == '/' && cur.peek(1) == Some('/') {
            cur.skip_line();
        } else if c == '/' && cur.peek(1) == Some('*') {
            cur.pos += 2;
            cur.skip_block_comment(true);
        } else if c == '"' {
            cur.bump();
            out.push(Literal {
                line,
                text: rust_quoted(&mut cur),
            });
        } else if c == '\'' {
            cur.bump();
            if cur.peek(0) == Some('\\') {
                // Escaped char literal: skip to the closing quote.
                cur.bump();
                cur.bump();
                while let Some(x) = cur.bump() {
                    if x == '\'' {
                        break;
                    }
                }
            } else if cur.peek(1) == Some('\'') {
                cur.bump();
                cur.bump();
            }
            // Otherwise a lifetime or label: the quote alone is consumed.
        } else if c.is_alphabetic() || c == '_' {
            let mut ident = String::new();
            while let Some(x) = cur.peek(0) {
                if !(x.is_alphanumeric() || x == '_') {
                    break;
                }
                ident.push(x);
                cur.bump();
            }
            match (ident.as_str(), cur.peek(0)) {
                ("r" | "br" | "cr", Some('"' | '#')) => {
                    if let Some(text) = rust_raw(&mut cur) {
                        out.push(Literal { line, text });
                    }
                }
                ("b" | "c", Some('"')) => {
                    cur.bump();
                    out.push(Literal {
                        line,
                        text: rust_quoted(&mut cur),
                    });
                }
                ("b", Some('\'')) => {
                    cur.bump();
                    if cur.eat('\\') {
                        cur.bump();
                    }
                    while let Some(x) = cur.bump() {
                        if x == '\'' {
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else {
            cur.bump();
        }
    }
    out
}

/// Body of a `"…"` literal, opening quote consumed.
fn rust_quoted(cur: &mut Cursor) -> String {
    let mut s = String::new();
    while let Some(c) = cur.bump() {
        match c {
            '"' => break,
            '\\' => cur.escape(&mut s),
            other => s.push(other),
        }
    }
    s
}

/// A raw string after its `r`/`br`/`cr` prefix; `None` if it is a raw identifier (`r#foo`).
fn rust_raw(cur: &mut Cursor) -> Option<String> {
    let mut hashes = 0;
    while cur.peek(hashes) == Some('#') {
        hashes += 1;
    }
    if cur.peek(hashes) != Some('"') {
        return None;
    }
    for _ in 0..=hashes {
        cur.bump();
    }
    let mut s = String::new();
    while let Some(c) = cur.bump() {
        if c == '"' && (0..hashes).all(|i| cur.peek(i) == Some('#')) {
            for _ in 0..hashes {
                cur.bump();
            }
            return Some(s);
        }
        s.push(c);
    }
    Some(s)
}

/// String literals of a C# source file: regular, verbatim (`@"…"`), interpolated (`$"…"`, holes kept as
/// written) and raw (`"""…"""`).
pub fn csharp_literals(src: &str) -> Vec<Literal> {
    let mut cur = Cursor::new(src);
    let mut out = Vec::new();
    while let Some(c) = cur.peek(0) {
        let line = cur.line;
        if c == '/' && cur.peek(1) == Some('/') {
            cur.skip_line();
        } else if c == '/' && cur.peek(1) == Some('*') {
            cur.pos += 2;
            cur.skip_block_comment(false);
        } else if c == '\'' {
            cur.bump();
            if cur.eat('\\') {
                cur.bump();
            }
            while let Some(x) = cur.bump() {
                if x == '\'' || x == '\n' {
                    break;
                }
            }
        } else if c == '"'
            || ((c == '@' || c == '$') && matches!(cur.peek(1), Some('"' | '@' | '$')))
        {
            let mut verbatim = false;
            while let Some(p @ ('@' | '$')) = cur.peek(0) {
                verbatim |= p == '@';
                cur.bump();
            }
            if cur.peek(0) != Some('"') {
                continue;
            }
            let mut quotes = 0;
            while cur.peek(quotes) == Some('"') {
                quotes += 1;
            }
            let text = if quotes >= 3 {
                csharp_raw(&mut cur, quotes)
            } else if quotes == 2 && !verbatim {
                // Empty regular string `""`.
                cur.bump();
                cur.bump();
                String::new()
            } else {
                cur.bump();
                csharp_quoted(&mut cur, verbatim)
            };
            out.push(Literal { line, text });
        } else {
            cur.bump();
        }
    }
    out
}

fn csharp_quoted(cur: &mut Cursor, verbatim: bool) -> String {
    let mut s = String::new();
    while let Some(c) = cur.bump() {
        match c {
            '"' if verbatim && cur.peek(0) == Some('"') => {
                cur.bump();
                s.push('"');
            }
            '"' => break,
            '\\' if !verbatim => cur.escape(&mut s),
            '\n' if !verbatim => break,
            other => s.push(other),
        }
    }
    s
}

fn csharp_raw(cur: &mut Cursor, quotes: usize) -> String {
    for _ in 0..quotes {
        cur.bump();
    }
    let mut s = String::new();
    while cur.peek(0).is_some() {
        if (0..quotes).all(|i| cur.peek(i) == Some('"')) {
            for _ in 0..quotes {
                cur.bump();
            }
            break;
        }
        if let Some(c) = cur.bump() {
            s.push(c);
        }
    }
    // Multi-line raw strings drop the first and last line breaks.
    s.trim_matches(|c| c == '\n' || c == '\r').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(v: Vec<Literal>) -> Vec<(usize, String)> {
        v.into_iter().map(|l| (l.line, l.text)).collect()
    }

    #[test]
    fn rust_strings_comments_chars_lifetimes() {
        let src = r##"
// "in a comment"
/* "block /* nested */ still comment" */
fn f<'a>(x: &'a str) -> char { let q = '"'; let e = '\''; let u = '\u{41}'; 'x' }
let s = "plain \"quoted\" \u{48}i\tend";
let r = r#"raw "with" quotes"#;
let b = b"bytes"; let rr = r"simple raw"; let r#match = 1;
let m = "multi\
         line";
"##;
        assert_eq!(
            texts(rust_literals(src)),
            vec![
                (5, "plain \"quoted\" Hi\tend".to_string()),
                (6, "raw \"with\" quotes".to_string()),
                (7, "bytes".to_string()),
                (7, "simple raw".to_string()),
                (8, "multiline".to_string()),
            ]
        );
    }

    #[test]
    fn csharp_strings() {
        let src = "// \"comment\"\nvar a = \"reg \\\"x\\\"\"; char c = '\"';\nvar v = @\"C:\\dir \"\"q\"\"\";\nvar i = $\"n={n}\"; var e = \"\";\nvar r = \"\"\"\n  raw \"text\"\n  \"\"\";\n";
        assert_eq!(
            texts(csharp_literals(src)),
            vec![
                (2, "reg \"x\"".to_string()),
                (3, "C:\\dir \"q\"".to_string()),
                (4, "n={n}".to_string()),
                (4, String::new()),
                (5, "  raw \"text\"\n  ".to_string()),
            ]
        );
    }
}
