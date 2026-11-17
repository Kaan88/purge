//! Case-insensitive, separator-aware prefix tests for file paths and registry keys (ENGINE_PLAN.md §5.10:
//! "All prefix tests are separator-aware").
//!
//! `C:\Program Files\Git` is inside `C:\Program Files`; `C:\Program Files (x86)` is not, although the
//! string starts with it. Every containment test in the engine (index, scan, harvest, guard) goes through
//! this module so that the rule is written once.
//!
//! Inputs are expected in canonical form ([`crate::canon`]): backslash separators only. A forward slash is
//! **not** a separator here, because it is a legal character in registry key names
//! (`...\Content Type\application/pdf`). Empty segments (doubled or trailing separators) are ignored, so
//! `C:\X\` and `C:\X` are the same path.
//!
//! Case folding uses Unicode lower-casing, except for a character whose lower-case form belongs to
//! another letter ([`fold_char`]). NTFS and the registry fold with their own upper-case tables, in which
//! the Kelvin sign U+212A is not `K`, the Angstrom sign U+212B is not `Å` and the Ohm sign U+2126 is not
//! `Ω` (checked on a volume and in a hive: `Kodi` and `\u{212A}odi` are two folders and two keys), while
//! Unicode lower-casing maps each pair to one letter. Such a character is left as it is, so a mismatch
//! with the system's tables can only make two names look different (never equal), which errs on the side
//! of "unrelated".

use std::collections::BTreeMap;

/// The separator of canonical paths and registry keys.
pub const SEP: char = '\\';

/// How one path relates to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relation {
    /// Both name the same item.
    Same,
    /// The first is strictly below the second.
    Inside,
    /// The first is a strict ancestor of the second.
    Ancestor,
    /// Neither contains the other.
    Unrelated,
}

/// The fold lives in `purge-model`, so that the object digest (C-OBJECT), which folds service names and
/// task paths, uses this very function (M1B-MODEL moved it there unchanged).
pub use purge_model::object::{fold, fold_char};

/// Case-insensitive equality of two names (single segments or whole strings).
pub fn eq_ci(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        a.eq_ignore_ascii_case(b)
    } else {
        a.chars()
            .flat_map(fold_char)
            .eq(b.chars().flat_map(fold_char))
    }
}

/// The non-empty segments of a path or key.
pub fn segments(path: &str) -> impl DoubleEndedIterator<Item = &str> {
    path.split(SEP).filter(|s| !s.is_empty())
}

/// How `a` relates to `b`.
pub fn relation(a: &str, b: &str) -> Relation {
    let mut left = segments(a);
    let mut right = segments(b);
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Relation::Same,
            (None, Some(_)) => return Relation::Ancestor,
            (Some(_), None) => return Relation::Inside,
            (Some(x), Some(y)) if eq_ci(x, y) => {}
            _ => return Relation::Unrelated,
        }
    }
}

/// `a` and `b` name the same item.
pub fn is_same(a: &str, b: &str) -> bool {
    relation(a, b) == Relation::Same
}

/// `child` is strictly below `parent`.
pub fn is_inside(child: &str, parent: &str) -> bool {
    relation(child, parent) == Relation::Inside
}

/// `ancestor` is a strict ancestor of `of`.
pub fn is_ancestor(ancestor: &str, of: &str) -> bool {
    relation(ancestor, of) == Relation::Ancestor
}

/// `child` is `parent` itself or below it.
pub fn is_same_or_inside(child: &str, parent: &str) -> bool {
    matches!(relation(child, parent), Relation::Same | Relation::Inside)
}

/// The part of `child` below `parent`, without a leading separator; `Some("")` when they are the same and
/// `None` when `child` is not at or below `parent`.
pub fn strip_prefix<'a>(child: &'a str, parent: &str) -> Option<&'a str> {
    let mut rest = child;
    for want in segments(parent) {
        rest = rest.trim_start_matches(SEP);
        let end = rest.find(SEP).unwrap_or(rest.len());
        if rest.is_empty() || !eq_ci(&rest[..end], want) {
            return None;
        }
        rest = &rest[end..];
    }
    Some(rest.trim_matches(SEP))
}

/// The parent of a path or key, or `None` for a single segment (a drive or a hive root) or an empty string.
///
/// The result has no trailing separator: the parent of `C:\X` is `C:`.
pub fn parent(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches(SEP);
    let cut = trimmed.rfind(SEP)?;
    let up = trimmed[..cut].trim_end_matches(SEP);
    (!up.is_empty()).then_some(up)
}

/// The strict ancestors of a path or key, nearest first.
pub fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(parent(path), |p| parent(p))
}

/// The last segment of a path or key.
pub fn leaf(path: &str) -> Option<&str> {
    segments(path).next_back()
}

/// The number of segments.
pub fn depth(path: &str) -> usize {
    segments(path).count()
}

/// The entries of a `;`-separated list of paths (`Path`, `PATHEXT`), empty ones included, each as
/// written (quotes and blanks kept).
///
/// A `;` between double quotes belongs to the entry: `"C:\Program Files\App;x\bin"` is one
/// directory, and cutting it there would make two entries of which the first looks like the folder
/// `C:\Program Files\App`. A quote that is never closed takes the rest of the text. The harvest
/// and the scanners must agree on what an entry and its position are, so both split with this.
///
/// An entry that comes out with a `;` in it, or with a quote that is not closed, is not one
/// directory that anybody can name with certainty ([`is_plain_list_entry`]): programs disagree on
/// how to read it, and it may hold several entries of the user's. It keeps its position in the
/// list and is never taken for an entry of an app.
pub fn list_entries(text: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (at, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                entries.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    entries.push(&text[start..]);
    entries
}

/// An entry of [`list_entries`] without the one pair of double quotes around it and the blanks
/// around that; an entry that is not quoted that way is returned trimmed.
pub fn unquoted_list_entry(entry: &str) -> &str {
    let entry = entry.trim();
    entry
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .map_or(entry, str::trim)
}

/// Whether `text` (an entry without its quotes, or what its `%NAME%` references expand to) can be
/// the name of **one** directory: no `;`, no `"`, no control character (a tab or a line break
/// separates things and is in no path), and no `:` other than the one after a drive letter that
/// starts the text.
///
/// `C:\App\cmd" "C:\Users\me\tools`, `C:\App\cmd,C:\Users\me\tools` and
/// `C:\App\cmd C:\Users\me\tools` all begin with the app's folder and all hold a second path:
/// whatever stands between the two, the second one starts with a drive letter and its `:`, which
/// no file name can hold. A `,` alone decides nothing (`C:\Program Files\Foo, Inc\bin` is one
/// directory): see [`ListEntry::ambiguous`].
pub fn is_one_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !text.contains([';', '"', '<', '>', '|', '?', '*'])
        && !text.chars().any(char::is_control)
        && !text
            .get(if drive { 2 } else { 0 }..)
            .unwrap_or("")
            .contains(':')
}

/// Whether an entry of [`list_entries`] is one plainly written item, as written: its text without
/// the quotes around it is [`is_one_path`]. `"C:\App;x\bin"` is not (a quoted `;`), neither is
/// `"C:\App\cmd;C:\Users\me\bin` (the quote is never closed and the entry runs to the end of the
/// list, over entries that belong to somebody else), nor `"C:\App\cmd" "C:\Users\me\bin"` (two
/// quoted paths in one entry: the quotes are balanced, and a `"` is left inside).
///
/// What the entry's `%NAME%` references lead to is not looked at here: [`ListEntry::read`] does.
pub fn is_plain_list_entry(entry: &str) -> bool {
    is_one_path(unquoted_list_entry(entry))
}

/// Whether `path` has a segment that is `..` (or more dots: Win32 drops trailing dots and
/// blanks, so `.. ` and `...` step back as well), with `\` and `/` both read as separators.
///
/// Such a path can leave the folder it starts in: `C:\App\..\..\Users\me\tools` begins with
/// `C:\App` and is not in it. No containment test of this module resolves `..` (they compare
/// segments), so whoever concludes "this path is the app's" from one must refuse these first.
pub fn steps_back(path: &str) -> bool {
    has_dot_segment(path, 2)
}

/// Whether a segment of `path` is made of dots and blanks only, with at least `least` dots
/// (`..`, `.. `, `. .`, `.. .`: how Win32 reads a name of dots and blanks is not something to
/// rely on, so every such segment counts).
fn has_dot_segment(path: &str, least: usize) -> bool {
    path.split(['\\', '/']).any(|segment| {
        let dots = segment.chars().filter(|c| *c == '.').count();
        dots >= least && segment.chars().all(|c| c == '.' || c.is_whitespace())
    })
}

/// What `text` says by itself: `text` without its `%NAME%` references, known or not.
fn literal_part(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => rest = &after[end + 1..],
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `text` with every `%NAME%` reference the environment knows replaced; a reference to a name it
/// does not know stays as written. Names are upper-cased in `env`
/// (`SystemSource::env`).
pub fn expand_env(text: &str, env: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => match env.get(&after[..end].to_uppercase()) {
                Some(value) if end > 0 => {
                    out.push_str(value);
                    rest = &after[end + 1..];
                }
                _ => {
                    out.push('%');
                    rest = after;
                }
            },
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// File extensions of programs and scripts, lower case with the dot: a blank after one of them
/// ends a file name ([`ListEntry::ambiguous`]), and the program of a command line ends in one
/// ([`is_program_file`]).
pub const PROGRAM_EXTENSIONS: [&str; 12] = [
    ".exe", ".com", ".bat", ".cmd", ".dll", ".msi", ".scr", ".cpl", ".ps1", ".vbs", ".js", ".lnk",
];

/// Whether the last segment of `path` is named like a program or script file.
pub fn is_program_file(path: &str) -> bool {
    let lower = path.trim().trim_matches('"').to_ascii_lowercase();
    PROGRAM_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// One entry of a `;`-separated list of directories (`Path`) that can be told to be one
/// directory, read the way the harvest and REG-ENV both must read it.
///
/// An entry edit takes the entry's whole text out of the list. That is right only when the text
/// stands for one directory, as written **and** after its `%NAME%` references are expanded:
/// `%MYDIRS%` is one entry of `Path`, and with `MYDIRS` = `C:\App\cmd;C:\Users\me\tools` it
/// stands for two directories, of which one is the user's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry<'a> {
    /// The entry without the quotes around it and without a `\` at its end.
    pub bare: &'a str,
    /// [`ListEntry::bare`] with its `%NAME%` references expanded.
    pub expanded: String,
    /// The entry is nothing but `%NAME%` references to variables the environment knows
    /// (`%MYDIRS%`; also `%MYDIRS%%EMPTY%` and `%A%\%B%`: no name of a folder is written in it).
    /// The entry says where to look, the variable says what is there: whoever
    /// wrote the entry, the directory is named somewhere else, and taking the entry out is
    /// taking out somebody's pointer rather than a mention of the app's folder. An installer's
    /// record on the list does not name its entries, so such an entry is never proven to be
    /// the installer's.
    pub indirect: bool,
    /// The entry holds a `,`, a `\\` after its start, or a blank followed by `\`, `/` or `%`.
    /// Windows does not split `Path` at a `,` or a blank and a directory name may hold either,
    /// and a doubled separator inside a path is harmless (`%JAVA_HOME%\bin` with a `JAVA_HOME`
    /// that ends in `\`), so the entry is read as one directory; but a list written with `,` or
    /// blanks by mistake looks the same (`C:\App\cmd,tools`, `C:\App\cmd \\server\tools`,
    /// `C:\App\cmd \Users\me\tools`, `C:\App\cmd %USERPROFILE%\tools`), and so does a
    /// program with an argument (`C:\App\x.exe /quiet`): nothing tells them apart. A blank
    /// before a plain word decides nothing and is not counted (`C:\Program Files\Tidy Notes`),
    /// except after the name of a program file (`C:\App\x.exe user text`). Text after a folder
    /// name (`C:\App\cmd user text`) cannot be told from a folder of that name: after an
    /// uninstall nothing exists to measure the path against, and no installer's record lists
    /// the app's folders.
    pub ambiguous: bool,
}

impl<'a> ListEntry<'a> {
    /// Reads one entry of [`list_entries`]. `None` when it is empty or not one plainly written
    /// directory, as written or expanded: not [`is_one_path`], or with a `.` or `..` segment
    /// (`C:\App\..\..\Users\me\tools` starts with the app's folder and is not in it; nothing
    /// here resolves such a path, and no installer writes one).
    pub fn read(entry: &'a str, env: &BTreeMap<String, String>) -> Option<Self> {
        let one = |text: &str| is_one_path(text) && !has_dot_segment(text, 1);
        let unquoted = unquoted_list_entry(entry);
        if unquoted.is_empty() || !one(unquoted) {
            return None;
        }
        let bare = unquoted.trim_end_matches(SEP);
        let expanded = expand_env(bare, env);
        if !one(&expanded) {
            return None;
        }
        let second_start = |text: &str| {
            text.char_indices().any(|(at, c)| {
                c.is_whitespace() && text[at + c.len_utf8()..].starts_with(['\\', '/', '%'])
            })
        };
        // `x.exe user text`: a program file's name, a blank, and more. A folder is not named
        // like that; a program with its arguments, or with somebody's words after it, is.
        let text_after_program = |text: &str| {
            let lower = text.to_ascii_lowercase();
            PROGRAM_EXTENSIONS.iter().any(|ext| {
                lower.match_indices(ext).any(|(at, _)| {
                    lower[at + ext.len()..]
                        .chars()
                        .next()
                        .is_some_and(char::is_whitespace)
                })
            })
        };
        let ambiguous = [bare, expanded.as_str()].into_iter().any(|text| {
            text.contains(',')
                || text.get(1..).is_some_and(|rest| rest.contains(r"\\"))
                || second_start(text)
                || text_after_program(text)
        });
        let indirect = expanded != bare
            && literal_part(bare)
                .chars()
                .all(|c| c == SEP || c == '/' || c.is_whitespace());
        Some(Self {
            bare,
            indirect,
            ambiguous,
            expanded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NTFS and the registry keep `Kodi` and `\u{212A}odi` apart (two folders, two keys on a real
    /// volume and hive), and so must every containment test.
    #[test]
    fn letters_that_only_unicode_lower_casing_joins_stay_apart() {
        for (sign, letter) in [
            ('\u{212A}', "K"),
            ('\u{212B}', "\u{C5}"),
            ('\u{2126}', "\u{3A9}"),
        ] {
            let sign = sign.to_string();
            assert!(!eq_ci(&sign, letter), "{sign} {letter}");
            assert!(!eq_ci(&sign, &letter.to_lowercase()), "{sign} {letter}");
            assert_ne!(fold(&sign), fold(letter));
            assert!(eq_ci(&sign, &sign));
        }
        let root = r"C:\Users\u\AppData\Local\Programs\Kodi";
        let other = "C:\\Users\\u\\AppData\\Local\\Programs\\\u{212A}odi\\x.exe";
        assert_eq!(relation(other, root), Relation::Unrelated);
        assert!(is_same_or_inside(
            r"c:\users\U\appdata\local\programs\KODI\x.exe",
            root
        ));
        // Ordinary letters fold as before, whatever their script.
        assert!(eq_ci("STRASSE.\u{C4}\u{416}", "strasse.\u{E4}\u{436}"));
        assert_eq!(fold("\u{C4}B\u{416}"), "\u{E4}b\u{436}");
    }

    /// Letters Windows does not fold: outside the BMP (Deseret), Georgian, Cherokee, a late Latin
    /// addition, a title-case digraph. Each pair is two folders on an NTFS volume.
    #[test]
    fn letters_windows_does_not_fold_stay_apart() {
        for (capital, small) in [
            ('\u{10400}', '\u{10428}'),
            ('\u{1C90}', '\u{10D0}'),
            ('\u{13A0}', '\u{AB70}'),
            ('\u{A7B0}', '\u{29E}'),
            ('\u{A78D}', '\u{265}'),
            ('\u{52E}', '\u{52F}'),
            ('\u{1C5}', '\u{1C6}'),
        ] {
            let (a, b) = (format!("{capital}pp"), format!("{small}pp"));
            assert!(!eq_ci(&a, &b), "{a} {b}");
            assert_ne!(fold(&a), fold(&b));
            assert!(eq_ci(&a, &a) && eq_ci(&b, &b));
        }
        // Its neighbours in the same blocks, which Windows folds, still fold.
        assert!(eq_ci("\u{1C4}\u{522}\u{A78B}", "\u{1C6}\u{523}\u{A78C}"));
    }

    #[test]
    fn list_entries_keep_a_quoted_semicolon() {
        assert_eq!(list_entries(r"C:\a;C:\b;"), [r"C:\a", r"C:\b", ""]);
        assert_eq!(list_entries(""), [""]);
        assert_eq!(
            list_entries(r#"C:\a;"C:\Program Files\App;x\bin";C:\b"#),
            [r"C:\a", r#""C:\Program Files\App;x\bin""#, r"C:\b"]
        );
        // Never closed: the rest is one entry.
        assert_eq!(
            list_entries(r#"C:\a;"C:\b;C:\c"#),
            [r"C:\a", r#""C:\b;C:\c"#]
        );
        for entry in [
            r"C:\a",
            r#""C:\Program Files\App\bin""#,
            "",
            " %X%\\y ",
            r#" "C:\a" "#,
            r"C:\Program Files\Foo, Inc\bin",
            r"\\server\share\bin",
        ] {
            assert!(is_plain_list_entry(entry), "{entry:?}");
        }
        for entry in [
            r#""C:\Program Files\App;x\bin""#,
            r#""C:\b;C:\c"#,
            r#""C:\b"#,
            r#"C:\b""#,
            // Two paths in one entry, whatever stands between them.
            r#""C:\App\cmd" "C:\Users\me\tools""#,
            r#"C:\App\"cmd""#,
            r"C:\App\cmd,C:\Users\me\tools",
            r"C:\App\cmd C:\Users\me\tools",
            r"C:\App\cmd:stream",
            r"%X%\cmd,D:\tools",
        ] {
            assert!(!is_plain_list_entry(entry), "{entry:?}");
        }
        // Without quotes it is `str::split`.
        let plain = r"%SystemRoot%\system32;;C:\Tools\bin";
        assert_eq!(list_entries(plain), plain.split(';').collect::<Vec<_>>());
    }

    #[test]
    fn a_list_entry_is_one_directory_as_written_and_expanded() {
        let env: BTreeMap<String, String> = [
            ("MYDIRS", r"C:\App\cmd;C:\Users\me\tools"),
            ("QUOTED", r#"C:\App\cmd" "C:\Users\me\tools"#),
            ("COMMAS", r"C:\App\cmd,C:\Users\me\tools"),
            ("ONE", r"C:\App\cmd"),
            ("PF", r"C:\Program Files"),
            ("EMPTY", ""),
            ("REL", r"Git\cmd"),
            ("COMMA", "cmd,x"),
            ("BLANK", r"cmd \Users\me\tools"),
            ("UP", r"..\..\Users\me\tools"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(
            expand_env(r"%pf%\x;%NOPE%;50%;%%", &env),
            r"C:\Program Files\x;%NOPE%;50%;%%"
        );

        // What the reference leads to is not one directory.
        for entry in [
            "%MYDIRS%",
            "%QUOTED%",
            "%COMMAS%",
            r#""%MYDIRS%""#,
            r"%MYDIRS%\x",
            "",
        ] {
            assert_eq!(ListEntry::read(entry, &env), None, "{entry:?}");
        }
        let read = |entry| ListEntry::read(entry, &env).expect(entry);
        let plain = read(r#" "%PF%\Git\cmd\" "#);
        assert_eq!(plain.bare, r"%PF%\Git\cmd");
        assert_eq!(plain.expanded, r"C:\Program Files\Git\cmd");
        assert!(!plain.indirect && !plain.ambiguous);
        // A bare reference: one directory, but named by the variable and not by the entry.
        assert!(read("%ONE%").indirect);
        assert!(read(r#""%one%\""#).indirect);
        assert!(!read(r"%ONE%\bin").indirect);
        // A name the environment does not know is text, not a reference.
        assert!(!read("%NOPE%").indirect);
        // A `,` does not split the entry and is remembered.
        assert!(read(r"C:\Program Files\Foo, Inc\bin").ambiguous);
        assert!(read(r"C:\App\cmd,tools").ambiguous);
        // A blank before something that starts a path, or an argument; not before a plain word.
        for entry in [
            r"C:\App\cmd \Users\me\tools",
            r"C:\App\cmd /Users/me/tools",
            r"C:\App\cmd %NOPE%\tools",
            r"C:\App\x.exe /quiet",
        ] {
            assert!(read(entry).ambiguous, "{entry:?}");
        }
        // Text after the name of a program file.
        for entry in [
            r"C:\App\x.exe user text",
            r"C:\App\x.DLL  ty",
            r"C:\App\run.cmd now",
        ] {
            assert!(read(entry).ambiguous, "{entry:?}");
        }
        for entry in [
            r"C:\App\x.exe",
            r"C:\App\x.exe.config",
            r"C:\App 1.2 beta\x.exe",
            r"C:\Program Files\Tidy Notes\cmd",
            r"%PF%\Tidy Notes\cmd",
            r"C:\App\cmd tools",
        ] {
            assert!(!read(entry).ambiguous, "{entry:?}");
        }
        // What the reference expands to counts as much as what is written.
        assert!(read(r"C:\App\%COMMA%").ambiguous && read(r"C:\App\%BLANK%").ambiguous);
        assert!(!read(r"C:\App\%REL%").ambiguous);
        // A control character separates; `.` and `..` segments leave the folder: not one path.
        for entry in [
            "C:\\App\\cmd\ttools",
            "C:\\App\\cmd\ntools",
            r"C:\App\..\..\Users\me\tools",
            r"C:\App\.\cmd",
            r"C:\App\.. \x",
            r"C:\App\...\x",
            r"C:\App\. .\x",
            r"C:\App\.. .\x",
            r"C:\App\ . \x",
            r"C:/App/../x",
            r"%ONE%\%UP%",
            r"%ONE%\.",
        ] {
            assert_eq!(ListEntry::read(entry, &env), None, "{entry:?}");
        }
        assert!(steps_back(r"C:\App\..\x") && steps_back("a/.. /b") && steps_back(r"x\..."));
        assert!(steps_back(r"C:\App\. .\x") && steps_back(r"C:\App\.. .\x"));
        assert!(!steps_back(r"C:\App\ . \x") && !steps_back(r"C:\App\a .. b\x"));
        assert!(!steps_back(r"C:\App\.\x") && !steps_back(r"C:\App\a..b\.x"));
        assert!(read(r"C:\App\a..b\.cfg").expanded.ends_with(".cfg"));
        // References only, however many: no folder is named in the entry.
        assert!(read("%ONE%%EMPTY%").indirect);
        assert!(read("%ONE%%NOPE%").indirect);
        assert!(!read("%ONE%50%").indirect);
        assert!(read(r"%PF%\%REL%").indirect);
        assert!(!read(r"%PF%\Git\cmd").indirect);
        // So is a second path that starts with `\\`, and a doubled separator that is none.
        assert!(read(r"C:\App\cmd \\server\tools").ambiguous);
        assert!(read(r"C:\App\\cmd").ambiguous);
        assert!(!read(r"\\server\share\cmd").ambiguous);
        assert!(!read(r"C:\App\cmd").ambiguous);
    }

    #[test]
    fn relation_table() {
        use Relation::*;
        let rows: &[(&str, &str, Relation)] = &[
            (r"C:\Program Files", r"c:\program files", Same),
            (r"C:\Program Files\", r"C:\Program Files", Same),
            (r"C:\Program Files\\Git", r"C:\Program Files\Git", Same),
            (r"C:\Program Files\Git", r"C:\Program Files", Inside),
            (r"C:\Program Files", r"C:\Program Files\Git\bin", Ancestor),
            (r"C:\Program Files (x86)", r"C:\Program Files", Unrelated),
            (r"C:\Program Files", r"C:\Program Files (x86)", Unrelated),
            (r"C:\Program FilesX\a", r"C:\Program Files", Unrelated),
            (
                r"HKLM\SOFTWARE\Mozilla\Firefox",
                r"hklm\software\mozilla",
                Inside,
            ),
            (
                r"HKLM\SOFTWARE\MozillaPlugins",
                r"HKLM\SOFTWARE\Mozilla",
                Unrelated,
            ),
            (
                r"HKLM\SOFTWARE\Microsoft.NET",
                r"HKLM\SOFTWARE\Microsoft",
                Unrelated,
            ),
            (r"C:\ÄPFEL\x", r"c:\äpfel", Inside),
            ("", "", Same),
            ("", r"C:\x", Ancestor),
        ];
        for (a, b, want) in rows {
            assert_eq!(relation(a, b), *want, "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn predicates_are_strict() {
        assert!(is_same(r"C:\A", r"c:\a\"));
        assert!(!is_inside(r"C:\A", r"C:\A"));
        assert!(!is_ancestor(r"C:\A", r"C:\A"));
        assert!(is_same_or_inside(r"C:\A", r"C:\A"));
        assert!(is_same_or_inside(r"C:\A\b", r"C:\A"));
        assert!(!is_same_or_inside(r"C:\Ab", r"C:\A"));
        assert!(is_ancestor(r"C:\A", r"C:\A\b"));
        assert!(!is_ancestor(r"C:\A\b", r"C:\A"));
    }

    #[test]
    fn forward_slash_is_not_a_separator() {
        let mime = r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\application/pdf";
        assert_eq!(leaf(mime), Some("application/pdf"));
        assert!(!is_inside(
            mime,
            r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\application"
        ));
    }

    #[test]
    fn strip_prefix_cases() {
        assert_eq!(
            strip_prefix(r"C:\Program Files\Git\bin", r"c:\program files"),
            Some(r"Git\bin")
        );
        assert_eq!(strip_prefix(r"C:\A\", r"C:\A"), Some(""));
        assert_eq!(strip_prefix(r"C:\Ab\c", r"C:\A"), None);
        assert_eq!(strip_prefix(r"C:\A", r"C:\A\b"), None);
        assert_eq!(strip_prefix(r"C:\A\\b\", r"C:\A"), Some("b"));
    }

    #[test]
    fn parent_ancestors_leaf_depth() {
        assert_eq!(parent(r"C:\A\b"), Some(r"C:\A"));
        assert_eq!(parent(r"C:\A\b\"), Some(r"C:\A"));
        assert_eq!(parent(r"C:\A"), Some("C:"));
        assert_eq!(parent("C:"), None);
        assert_eq!(parent(r"C:\"), None);
        assert_eq!(parent(""), None);
        let up: Vec<_> = ancestors(r"HKLM\SOFTWARE\X\Y").collect();
        assert_eq!(up, [r"HKLM\SOFTWARE\X", r"HKLM\SOFTWARE", "HKLM"]);
        assert_eq!(leaf(r"C:\A\b\"), Some("b"));
        assert_eq!(leaf(""), None);
        assert_eq!(depth(r"C:\A\\b\"), 3);
    }
}
