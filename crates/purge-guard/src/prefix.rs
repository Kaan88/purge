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
//! Case folding uses Unicode lower-casing. NTFS and the registry fold with their own upper-case tables;
//! the two agree on everything but a handful of exotic code points, and a mismatch there can only make two
//! names look different (never equal), which errs on the side of "unrelated".

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

/// Folds a string for case-insensitive comparison or use as a map key.
pub fn fold(s: &str) -> String {
    s.to_lowercase()
}

/// Case-insensitive equality of two names (single segments or whole strings).
pub fn eq_ci(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        a.eq_ignore_ascii_case(b)
    } else {
        a.chars()
            .flat_map(char::to_lowercase)
            .eq(b.chars().flat_map(char::to_lowercase))
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

#[cfg(test)]
mod tests {
    use super::*;

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
