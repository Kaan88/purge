//! .NET's `StringComparison.OrdinalIgnoreCase` and `ToUpperInvariant`, which the WinUI app's rules use:
//! each character is compared by its simple upper-case mapping (one character to one character), so
//! `ß` stays `ß` and the lengths of both sides never change.

/// The simple upper-case mapping of one character: itself when the full mapping is not one character.
pub(crate) fn fold(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

/// `ToUpperInvariant`.
pub(crate) fn to_upper_invariant(s: &str) -> String {
    s.chars().map(fold).collect()
}

/// `string.Equals(a, b, OrdinalIgnoreCase)`.
pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars().map(fold).eq(b.chars().map(fold))
}

/// `a.StartsWith(b, OrdinalIgnoreCase)`.
pub(crate) fn starts_with_ignore_case(a: &str, b: &str) -> bool {
    let mut a = a.chars().map(fold);
    b.chars().map(fold).all(|c| a.next() == Some(c))
}

/// `a.Contains(b, OrdinalIgnoreCase)`. Folding keeps one character per character, so a match in the
/// folded texts is a match in the originals.
pub(crate) fn contains_ignore_case(hay: &str, needle: &str) -> bool {
    to_upper_invariant(hay).contains(&to_upper_invariant(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding_matches_ordinal_ignore_case() {
        assert!(eq_ignore_case("SharedDLLs", "shareddlls"));
        assert!(!eq_ignore_case("Run", "RunOnce"));
        assert!(eq_ignore_case("straße", "STRAßE"));
        assert!(starts_with_ignore_case("Mozilla Firefox", "mozilla"));
        assert!(!starts_with_ignore_case("Moz", "Mozilla"));
        assert!(contains_ignore_case(r"C:\Apps\Fox", r"apps\fox"));
        assert!(contains_ignore_case("abc", ""));
    }
}
