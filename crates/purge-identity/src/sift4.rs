//! Sift4 string distance (the "simple" variant), used **only** to order otherwise equal matches (§5.4
//! step 9). It never decides whether something matches.
//!
//! Sift4 is a linear-time approximation of the edit distance: it walks both strings once, counts the
//! characters that line up (allowing the two cursors to drift apart by at most `max_offset`) and returns
//! `max(len) - matched`. Written from the published description of the algorithm; the distance is counted
//! in `char`s, so callers should pass normalised text (see [`crate::tokenizer::normalize`]).

/// How far the two cursors may drift apart while looking for the next common character.
pub const DEFAULT_MAX_OFFSET: usize = 5;

/// Sift4 distance between `a` and `b` with [`DEFAULT_MAX_OFFSET`].
pub fn distance(a: &str, b: &str) -> usize {
    distance_with_offset(a, b, DEFAULT_MAX_OFFSET)
}

/// Sift4 distance between `a` and `b`. `0` means equal; the result never exceeds the longer length.
pub fn distance_with_offset(a: &str, b: &str, max_offset: usize) -> usize {
    let s1: Vec<char> = a.chars().collect();
    let s2: Vec<char> = b.chars().collect();
    let (l1, l2) = (s1.len(), s2.len());
    if l1 == 0 {
        return l2;
    }
    if l2 == 0 {
        return l1;
    }

    let (mut c1, mut c2) = (0usize, 0usize);
    // Total length of the common runs found so far, and the length of the run in progress.
    let (mut common, mut run) = (0usize, 0usize);
    while c1 < l1 && c2 < l2 {
        if s1[c1] == s2[c2] {
            run += 1;
        } else {
            common += run;
            run = 0;
            if c1 != c2 {
                c1 = c1.max(c2);
                c2 = c1;
            }
            for i in 0..max_offset {
                if c1 + i >= l1 && c2 + i >= l2 {
                    break;
                }
                if c1 + i < l1 && c2 < l2 && s1[c1 + i] == s2[c2] {
                    c1 += i;
                    run += 1;
                    break;
                }
                if c2 + i < l2 && c1 < l1 && s1[c1] == s2[c2 + i] {
                    c2 += i;
                    run += 1;
                    break;
                }
            }
        }
        c1 += 1;
        c2 += 1;
    }
    common += run;
    l1.max(l2).saturating_sub(common)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors() {
        let cases: &[(&str, &str, usize)] = &[
            ("", "", 0),
            ("", "abc", 3),
            ("abc", "", 3),
            ("abc", "abc", 0),
            ("abc", "abd", 1),
            ("abcd", "abd", 1),
            ("abd", "abcd", 1),
            ("ab", "ba", 1),
            ("kitten", "sitting", 3),
            ("notepad", "notepad++", 2),
        ];
        for &(a, b, want) in cases {
            assert_eq!(distance(a, b), want, "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn zero_only_for_equal_and_bounded_by_the_longer_length() {
        let words = [
            "git",
            "github",
            "code",
            "vscode",
            "notepad++",
            "notepad",
            "firefox",
            "thunderbird",
            "ıi",
        ];
        for a in words {
            for b in words {
                let d = distance(a, b);
                assert!(d <= a.chars().count().max(b.chars().count()));
                assert_eq!(d == 0, a == b, "{a:?} vs {b:?}");
            }
        }
    }

    #[test]
    fn counts_chars_not_bytes() {
        assert_eq!(distance("ağaç", "agac"), 2);
        assert_eq!(distance("日本語", "日本"), 1);
    }

    #[test]
    fn offset_limits_the_search() {
        // The common tail sits 6 characters further in `b`: out of reach for offset 5, found with 10.
        assert_eq!(distance_with_offset("xyz", "abcdefxyz", 5), 9);
        assert_eq!(distance_with_offset("xyz", "abcdefxyz", 10), 6);
    }
}
