//! The words of the consent dialog and the rules that keep a name or a path from misleading (design 8
//! and T12).
//!
//! Every name and path the dialog shows goes through [`shown`] or [`quote`], and nothing else puts
//! text from a scan, a program or a journal into the dialog. What [`shown`] does:
//!
//! - control characters (C0, DEL, C1), bidirectional controls, zero-width and other invisible
//!   characters, line and paragraph separators, every space that is not a plain space, private-use and
//!   non-characters, and the double quote are written as `\u{hex}`;
//! - a plain space is written that way too when it starts or ends a path component or follows another
//!   space, so `Program Files` and `Program Files ` and `Program  Files` do not look alike;
//! - in a word that holds an ASCII letter or digit, letters of the blocks that borrow Latin shapes
//!   (Cyrillic, Greek, Armenian, Cherokee, Coptic, full-width forms, mathematical letters, IPA, letter-like
//!   symbols) are written that way too, so `Mozill\u{430}` cannot pass for `Mozilla`; a whole word of
//!   one such script is shown as it is;
//! - a component of more than [`NAME_CUT`] characters keeps its first 56 and last 24 and says how
//!   many it left out in between; a whole text over [`LINE_COST`] shown characters keeps both ends the
//!   same way;
//! - [`quote`] puts the text in double quotes, and no quote can occur inside it, so the text cannot
//!   run on into the words around it.
//!
//! [`Flags`] says whether anything was written as an escape or left out; the view turns that into an
//! attention reason, so such an item is listed in full and never folded into "and N more".

/// Window title of every page.
pub const TITLE: &str = "Purge security prompt";
/// Marks an item that needs attention.
pub const MARK: &str = "\u{26A0}";
/// Starts a line of the other items.
pub const BULLET: &str = "\u{2022}";
/// Separates the parts of a line.
pub const SEP: &str = " \u{b7} ";

/// The most characters of one path component or name that are shown.
pub const NAME_CUT: usize = 80;
/// The most characters a whole shown text holds before its middle is left out.
pub const LINE_COST: usize = 400;

const HEAD: usize = 56;
const TAIL: usize = NAME_CUT - HEAD;

/// What [`shown`] had to do to a text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// At least one character is written as `\u{...}`.
    pub escaped: bool,
    /// Something was left out (`[N characters not shown]`).
    pub shortened: bool,
}

impl Flags {
    /// Adds what `other` did.
    pub fn merge(&mut self, other: Flags) {
        self.escaped |= other.escaped;
        self.shortened |= other.shortened;
    }

    /// Whether the text is shown exactly as it is.
    pub fn is_plain(&self) -> bool {
        !self.escaped && !self.shortened
    }
}

/// A text ready for the dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// The text: printable, no line break, nothing the dialog could read as markup.
    pub text: String,
    /// What was done to it.
    pub flags: Flags,
}

/// Characters that are never shown as themselves.
fn hidden(c: char) -> bool {
    let u = c as u32;
    c == '"'
        || c.is_control()
        || (c.is_whitespace() && c != ' ')
        || (u & 0xFFFE) == 0xFFFE
        || matches!(
            u,
            0xAD
                | 0x34F
                | 0x61C
                | 0x115F
                | 0x1160
                | 0x17B4
                | 0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x2028..=0x202F
                | 0x205F..=0x206F
                | 0x3164
                | 0xE000..=0xF8FF
                | 0xFDD0..=0xFDEF
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF0..=0xFFFF
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE0FFF
                | 0xF0000..=0x10FFFF
        )
}

/// Letters of blocks whose shapes can pass for Latin ones.
fn borrows_latin_shapes(c: char) -> bool {
    matches!(
        c as u32,
        0x250..=0x2AF
            | 0x370..=0x3FF
            | 0x400..=0x52F
            | 0x531..=0x58F
            | 0x1C80..=0x1C8F
            | 0x13A0..=0x13FF
            | 0x2100..=0x214F
            | 0x2C80..=0x2CFF
            | 0xA640..=0xA69F
            | 0xFF01..=0xFF5E
            | 0x1D400..=0x1D7FF
    )
}

/// For each character, whether it sits in a word that mixes an ASCII letter or digit with letters of a
/// block that borrows Latin shapes, and is one of those letters.
fn mixed_script(chars: &[char]) -> Vec<bool> {
    let mut out = vec![false; chars.len()];
    let mut start = 0;
    while start < chars.len() {
        if !chars[start].is_alphanumeric() {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < chars.len() && chars[end].is_alphanumeric() {
            end += 1;
        }
        let word = &chars[start..end];
        if word.iter().any(char::is_ascii_alphanumeric)
            && word.iter().any(|c| borrows_latin_shapes(*c))
        {
            for (i, c) in word.iter().enumerate() {
                out[start + i] = borrows_latin_shapes(*c);
            }
        }
        start = end;
    }
    out
}

fn escape(c: char) -> String {
    format!("\\u{{{:x}}}", c as u32)
}

/// The text left out in the middle of a shown text.
pub fn left_out(n: usize) -> String {
    if n == 1 {
        "[1 character not shown]".to_owned()
    } else {
        format!("[{n} characters not shown]")
    }
}

/// One path component (or a whole name) as pieces of one shown character each; at most
/// [`NAME_CUT`] of them plus the marker.
fn component(comp: &str, flags: &mut Flags) -> Vec<String> {
    let chars: Vec<char> = comp.chars().collect();
    let mixed = mixed_script(&chars);
    let first_visible = chars.iter().position(|c| *c != ' ');
    let last_visible = chars.iter().rposition(|c| *c != ' ');
    let mut out: Vec<String> = Vec::with_capacity(chars.len().min(NAME_CUT + 1));
    for (i, &c) in chars.iter().enumerate() {
        let escape_it = if c == ' ' {
            first_visible.is_none_or(|f| i < f)
                || last_visible.is_none_or(|l| i > l)
                || chars[i - 1] == ' '
        } else {
            hidden(c) || mixed[i]
        };
        if escape_it {
            flags.escaped = true;
            out.push(escape(c));
        } else {
            out.push(c.to_string());
        }
    }
    if out.len() > NAME_CUT {
        let left_out_n = out.len() - NAME_CUT;
        let tail = out.split_off(out.len() - TAIL);
        out.truncate(HEAD);
        out.push(left_out(left_out_n));
        out.extend(tail);
        flags.shortened = true;
    }
    out
}

fn cost(piece: &str) -> usize {
    piece.chars().count()
}

/// Keeps both ends of a text whose pieces are together longer than [`LINE_COST`] characters.
fn cap_line(pieces: &mut Vec<String>, flags: &mut Flags) {
    let total: usize = pieces.iter().map(|p| cost(p)).sum();
    if total <= LINE_COST {
        return;
    }
    let half = LINE_COST / 2 - 20;
    let mut head = 0;
    let mut used = 0;
    while head < pieces.len() && used + cost(&pieces[head]) <= half {
        used += cost(&pieces[head]);
        head += 1;
    }
    let mut tail = pieces.len();
    used = 0;
    while tail > head && used + cost(&pieces[tail - 1]) <= half {
        used += cost(&pieces[tail - 1]);
        tail -= 1;
    }
    let tail_pieces = pieces.split_off(tail);
    pieces.truncate(head);
    pieces.push(left_out(tail - head));
    pieces.extend(tail_pieces);
    flags.shortened = true;
}

/// A name or a path for the dialog (see the module docs). `\` and `/` end a component.
pub fn shown(text: &str) -> Shown {
    let mut flags = Flags::default();
    let mut pieces: Vec<String> = Vec::new();
    for part in text.split_inclusive(['\\', '/']) {
        match part.strip_suffix(['\\', '/']) {
            Some(comp) => {
                pieces.extend(component(comp, &mut flags));
                pieces.push(part[comp.len()..].to_owned());
            }
            None => pieces.extend(component(part, &mut flags)),
        }
    }
    cap_line(&mut pieces, &mut flags);
    Shown {
        text: pieces.concat(),
        flags,
    }
}

/// [`shown`] in double quotes.
pub fn quote(text: &str) -> Shown {
    let mut s = shown(text);
    s.text = format!("\"{}\"", s.text);
    s
}

/// `1,234,567`.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `1 item`, `2 items`, `5,000 items`.
pub fn count(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", grouped(n), if n == 1 { one } else { many })
}

/// `1 byte`, `512 bytes`, `1.5 KB`, `2.0 GB` (powers of 1024, one decimal, rounded down).
pub fn size(bytes: u64) -> String {
    if bytes < 1024 {
        return count(bytes, "byte", "bytes");
    }
    let mut unit = 1u128 << 10;
    for name in ["KB", "MB", "GB", "TB", "PB"] {
        if u128::from(bytes) < unit << 10 || name == "PB" {
            let tenths = u128::from(bytes) * 10 / unit;
            return format!("{}.{} {name}", tenths / 10, tenths % 10);
        }
        unit <<= 10;
    }
    unreachable!("the loop returns at PB")
}

/// A moment the broker read from its own records, written `2026-12-21` or `2026-12-21 14:05 UTC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Year.
    pub year: u16,
    /// Month, 1 to 12.
    pub month: u8,
    /// Day of the month.
    pub day: u8,
    /// Hour, 0 to 23.
    pub hour: u8,
    /// Minute, 0 to 59.
    pub minute: u8,
}

impl Stamp {
    /// `2026-12-21`.
    pub fn date(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `2026-12-21 14:05 UTC`.
    pub fn date_time(&self) -> String {
        format!("{} {:02}:{:02} UTC", self.date(), self.hour, self.minute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_and_paths_are_unchanged() {
        for s in [
            r"C:\Program Files\Mozilla Firefox",
            r"HKLM\SOFTWARE\Mozilla",
            "7-Zip (x64) v2.0_beta",
            "\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441}",
            "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30d5}\u{30a9}\u{30eb}\u{30c0}",
            "Caf\u{e9} M\u{fc}nchen",
            "",
        ] {
            let sh = shown(s);
            assert_eq!(sh.text, s);
            assert!(sh.flags.is_plain(), "{s}");
        }
    }

    #[test]
    fn controls_and_bidi_are_escaped() {
        let sh = shown("a\u{202e}b\nc\td\u{0}e\u{7f}f\u{85}g\u{2028}h\u{200b}i\u{feff}j");
        assert_eq!(
            sh.text,
            r"a\u{202e}b\u{a}c\u{9}d\u{0}e\u{7f}f\u{85}g\u{2028}h\u{200b}i\u{feff}j"
        );
        assert!(sh.flags.escaped && !sh.flags.shortened);
        for c in [
            '\u{202a}',
            '\u{202b}',
            '\u{202c}',
            '\u{202d}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{200e}',
            '\u{200f}',
            '\u{61c}',
            '\u{a0}',
            '\u{3000}',
            '\u{e0041}',
            '\u{fe0f}',
            '\u{fffc}',
            '\u{e000}',
        ] {
            let sh = shown(&format!("x{c}y"));
            assert_eq!(sh.text, format!("x\\u{{{:x}}}y", c as u32), "{c:?}");
        }
    }

    #[test]
    fn the_quote_cannot_be_closed_from_inside() {
        let q = quote("a\" \u{b7} Safe \u{b7} \"b");
        assert_eq!(q.text, "\"a\\u{22} \u{b7} Safe \u{b7} \\u{22}b\"");
        assert_eq!(q.text.matches('"').count(), 2);
    }

    #[test]
    fn spaces_that_cannot_be_seen_are_written_out() {
        assert_eq!(
            shown(r"C:\Program Files \x").text,
            r"C:\Program Files\u{20}\x"
        );
        assert_eq!(shown(r"C:\ Program Files").text, r"C:\\u{20}Program Files");
        assert_eq!(shown("a  b").text, r"a \u{20}b");
        assert_eq!(shown("a   ").text, r"a\u{20}\u{20}\u{20}");
        assert_eq!(shown(" ").text, r"\u{20}");
        assert_eq!(shown("two words").text, "two words");
    }

    #[test]
    fn look_alike_letters_in_a_latin_word_are_written_out() {
        let sh = shown("Mozill\u{430}");
        assert_eq!(sh.text, r"Mozill\u{430}");
        assert!(sh.flags.escaped);
        // Greek omicron, full-width letter, mathematical letter, dotless i.
        assert_eq!(shown("g\u{3bf}\u{3bf}gle").text, r"g\u{3bf}\u{3bf}gle");
        assert_eq!(shown("a\u{ff42}c").text, r"a\u{ff42}c");
        assert_eq!(shown("\u{1d41a}pp").text, r"\u{1d41a}pp");
        // The check is per word: a Cyrillic word next to a Latin word is not mixed.
        assert_eq!(
            shown("\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441} Browser").text,
            "\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441} Browser"
        );
        let path = "C:\\\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441}\\Browser";
        assert_eq!(shown(path).text, path);
        assert_eq!(
            shown("\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441}7").text,
            r"\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441}7"
        );
    }

    #[test]
    fn a_long_component_keeps_both_ends_and_says_so() {
        let name = format!("{}{}", "a".repeat(150), "TAIL-END-OF-THE-NAME.exe");
        let sh = shown(&name);
        assert!(sh.flags.shortened && !sh.flags.escaped);
        assert!(sh.text.starts_with(&"a".repeat(56)));
        assert!(sh.text.ends_with("-OF-THE-NAME.exe"));
        assert!(sh.text.contains("[94 characters not shown]"), "{}", sh.text);
        let kept = sh.text.chars().count() - "[94 characters not shown]".chars().count();
        assert_eq!(kept, NAME_CUT);
        // Exactly 80 is not cut; 81 is.
        assert!(shown(&"b".repeat(80)).flags.is_plain());
        let eighty_one = shown(&"b".repeat(81));
        assert!(eighty_one.text.contains("[1 character not shown]"));
    }

    #[test]
    fn escapes_count_as_one_character_of_the_name() {
        let sh = shown(&"\u{202e}".repeat(90));
        assert!(sh.flags.escaped && sh.flags.shortened);
        // Each escape is one character of the name (at most 80 of them), and the whole text is held
        // to LINE_COST shown characters besides.
        let n = sh.text.matches("\\u{202e}").count();
        assert!(n > 0 && n <= NAME_CUT, "{n}");
        assert!(sh.text.contains("characters not shown]"));
        assert!(sh.text.chars().count() <= LINE_COST);
        let ten = shown(&"\u{202e}".repeat(NAME_CUT + 10));
        assert!(ten.flags.shortened);
    }

    #[test]
    fn a_long_path_of_short_components_keeps_both_ends() {
        let path = format!(r"C:\{}\final.txt", vec!["dir"; 200].join("\\"));
        let sh = shown(&path);
        assert!(sh.flags.shortened);
        assert!(sh.text.starts_with(r"C:\dir\dir"));
        assert!(sh.text.ends_with(r"\dir\final.txt"));
        assert!(sh.text.chars().count() <= LINE_COST);
        assert!(sh.text.contains("characters not shown]"));
    }

    #[test]
    fn the_shown_text_is_bounded_even_when_every_character_is_an_escape() {
        let hostile = format!("{}\\", "\u{202e}".repeat(80)).repeat(100);
        let sh = shown(&hostile);
        assert!(
            sh.text.chars().count() <= LINE_COST + 30,
            "{}",
            sh.text.len()
        );
    }

    #[test]
    fn nothing_but_printable_text_comes_out() {
        let mut all = String::new();
        for u in 0u32..0x3000 {
            if let Some(c) = char::from_u32(u) {
                all.push(c);
            }
        }
        for u in [0xe0001u32, 0xfeff, 0x10ffff, 0x1f600] {
            all.push(char::from_u32(u).unwrap());
        }
        let sh = shown(&all);
        for c in sh.text.chars() {
            assert!(
                !c.is_control() && !hidden(c) && (c == ' ' || !c.is_whitespace()),
                "{c:?} left in the text"
            );
        }
    }

    #[test]
    fn numbers_and_sizes() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(5_000), "5,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(count(1, "item", "items"), "1 item");
        assert_eq!(count(2, "item", "items"), "2 items");
        assert_eq!(size(0), "0 bytes");
        assert_eq!(size(1), "1 byte");
        assert_eq!(size(1023), "1,023 bytes");
        assert_eq!(size(1024), "1.0 KB");
        assert_eq!(size(1536), "1.5 KB");
        assert_eq!(size(1 << 30), "1.0 GB");
        assert_eq!(size((1 << 30) + (1 << 30) / 4), "1.2 GB");
        assert_eq!(size(u64::MAX), "16383.9 PB");
    }

    #[test]
    fn stamps() {
        let s = Stamp {
            year: 2026,
            month: 12,
            day: 1,
            hour: 9,
            minute: 5,
        };
        assert_eq!(s.date(), "2026-12-01");
        assert_eq!(s.date_time(), "2026-12-01 09:05 UTC");
    }
}
