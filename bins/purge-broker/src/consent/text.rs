//! The words of the consent dialog and the rules that keep a name or a path from misleading (design 8
//! and T12).
//!
//! Every name and path the dialog shows goes through [`shown`] or [`quote`], and nothing else puts
//! text from a scan, a program or a journal into the dialog. What [`shown`] does:
//!
//! - control characters (C0, DEL, C1), bidirectional controls, zero-width and other invisible
//!   characters (the braille blank included), line and paragraph separators, every space that is not
//!   a plain space, private-use and non-characters, and the double quote are written as `\u{hex}`;
//! - the backslash of a literal `\u{` is written as `\u{5c}`, so that every `\u{` in the dialog is an
//!   escape (review N5);
//! - a plain space is written that way too when it starts or ends a path component or follows another
//!   space, so `Program Files` and `Program Files ` and `Program  Files` do not look alike;
//! - in a word that holds an ASCII letter or digit, every alphanumeric character outside Basic Latin,
//!   the Latin-1 letters, Latin Extended-A and Latin Extended Additional is written that way, so
//!   `Mozill\u{430}` and `Goog\u{217c}e` cannot pass for `Mozilla` and `Google`; a whole word of one
//!   other script is shown as it is;
//! - a path whose last component is wholly in a script that borrows Latin shapes while the components
//!   before it are ASCII (a folder under `C:\Vendor` named in Cyrillic letters that read "Apple") is
//!   shown as it is but flagged: the view adds an attention reason;
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
    /// A path's last component is wholly in a script that borrows Latin shapes, while the components
    /// before it are ASCII. The text is shown as it is; the view turns this into an attention reason
    /// (review S6).
    pub look_alike: bool,
}

impl Flags {
    /// Adds what `other` did.
    pub fn merge(&mut self, other: Flags) {
        self.escaped |= other.escaped;
        self.shortened |= other.shortened;
        self.look_alike |= other.look_alike;
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
                | 0x2800
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

/// Letters of blocks whose shapes can pass for Latin ones (review S6 added the small Roman numerals,
/// the dental click, Lisu, Cherokee small letters and the phonetic small capitals).
fn borrows_latin_shapes(c: char) -> bool {
    matches!(
        c as u32,
        0x1C0
            | 0x250..=0x2AF
            | 0x370..=0x3FF
            | 0x400..=0x52F
            | 0x531..=0x58F
            | 0x1C80..=0x1C8F
            | 0x13A0..=0x13FF
            | 0x2100..=0x214F
            | 0x2170..=0x217F
            | 0x2C80..=0x2CFF
            | 0xA4D0..=0xA4FF
            | 0xA640..=0xA69F
            | 0xAB70..=0xABBF
            | 0xFF01..=0xFF5E
            | 0x1D00..=0x1D7F
            | 0x1D400..=0x1D7FF
    )
}

/// Whether a character may be shown as itself in a word that also holds an ASCII letter or digit:
/// Basic Latin (letters and digits), the Latin-1 letters, Latin Extended-A and Latin Extended
/// Additional (review S6).
fn latin_like(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || (c.is_alphabetic() && matches!(c as u32, 0xC0..=0xFF | 0x100..=0x17F | 0x1E00..=0x1EFF))
}

/// For each character, whether it sits in a word that holds an ASCII letter or digit and is an
/// alphanumeric character outside the Latin allow-list of [`latin_like`] (review S6).
fn look_alike_in_word(chars: &[char]) -> Vec<bool> {
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
        if word.iter().any(char::is_ascii_alphanumeric) {
            for (i, c) in word.iter().enumerate() {
                out[start + i] = c.is_alphanumeric() && !latin_like(*c);
            }
        }
        start = end;
    }
    out
}

/// Whether every alphanumeric character of `comp` is in a block that borrows Latin shapes, and there
/// is at least one.
fn wholly_look_alike(comp: &str) -> bool {
    let mut alnum = 0usize;
    for c in comp.chars().filter(|c| c.is_alphanumeric()) {
        if !borrows_latin_shapes(c) {
            return false;
        }
        alnum += 1;
    }
    alnum > 0
}

fn escape(c: char) -> String {
    format!("\\u{{{:x}}}", c as u32)
}

/// Whether `rest` starts with a literal `\u{`: text from outside that reads as an escape Purge
/// wrote (review N5). Its backslash is written as `\u{5c}`, so that every `\u{` in the dialog is
/// one of Purge's escapes and stands for the one character it names: a key named `u{430}` under
/// `HKCU\Software` reads `HKCU\Software\u{5c}u{430}`, not as a Cyrillic letter, and a name cannot
/// pass a word off as a character the font did not have ([`NO_GLYPH_NOTE`]).
fn starts_literal_escape(rest: &[char]) -> bool {
    matches!(rest, ['\\', 'u', '{', ..])
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
fn component(comp: &str, flags: &mut Flags, cut: bool) -> Vec<String> {
    let chars: Vec<char> = comp.chars().collect();
    let look_alike = look_alike_in_word(&chars);
    let first_visible = chars.iter().position(|c| *c != ' ');
    let last_visible = chars.iter().rposition(|c| *c != ' ');
    let mut out: Vec<String> = Vec::with_capacity(chars.len().min(NAME_CUT + 1));
    for (i, &c) in chars.iter().enumerate() {
        let escape_it = if c == ' ' {
            first_visible.is_none_or(|f| i < f)
                || last_visible.is_none_or(|l| i > l)
                || chars[i - 1] == ' '
        } else {
            hidden(c) || look_alike[i] || starts_literal_escape(&chars[i..])
        };
        if escape_it {
            flags.escaped = true;
            out.push(escape(c));
        } else {
            out.push(c.to_string());
        }
    }
    if cut && out.len() > NAME_CUT {
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
    let mut parts: Vec<(&str, &str)> = Vec::new();
    for part in text.split_inclusive(['\\', '/']) {
        match part.strip_suffix(['\\', '/']) {
            Some(comp) => parts.push((comp, &part[comp.len()..])),
            None => parts.push((part, "")),
        }
    }
    // A path whose last component is wholly in a look-alike script, while the components before it
    // are ASCII, is shown as it is and flagged (review S6).
    if let Some(last) = parts.iter().rposition(|(comp, _)| !comp.is_empty()) {
        if last > 0
            && parts[..last].iter().all(|(comp, _)| comp.is_ascii())
            && wholly_look_alike(parts[last].0)
        {
            flags.look_alike = true;
        }
    }
    for (k, &(comp, sep)) in parts.iter().enumerate() {
        pieces.extend(component(comp, &mut flags, true));
        if sep.is_empty() {
            continue;
        }
        // A separator that starts a literal `\u{` with the next component (review N5).
        if sep == "\\"
            && parts
                .get(k + 1)
                .is_some_and(|(next, _)| next.starts_with("u{"))
        {
            flags.escaped = true;
            pieces.push(escape('\\'));
        } else {
            pieces.push(sep.to_owned());
        }
    }
    cap_line(&mut pieces, &mut flags);
    Shown {
        text: pieces.concat(),
        flags,
    }
}

/// Free text for the dialog: the same escapes as [`shown`], but `\` and `/` do not end a component, so
/// a command's arguments (`/S /D=C:\x`) are one piece, and only the whole text is cut ([`LINE_COST`]).
pub fn shown_line(text: &str) -> Shown {
    let mut flags = Flags::default();
    let mut pieces = component(text, &mut flags, false);
    cap_line(&mut pieces, &mut flags);
    Shown {
        text: pieces.concat(),
        flags,
    }
}

/// [`shown_line`] in double quotes.
pub fn quote_line(text: &str) -> Shown {
    let mut s = shown_line(text);
    s.text = format!("\"{}\"", s.text);
    s
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

/// What a sheet says when [`drawable`] wrote a character as an escape.
pub const NO_GLYPH_NOTE: &str =
    "Characters this window has no font for are shown as \\u{...}; they are part of the name.";

/// The characters the dialog's own words and every escape are made of: printable ASCII and the
/// three marks. [`drawable`] never rewrites them; [`fixed_words_drawable`] is the check that it
/// need not.
fn fixed(c: char) -> bool {
    (' '..='~').contains(&c) || [MARK, BULLET, SEP].iter().any(|m| m.contains(c))
}

/// Whether a renderer can draw the dialog's own words and every escape: it has a glyph for each
/// printable ASCII character and for the three marks. A renderer that cannot must not draw the
/// dialog at all (the broker asks with the TaskDialog): an escape it cannot draw says nothing.
pub fn fixed_words_drawable(has_glyph: &dyn Fn(char) -> bool) -> bool {
    ('!'..='~')
        .chain([MARK, BULLET, SEP].iter().flat_map(|m| m.chars()))
        .filter(|c| *c != ' ')
        .all(has_glyph)
}

/// `text`, which is ready for the dialog, for a renderer that draws with a fixed set of fonts
/// (review B1 of BROKER-CONSENT-UI): every character the set has no glyph for is written as
/// `\u{hex}`, as [`shown`] writes a hidden one. Nothing is then drawn as an empty box, as nothing,
/// or with a font that was found by a name anybody can register. `has_glyph` is the renderer's
/// answer for one character; it is not asked about the characters of [`fixed`].
///
/// It is the renderer's pass and not [`shown`]'s: the TaskDialog draws the same view with the
/// system's own fallback and shows these characters as they are.
///
/// A literal `\u{` (review N5) is not this pass's to escape: here it cannot be told from an escape
/// [`shown`] wrote, and both renderers must show it the same. [`shown`] and [`shown_line`] write
/// its backslash as `\u{5c}` where the text enters the view, so every `\u{` this pass sees is an
/// escape, and this pass leaves escapes alone.
pub fn drawable<'a>(text: &'a str, has_glyph: &dyn Fn(char) -> bool) -> std::borrow::Cow<'a, str> {
    drawable_line(text, has_glyph, &[])
}

/// [`drawable`] for a renderer that can also say which parts of a whole line it would not draw:
/// `undrawn` is the byte ranges of `text` its layout draws with a missing glyph (TK-1: a letter and
/// a combining mark that no single font has together are such a range, although each has a glyph
/// alone). A character that is not one of [`fixed`] is written as `\u{hex}` when `has_glyph` says
/// no to it alone, or when it is inside one of the ranges; the characters of [`fixed`] are never
/// rewritten, wherever they are. A range is a whole cluster, so the marks that went with an escaped
/// letter are escaped with it, and what is left of the cluster is characters of [`fixed`], which
/// the renderer draws alone.
pub fn drawable_line<'a>(
    text: &'a str,
    has_glyph: &dyn Fn(char) -> bool,
    undrawn: &[std::ops::Range<usize>],
) -> std::borrow::Cow<'a, str> {
    let keeps =
        |i: usize, c: char| fixed(c) || (has_glyph(c) && !undrawn.iter().any(|r| r.contains(&i)));
    if text.char_indices().all(|(i, c)| keeps(i, c)) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for (i, c) in text.char_indices() {
        if keeps(i, c) {
            out.push(c);
        } else {
            out.push_str(&escape(c));
        }
    }
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A renderer with the Latin fonts only: Basic Latin, Latin-1, Latin Extended-A and the marks.
    fn latin_only(c: char) -> bool {
        (c as u32) < 0x180 || [MARK, BULLET, SEP].iter().any(|m| m.contains(c))
    }

    #[test]
    fn what_the_fonts_cannot_draw_is_written_as_an_escape() {
        // Nothing to do: the same text, not a copy.
        for plain in [
            r"C:\Program Files\Mozilla Firefox",
            "Caf\u{e9} M\u{fc}nchen",
            "\u{26a0} Needs your attention (3)",
            "\u{2022} HKLM\\SOFTWARE\\Vendor \u{b7} 12 values",
            r"Mozill\u{430}",
            "",
        ] {
            let got = drawable(plain, &latin_only);
            assert!(matches!(got, std::borrow::Cow::Borrowed(_)), "{plain}");
            assert_eq!(got, plain);
        }
        // A name in a script the fonts do not have: each character, in order, and nothing else.
        assert_eq!(
            drawable("C:\\\u{65e5}\u{672c}\\app \u{1f600}.exe", &latin_only),
            r"C:\\u{65e5}\u{672c}\app \u{1f600}.exe"
        );
        assert_eq!(
            drawable(
                "\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441} Browser",
                &latin_only
            ),
            r"\u{42f}\u{43d}\u{434}\u{435}\u{43a}\u{441} Browser"
        );
        // A font that claims nothing still leaves the dialog's own characters alone: they are
        // what `fixed_words_drawable` answers for.
        let nothing = |_: char| false;
        assert_eq!(
            drawable("\u{26a0} a\u{e9}b \u{b7} \"x\"", &nothing),
            "\u{26a0} a\\u{e9}b \u{b7} \"x\""
        );
        // An escape is made of characters that are never rewritten: a second pass changes nothing.
        let once = drawable("\u{65e5}\u{e9}", &nothing).into_owned();
        assert_eq!(drawable(&once, &nothing), once);
    }

    /// TK-1, rule 2: what the renderer's layout of the whole line would not draw is written out by
    /// whole clusters, though each character has a glyph alone; the fixed characters stay.
    #[test]
    fn what_the_layout_of_a_line_cannot_draw_is_written_as_an_escape() {
        // One range of a line, as the renderer's layout names it.
        let one = |r: std::ops::Range<usize>| vec![r];
        let all = |_: char| true;
        // A Cyrillic a and U+20DD (bytes 6..11), which no single font has together.
        let line = "Mozill\u{430}\u{20dd}.exe";
        assert_eq!(
            drawable_line(line, &all, &one(6..11)),
            r"Mozill\u{430}\u{20dd}.exe"
        );
        // A range that holds a fixed character: it is drawn alone, so it stays.
        assert_eq!(drawable_line("e\u{20dd}x", &all, &one(0..4)), r"e\u{20dd}x");
        // No range and every glyph: the same text, not a copy.
        let got = drawable_line(line, &all, &[]);
        assert!(matches!(got, std::borrow::Cow::Borrowed(_)));
        // Both rules at once: one character alone, two by their cluster.
        assert_eq!(
            drawable_line("\u{65e5}\u{430}\u{301}", &|c| c != '\u{65e5}', &one(3..7)),
            r"\u{65e5}\u{430}\u{301}"
        );
        // A second pass over the escaped text changes nothing.
        let once = drawable_line(line, &all, &one(6..11)).into_owned();
        assert_eq!(drawable_line(&once, &all, &[]), once);
    }

    /// Review N5: a literal `\u{` from outside cannot pass for one of Purge's escapes, in either
    /// renderer, and the fixed-font pass leaves what `shown` wrote alone.
    #[test]
    fn a_literal_escape_is_escaped_where_the_text_enters() {
        let sh = shown(r"HKCU\Software\u{430}");
        assert_eq!(sh.text, r"HKCU\Software\u{5c}u{430}");
        assert!(sh.flags.escaped);
        let sh = shown(r"C:\Vendor\u{41}\app.exe");
        assert_eq!(sh.text, r"C:\Vendor\u{5c}u{41}\app.exe");
        // In free text the backslash is in the piece.
        let sh = shown_line(r"/D=C:\x \u{202e}");
        assert_eq!(sh.text, r"/D=C:\x \u{5c}u{202e}");
        assert!(sh.flags.escaped);
        // A name that is the sequence alone, and one with the brace missing (no escape then).
        assert_eq!(shown_line(r"\u{").text, r"\u{5c}u{");
        let plain = shown(r"C:\users\u1\app");
        assert_eq!(plain.text, r"C:\users\u1\app");
        assert!(plain.flags.is_plain());
        // The renderer's pass keeps both escapes as they are.
        let sh = shown("C:\\Vendor\\u{430}\\\u{202e}x");
        assert_eq!(sh.text, r"C:\Vendor\u{5c}u{430}\\u{202e}x");
        assert_eq!(drawable(&sh.text, &latin_only), sh.text);
    }

    #[test]
    fn a_renderer_without_the_dialogs_own_characters_is_refused() {
        assert!(fixed_words_drawable(&latin_only));
        assert!(fixed_words_drawable(&|_| true));
        assert!(!fixed_words_drawable(&|_| false));
        // One missing is enough: a letter, a digit, a brace of the escape, each mark.
        for missing in [
            'a', 'Z', '7', '\\', '{', '}', '\u{26a0}', '\u{2022}', '\u{b7}',
        ] {
            assert!(
                !fixed_words_drawable(&|c| c != missing && latin_only(c)),
                "{missing:?}"
            );
        }
        // The plain space needs no glyph.
        assert!(fixed_words_drawable(&|c| c != ' ' && latin_only(c)));
        // The dialog's fixed words are of those characters alone.
        let (one, many) = (left_out(1), left_out(12));
        for words in [
            TITLE,
            MARK,
            BULLET,
            SEP,
            NO_GLYPH_NOTE,
            one.as_str(),
            many.as_str(),
        ] {
            assert!(words.chars().all(fixed), "{words}");
        }
    }

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
    fn free_text_keeps_slashes_and_long_words_but_escapes_the_same_things() {
        let args = r"/S /D=C:\Program Files\Vendor /LOG=C:\Users\Someone\AppData\Local\Temp\a-very-long-file-name-that-goes-on-and-on-and-on-beyond-eighty-characters.log";
        let sh = shown_line(args);
        assert_eq!(sh.text, args);
        assert!(sh.flags.is_plain());
        assert!(
            !shown(args).flags.is_plain(),
            "a path reading would flag it"
        );
        let sh = quote_line("/S \u{202e}x\n  y");
        assert_eq!(sh.text, "\"/S \\u{202e}x\\u{a} \\u{20}y\"");
        assert!(sh.flags.escaped);
        let long = format!("/S {}", "x".repeat(900));
        let sh = shown_line(&long);
        assert!(sh.flags.shortened && sh.text.contains("characters not shown"));
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
            '\u{2800}',
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
    fn the_added_look_alike_scripts_are_written_out_in_a_latin_word() {
        // Small Roman numerals (letter numbers), the dental click, Lisu, Cherokee small letters and
        // the phonetic small capitals (review S6).
        for c in [
            '\u{217c}', '\u{2170}', '\u{1c0}', '\u{a4d0}', '\u{ab70}', '\u{1d00}',
        ] {
            let sh = shown(&format!("a{c}b"));
            assert_eq!(sh.text, format!("a\\u{{{:x}}}b", c as u32), "{c:?}");
            assert!(sh.flags.escaped && !sh.flags.look_alike, "{c:?}");
        }
        assert_eq!(shown("Goog\u{217c}e").text, r"Goog\u{217c}e");
        // Any alphabetic character outside the Latin allow-list is escaped in such a word.
        assert_eq!(shown("a\u{5d0}b").text, r"a\u{5d0}b");
        // The Latin allow-list itself needs no escape: Latin-1, Extended-A, Extended Additional.
        for s in [
            "Caf\u{e9}",
            "\u{141}\u{f3}d\u{17a}",
            "\u{1e62}\u{1e0d}\u{1eb9}",
        ] {
            let sh = shown(&format!("x{s}y"));
            assert!(sh.flags.is_plain(), "{s}: {}", sh.text);
            assert_eq!(sh.text, format!("x{s}y"));
        }
    }

    #[test]
    fn a_path_whose_last_component_is_look_alike_is_flagged_without_escaping() {
        let apple = "\u{410}\u{440}\u{440}\u{4cf}\u{435}";
        let path = format!(r"C:\Vendor\{apple}");
        let sh = shown(&path);
        assert_eq!(sh.text, path, "the text is shown as it is");
        assert!(sh.flags.look_alike && !sh.flags.escaped);
        assert!(sh.flags.is_plain(), "the legend promises escapes only");

        // The same word as a whole name is shown by design, unflagged.
        let bare = shown(apple);
        assert_eq!(bare.text, apple);
        assert!(bare.flags.is_plain() && !bare.flags.look_alike);

        // Only a path whose components before the last are ASCII takes the flag.
        for other in [
            format!("C:\\{apple}\\Vendor"),
            format!("C:\\{}\\{apple}", '\u{5d0}'),
            format!("C:\\Vendor\\{}", "\u{65e5}\u{672c}\u{8a9e}"),
        ] {
            let sh = shown(&other);
            assert!(!sh.flags.look_alike, "{other}");
        }
    }

    #[test]
    fn a_braille_blank_is_invisible() {
        let sh = shown("a\u{2800}b");
        assert_eq!(sh.text, r"a\u{2800}b");
        assert!(sh.flags.escaped);
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
