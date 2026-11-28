//! A [`ConsentView`] as one scrolling sheet: what the toolkit dialog (`super::toolkit`) draws, as
//! [`super::dialog::pages`] is what the TaskDialog draws. Pure, and nothing but a regrouping: every
//! line of the view is in the sheet once, in the view's order, and the sheet adds two headings and
//! no other word. Names and paths went through [`super::text`] when the view was built; nothing here
//! formats one.
//!
//! Where the TaskDialog pages the attention list and folds the other items behind "Show details", the
//! sheet has them all in one list that scrolls: the summary, then the attention entries under their
//! heading, then the other items under theirs. The button that approves, the box and the footer are
//! not in the list; they stay in view below it.

use super::text::{MARK, NO_GLYPH_NOTE, TITLE, drawable, fixed_words_drawable};
use super::view::{ConsentView, Icon};

/// The heading over the other items (the TaskDialog's "Show details" part).
pub const OTHERS_HEADING: &str = "The other items";

/// One line of the sheet's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A line of the summary.
    Summary(String),
    /// The heading of the attention list, with its count.
    AttentionHeading(String),
    /// An attention entry: never cut, never summarised.
    Attention(String),
    /// The heading of the other items.
    OthersHeading(String),
    /// One of the other items.
    Other(String),
    /// "and N more of the same kinds".
    More(String),
}

impl Block {
    /// The words of the line.
    pub fn text(&self) -> &str {
        match self {
            Block::Summary(t)
            | Block::AttentionHeading(t)
            | Block::Attention(t)
            | Block::OthersHeading(t)
            | Block::Other(t)
            | Block::More(t) => t,
        }
    }

    /// Whether the sheet added the line (a heading), as opposed to a line of the view.
    pub fn is_heading(&self) -> bool {
        matches!(self, Block::AttentionHeading(_) | Block::OthersHeading(_))
    }
}

/// Everything the toolkit dialog says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sheet {
    /// The window title.
    pub title: String,
    /// The icon.
    pub icon: Icon,
    /// The main instruction.
    pub instruction: String,
    /// The list, top to bottom.
    pub blocks: Vec<Block>,
    /// The text of the verification box; `None` for no box.
    pub verification: Option<String>,
    /// The label of the button that approves.
    pub approve: String,
    /// The footer, which carries the confirmation code.
    pub footer: String,
}

/// The heading of the attention list: the TaskDialog's on a dialog of one page.
pub fn attention_heading(total: usize) -> String {
    format!("{MARK} Needs your attention ({total})")
}

/// The sheet of `view`.
pub fn sheet(view: &ConsentView) -> Sheet {
    let mut blocks: Vec<Block> = view.summary.iter().cloned().map(Block::Summary).collect();
    if !view.attention.is_empty() {
        blocks.push(Block::AttentionHeading(attention_heading(
            view.attention.len(),
        )));
        blocks.extend(
            view.attention
                .iter()
                .map(|e| Block::Attention(e.text.clone())),
        );
    }
    if !view.others.is_empty() || view.others_more.is_some() {
        blocks.push(Block::OthersHeading(OTHERS_HEADING.to_owned()));
        blocks.extend(view.others.iter().map(|e| Block::Other(e.text.clone())));
        blocks.extend(view.others_more.iter().cloned().map(Block::More));
    }
    Sheet {
        title: TITLE.to_owned(),
        icon: view.icon,
        instruction: view.instruction.clone(),
        blocks,
        verification: view.verification.clone(),
        approve: view.button.clone(),
        footer: view.footer.clone(),
    }
}

impl Block {
    /// The same kind of line with other words.
    fn with_text(&self, text: String) -> Block {
        match self {
            Block::Summary(_) => Block::Summary(text),
            Block::AttentionHeading(_) => Block::AttentionHeading(text),
            Block::Attention(_) => Block::Attention(text),
            Block::OthersHeading(_) => Block::OthersHeading(text),
            Block::Other(_) => Block::Other(text),
            Block::More(_) => Block::More(text),
        }
    }
}

impl Sheet {
    /// This sheet for a renderer that draws with a fixed set of fonts (review B1 of
    /// BROKER-CONSENT-UI): every character the set has no glyph for is written as `\u{hex}`
    /// ([`super::text::drawable`]), in every line, the button and the box included, and when one
    /// was, [`NO_GLYPH_NOTE`] ends the summary. The lines, their order and their kinds are the
    /// sheet's own. `has_glyph` is the renderer's answer for one character.
    ///
    /// `None` when the set cannot draw the dialog's own words or an escape
    /// ([`super::text::fixed_words_drawable`]): that renderer must not draw the dialog.
    pub fn drawable(&self, has_glyph: &dyn Fn(char) -> bool) -> Option<Sheet> {
        if !fixed_words_drawable(has_glyph) {
            return None;
        }
        let mut rewrote = false;
        let mut pass = |text: &str| {
            let out = drawable(text, has_glyph);
            rewrote |= matches!(out, std::borrow::Cow::Owned(_));
            out.into_owned()
        };
        let mut sheet = Sheet {
            title: pass(&self.title),
            icon: self.icon,
            instruction: pass(&self.instruction),
            blocks: self
                .blocks
                .iter()
                .map(|b| b.with_text(pass(b.text())))
                .collect(),
            verification: self.verification.as_deref().map(&mut pass),
            approve: pass(&self.approve),
            footer: pass(&self.footer),
        };
        if rewrote {
            let after_summary = sheet
                .blocks
                .iter()
                .take_while(|b| matches!(b, Block::Summary(_)))
                .count();
            sheet
                .blocks
                .insert(after_summary, Block::Summary(NO_GLYPH_NOTE.to_owned()));
        }
        Some(sheet)
    }

    /// Every line the sheet puts in front of the user, in reading order.
    pub fn lines(&self) -> Vec<&str> {
        let mut out: Vec<&str> = vec![&self.title, &self.instruction];
        out.extend(self.blocks.iter().map(Block::text));
        out.extend(self.verification.as_deref());
        out.push(&self.footer);
        out.push(&self.approve);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::dialog::{PRIMARY, pages};
    use super::super::samples;
    use super::*;

    /// The view's own lines, in the order the sheet must keep.
    fn view_lines(v: &ConsentView) -> Vec<&str> {
        let mut out: Vec<&str> = v.summary.iter().map(String::as_str).collect();
        out.extend(v.attention.iter().map(|e| e.text.as_str()));
        out.extend(v.others.iter().map(|e| e.text.as_str()));
        out.extend(v.others_more.as_deref());
        out
    }

    #[test]
    fn the_sheet_is_the_view_regrouped_and_two_headings() {
        for s in samples::all() {
            let v = &s.view;
            let sh = sheet(v);
            let kept: Vec<&str> = sh
                .blocks
                .iter()
                .filter(|b| !b.is_heading())
                .map(Block::text)
                .collect();
            assert_eq!(kept, view_lines(v), "{}", s.name);
            let headings: Vec<&Block> = sh.blocks.iter().filter(|b| b.is_heading()).collect();
            let mut want = Vec::new();
            if !v.attention.is_empty() {
                want.push(Block::AttentionHeading(format!(
                    "{MARK} Needs your attention ({})",
                    v.attention.len()
                )));
            }
            if !v.others.is_empty() || v.others_more.is_some() {
                want.push(Block::OthersHeading(OTHERS_HEADING.into()));
            }
            assert_eq!(headings, want.iter().collect::<Vec<_>>(), "{}", s.name);
            assert_eq!(sh.title, TITLE);
            assert_eq!(sh.instruction, v.instruction, "{}", s.name);
            assert_eq!(sh.approve, v.button, "{}", s.name);
            assert_eq!(sh.footer, v.footer, "{}", s.name);
            assert_eq!(sh.verification, v.verification, "{}", s.name);
            assert_eq!(sh.icon, v.icon, "{}", s.name);
            assert!(sh.footer.contains(&v.code.to_string()), "{}", s.name);
        }
    }

    /// Review B1: for fonts that have every character the sheet is itself; for fonts that lack
    /// some, each such character is an escape in place, the lines keep their number, order and
    /// kinds, one note is added, and the code in the footer is untouched.
    #[test]
    fn the_sheet_for_fixed_fonts_escapes_what_they_lack_and_nothing_else() {
        let ascii_and_marks = |c: char| c.is_ascii() || "\u{26a0}\u{2022}\u{b7}".contains(c);
        let mut rewritten = 0;
        for s in samples::all() {
            let sh = sheet(&s.view);
            assert_eq!(sh.drawable(&|_| true).as_ref(), Some(&sh), "{}", s.name);
            assert_eq!(sh.drawable(&|_| false), None, "{}", s.name);
            let got = sh.drawable(&ascii_and_marks).unwrap();
            for line in got.lines() {
                assert!(line.chars().all(ascii_and_marks), "{}: {line}", s.name);
            }
            assert_eq!(got.footer, sh.footer, "{}", s.name);
            assert!(got.footer.contains(&s.view.code.to_string()), "{}", s.name);
            assert_eq!((got.title.as_str(), got.icon), (TITLE, sh.icon));
            if got == sh {
                continue;
            }
            rewritten += 1;
            let note = Block::Summary(NO_GLYPH_NOTE.to_owned());
            assert_eq!(
                got.blocks.iter().filter(|b| **b == note).count(),
                1,
                "{}",
                s.name
            );
            let at = got.blocks.iter().position(|b| *b == note).unwrap();
            assert!(
                got.blocks[..at]
                    .iter()
                    .all(|b| matches!(b, Block::Summary(_))),
                "{}",
                s.name
            );
            assert!(
                !matches!(got.blocks.get(at + 1), Some(Block::Summary(_))),
                "{}",
                s.name
            );
            let mut rest = got.blocks.clone();
            rest.remove(at);
            assert_eq!(rest.len(), sh.blocks.len(), "{}", s.name);
            for (new, old) in rest.iter().zip(&sh.blocks) {
                assert_eq!(
                    std::mem::discriminant(new),
                    std::mem::discriminant(old),
                    "{}",
                    s.name
                );
                assert_eq!(
                    new.text(),
                    drawable(old.text(), &ascii_and_marks),
                    "{}",
                    s.name
                );
            }
        }
        assert!(
            rewritten > 0,
            "a sample has a name outside ASCII, or this tests nothing"
        );
    }

    /// Both renderers say the same: every entry the TaskDialog's pages name is in the sheet, and
    /// the sheet names no entry they do not.
    #[test]
    fn the_sheet_and_the_pages_name_the_same_entries() {
        for s in samples::all() {
            let v = &s.view;
            let sh = sheet(v);
            let paged: String = pages(v)
                .iter()
                .flat_map(|p| [p.content.as_str(), p.expanded.as_deref().unwrap_or("")])
                .collect::<Vec<_>>()
                .join("\n");
            for b in sh.blocks.iter().filter(|b| !b.is_heading()) {
                assert!(paged.contains(b.text()), "{}: {:?}", s.name, b.text());
            }
            let last = pages(v).pop().unwrap();
            assert_eq!(last.buttons[0].id, PRIMARY);
            assert_eq!(last.buttons[0].label, sh.approve, "{}", s.name);
            assert_eq!(last.verification, sh.verification, "{}", s.name);
            assert_eq!(
                last.footer.as_deref(),
                Some(sh.footer.as_str()),
                "{}",
                s.name
            );
            assert_eq!(last.instruction, sh.instruction, "{}", s.name);
        }
    }

    #[test]
    fn a_long_attention_list_is_whole_and_in_order() {
        let long = samples::all()
            .into_iter()
            .find(|s| s.name == "quarantine-long")
            .unwrap();
        let sh = sheet(&long.view);
        let attention: Vec<&str> = sh
            .blocks
            .iter()
            .filter_map(|b| match b {
                Block::Attention(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(attention.len(), 200);
        assert_eq!(
            attention,
            long.view
                .attention
                .iter()
                .map(|e| e.text.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            sh.blocks
                .contains(&Block::AttentionHeading(attention_heading(200)))
        );
    }

    #[test]
    fn no_sample_line_carries_a_control_or_bidi_character() {
        for s in samples::all() {
            for line in sheet(&s.view).lines() {
                for c in line.chars() {
                    let u = c as u32;
                    let bad = c.is_control()
                        || matches!(u, 0x200B..=0x200F | 0x2028..=0x202F | 0x2060..=0x206F | 0xFEFF);
                    assert!(!bad, "{}: {c:?} in {line:?}", s.name);
                }
            }
        }
    }
}
