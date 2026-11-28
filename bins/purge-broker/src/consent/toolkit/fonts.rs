//! The fonts the toolkit dialog draws with, and what they can draw (review B1 of BROKER-CONSENT-UI;
//! the toolkit's half is `docs/TOOLKIT_REQUESTS.md` TK-1, closed at toolkit revision `aff4312`).
//!
//! **Three files and nothing else.** `segoeui.ttf` (Segoe UI 400, [`Face::Ui`]), `seguisb.ttf`
//! (Segoe UI 600, [`Face::Semibold`]) and `seguisym.ttf` (Segoe UI Symbol, for U+26A0), in that
//! order, from the `Fonts` folder of the Windows directory as the kernel records it
//! (`GetSystemWindowsDirectoryW`, [`purge_win::known_folders::system_windows_dir`]; never
//! `%WINDIR%` or `%SystemRoot%`, which are the caller's, design T7). They are read once by
//! [`mdshared_text::fixed_fonts`], whose collection never enumerates the system's fonts, sets no
//! fallback and no generic family. So a font any process of the user installed for that user alone
//! (`%LOCALAPPDATA%\Microsoft\Windows\Fonts` and the `HKCU` `Fonts` key) draws no glyph of the
//! dialog, under any name. The files belong to TrustedInstaller; users can only read them.
//!
//! **What they cannot draw is written out, never drawn** (the escape rule of TK-1):
//!
//! 1. The characters the dialog's own words and every escape are made of (printable ASCII, U+26A0,
//!    U+2022, U+00B7) and U+2026, the ellipsis the toolkit's painter ends a shortened line with,
//!    must each have a glyph in both faces ([`has_glyph`], one character alone). If one has not,
//!    there is no toolkit dialog: [`sheet_for`] is `None` and the request is asked with the
//!    TaskDialog. The painter cuts a shortened line between characters, not clusters; the lines
//!    it shortens in this dialog (the title row, the hint, a button label that would not fit) are
//!    made of those characters alone, so a cut never splits a cluster or an escape.
//! 2. Every other character of every line is written as `\u{hex}` when one face lacks it alone
//!    ([`has_glyph`]) or when the layout of the whole line in either face draws it with the
//!    `.notdef` glyph ([`undrawn`]: a base and a mark that only different files have, such as a
//!    Cyrillic a and U+20DD, which is in `seguisym.ttf` only). Every line of the result is then
//!    laid out again, and a sheet with anything left undrawn is `None` too.
//!
//! An error reading the files (any [`mdshared_text::FixedFontsError`], a variant added later
//! included) is no toolkit dialog either: never the system's fonts instead.

use std::ops::Range;
use std::path::{Path, PathBuf};

use mdshared_text::FixedFonts;
use mdshared_text::FixedFontsError;
use mdshared_text::fixed_fonts;
use mdshared_ui::gfx::Face;

use super::super::sheet::Sheet;
use super::super::text::fixed_words_drawable;

/// The font files under `<Windows>\Fonts`, in the order the layout asks them.
pub const FILES: [&str; 3] = ["segoeui.ttf", "seguisb.ttf", "seguisym.ttf"];

/// The ellipsis the toolkit's painter adds to a line it shortens (`Painter::text`, `elide`): a
/// character the dialog never passed, so rule 1 asks for it with the dialog's own.
pub const ELLIPSIS: char = '\u{2026}';

/// The faces the dialog draws with (`super::draw`): both must draw every character it is given.
const FACES: [Face; 2] = [Face::Ui, Face::Semibold];

/// Why there are no fonts for the dialog.
#[derive(Debug)]
pub enum Unavailable {
    /// `GetSystemWindowsDirectoryW` failed.
    WindowsDir(purge_win::os::Win32Error),
    /// The Windows directory it gave is not a full path.
    NotAbsolute(PathBuf),
    /// A file could not be read as a font.
    Fonts(FixedFontsError),
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unavailable::WindowsDir(e) => write!(f, "no Windows directory: {e:?}"),
            Unavailable::NotAbsolute(p) => {
                write!(
                    f,
                    "the Windows directory {} is not a full path",
                    p.display()
                )
            }
            Unavailable::Fonts(e) => write!(f, "{e}"),
        }
    }
}

/// The three files under `windows` (the Windows directory), in order.
pub fn files_in(windows: &Path) -> [PathBuf; 3] {
    FILES.map(|f| windows.join("Fonts").join(f))
}

/// The dialog's fonts, from the system's Windows directory.
pub fn system() -> Result<FixedFonts, Unavailable> {
    let windows =
        purge_win::known_folders::system_windows_dir().map_err(Unavailable::WindowsDir)?;
    load(&windows)
}

/// The dialog's fonts from the `Fonts` folder of `windows`. Every error is an error: a missing,
/// unreadable, oversized or damaged file is never a shorter list.
pub fn load(windows: &Path) -> Result<FixedFonts, Unavailable> {
    if !windows.is_absolute() {
        return Err(Unavailable::NotAbsolute(windows.to_path_buf()));
    }
    let files = files_in(windows);
    let paths: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    fixed_fonts(&paths).map_err(Unavailable::Fonts)
}

/// Rule 1: whether both faces draw `c`, a character alone.
pub fn has_glyph(fonts: &FixedFonts, c: char) -> bool {
    FACES.iter().all(|f| fonts.has_glyph(f.weight(), c))
}

/// Rule 2: the byte ranges of `line` that the layout of the whole line draws with a missing glyph
/// in either face, in order and joined where they meet.
pub fn undrawn(fonts: &FixedFonts, line: &str) -> Vec<Range<usize>> {
    let mut all: Vec<Range<usize>> = FACES
        .iter()
        .flat_map(|f| fonts.undrawn(f.weight(), line))
        .collect();
    all.sort_by_key(|r| r.start);
    let mut out: Vec<Range<usize>> = Vec::new();
    for r in all {
        match out.last_mut() {
            Some(last) if last.end >= r.start => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

/// Rule 1 whole: the dialog's own words, every escape and the painter's ellipsis.
pub fn own_words_drawable(fonts: &FixedFonts) -> bool {
    let has = |c: char| has_glyph(fonts, c);
    fixed_words_drawable(&has) && has(ELLIPSIS)
}

/// `sheet` as the window may draw it with `fonts`: rules 1 and 2 ([`Sheet::drawable_lines`]).
/// `None`: the toolkit window must not draw it; the TaskDialog asks.
pub fn sheet_for(fonts: &FixedFonts, sheet: &Sheet) -> Option<Sheet> {
    if !own_words_drawable(fonts) {
        return None;
    }
    sheet.drawable_lines(&|c| has_glyph(fonts, c), &|line| undrawn(fonts, line))
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use mdshared_ui::gfx::{Gfx, Painter};

    use super::super::super::samples;
    use super::super::super::sheet::{Block, sheet};
    use super::super::super::text::{NO_GLYPH_NOTE, TITLE};
    use super::*;

    /// The real Segoe files of this machine, read once.
    fn fonts() -> &'static FixedFonts {
        static FONTS: OnceLock<FixedFonts> = OnceLock::new();
        FONTS.get_or_init(|| system().expect("the Segoe UI files are in <Windows>\\Fonts"))
    }

    #[test]
    fn the_three_files_come_from_the_windows_directory_and_nothing_else() {
        let windows = purge_win::known_folders::system_windows_dir().unwrap();
        let fonts = fonts();
        assert_eq!(fonts.files(), files_in(&windows).as_slice());
        assert_eq!(fonts.family_names(), ["Segoe UI", "Segoe UI Symbol"]);
        // The path ends in the names of the table, under Fonts.
        let first = &fonts.files()[0];
        assert!(first.ends_with(r"Fonts\segoeui.ttf"), "{}", first.display());
    }

    #[test]
    fn a_file_that_cannot_be_read_is_no_fonts_never_fewer() {
        let dir = std::env::temp_dir().join(format!("purge-tk1-fonts-{}", std::process::id()));
        let fonts_dir = dir.join("Fonts");
        std::fs::create_dir_all(&fonts_dir).unwrap();
        let windows = purge_win::known_folders::system_windows_dir().unwrap();
        // No file at all.
        assert!(matches!(
            load(&dir),
            Err(Unavailable::Fonts(FixedFontsError::Read { .. }))
        ));
        // Two good files and a third that is not a font.
        for f in &FILES[..2] {
            std::fs::copy(windows.join("Fonts").join(f), fonts_dir.join(f)).unwrap();
        }
        std::fs::write(fonts_dir.join(FILES[2]), b"not a font").unwrap();
        assert!(matches!(
            load(&dir),
            Err(Unavailable::Fonts(FixedFontsError::NotAFont { .. }))
        ));
        // A folder where a file should be.
        std::fs::remove_file(fonts_dir.join(FILES[2])).unwrap();
        std::fs::create_dir(fonts_dir.join(FILES[2])).unwrap();
        assert!(matches!(
            load(&dir),
            Err(Unavailable::Fonts(FixedFontsError::Read { .. }))
        ));
        // A relative Windows directory is refused before anything is read.
        assert!(matches!(
            load(Path::new("Windows")),
            Err(Unavailable::NotAbsolute(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rule 1 with the real files: every fixed character and the ellipsis, in both faces.
    #[test]
    fn the_segoe_files_draw_the_dialogs_own_words_and_the_ellipsis() {
        let fonts = fonts();
        assert!(own_words_drawable(fonts));
        for c in ['\u{26a0}', '\u{2022}', '\u{b7}', ELLIPSIS, 'A', '~'] {
            assert!(has_glyph(fonts, c), "{c:?}");
        }
        // U+26A0 is drawn from seguisym.ttf, the last file: Segoe UI has no glyph for it.
        assert!(fonts.has_glyph(400.0, '\u{26a0}'));
        // Han and Hangul: in none of the three. (An emoji such as U+1F600 is: Segoe UI Symbol has
        // monochrome outlines for many.)
        assert!(!has_glyph(fonts, '\u{65e5}'));
        assert!(!has_glyph(fonts, '\u{ac00}'));
        assert!(has_glyph(fonts, '\u{1f600}'));
        // Cyrillic is in Segoe UI.
        assert!(has_glyph(fonts, '\u{430}'));
    }

    /// Rule 2 with the real files: a Cyrillic a (Segoe UI) and U+20DD (Segoe UI Symbol only) each
    /// have a glyph alone, and the pair is drawn with a missing glyph; the sheet writes it out.
    #[test]
    fn a_letter_and_a_mark_of_different_files_are_written_out() {
        let fonts = fonts();
        assert!(has_glyph(fonts, '\u{430}'));
        assert!(has_glyph(fonts, '\u{20dd}'));
        let line = "C:\\Vendor\\\u{430}\u{20dd}\\app.exe";
        let at = line.find('\u{430}').unwrap();
        let got = undrawn(fonts, line);
        assert!(
            got.iter().any(|r| r.start <= at && r.end > at),
            "{got:?} for {line:?}"
        );
        for face in FACES {
            assert!(!fonts.undrawn(face.weight(), line).is_empty(), "{face:?}");
        }
        let mut sh = sheet(&samples::all()[0].view);
        sh.blocks.push(Block::Other(line.to_owned()));
        let drawn = sheet_for(fonts, &sh).unwrap();
        assert_eq!(
            drawn.blocks.last(),
            Some(&Block::Other(
                r"C:\Vendor\\u{430}\u{20dd}\app.exe".to_owned()
            ))
        );
        assert!(
            drawn
                .blocks
                .contains(&Block::Summary(NO_GLYPH_NOTE.to_owned()))
        );
        for line in drawn.lines() {
            assert_eq!(undrawn(fonts, line), Vec::<Range<usize>>::new(), "{line}");
        }
        // A letter and a mark the same file has: drawn, left as it is.
        assert!(undrawn(fonts, "Caf\u{65}\u{301}").is_empty());
    }

    /// Every sample, as the window gets it: nothing left undrawn in either face, the footer and
    /// its code untouched, and the folder in Han written out.
    #[test]
    fn every_sample_is_drawable_with_the_segoe_files() {
        let fonts = fonts();
        let mut escaped = 0;
        for s in samples::all() {
            let sh = sheet(&s.view);
            let got = sheet_for(fonts, &sh).unwrap_or_else(|| panic!("{}", s.name));
            for line in got.lines() {
                assert!(undrawn(fonts, line).is_empty(), "{}: {line}", s.name);
                assert!(
                    line.chars().all(|c| has_glyph(fonts, c) || c == ' '),
                    "{}: {line}",
                    s.name
                );
            }
            assert_eq!(got.footer, sh.footer, "{}", s.name);
            assert!(got.footer.contains(&s.view.code.to_string()), "{}", s.name);
            assert_eq!(got.title, TITLE);
            if got != sh {
                escaped += 1;
                assert!(
                    got.lines().iter().any(|l| l.contains(r"\u{65e5}")),
                    "{}",
                    s.name
                );
            }
        }
        assert!(escaped > 0, "the hostile sample has a Han folder");
    }

    /// The painter shortens a line with U+2026: the title row of a narrow window ends in it, and
    /// the fixed fonts draw what it gives.
    #[test]
    fn an_elided_line_is_drawn_whole() {
        let fonts = fonts();
        let mut gfx = Gfx::with_fonts(fonts);
        let mut scratch = mdshared_text::Bitmap::new(1, 1);
        let mut p = Painter::new(&mut scratch, &mut gfx, 1.0);
        for face in FACES {
            let full = p.measure(face, 12.0, TITLE);
            let cut = p.elide(face, 12.0, TITLE, full / 2.0);
            assert!(cut.ends_with(ELLIPSIS), "{cut}");
            assert!(cut.chars().count() < TITLE.chars().count());
            assert!(fonts.undrawn(face.weight(), &cut).is_empty(), "{cut}");
        }
    }

    /// The measuring `Gfx` lays out with the files' families only: a name the files do not have
    /// cannot be reached, and a Han character is drawn as the first font's missing glyph, which is
    /// what `undrawn` reports.
    #[test]
    fn the_layout_and_the_check_agree_on_what_is_missing() {
        let fonts = fonts();
        for (text, missing) in [("abc", false), ("a\u{65e5}c", true), ("\u{26a0} x", false)] {
            for face in FACES {
                assert_eq!(
                    !fonts.undrawn(face.weight(), text).is_empty(),
                    missing,
                    "{text:?} {face:?}"
                );
            }
        }
    }
}
