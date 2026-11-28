# Requests to the toolkit

What Purge needs from the toolkit (`mdshared-ui`, `mdshared-text`; repository
`https://github.com/Kaan88/markdown-shared-rs`) and cannot do itself: Purge does not change the toolkit's
repository. One request per section, written so that it can be handed over as it stands. When one lands, the pin
(`Cargo.toml`, `xtask check-deps` rule 6: `TOOLKIT_REV`, `TOOLKIT_COMMIT`, `TOOLKIT_NAMES`) moves in a commit of its
own and the section here gets the revision that closed it.

| Id | Request | For | State |
|---|---|---|---|
| TK-1 | A fixed list of font files instead of the system's font collection | The broker's toolkit consent dialog (M3_DESIGN 8.3, review B1) | Open. Blocks the toolkit dialog as a default; does not block a release with the TaskDialog |

## TK-1: draw with a fixed list of font files (review B1 of BROKER-CONSENT-UI)

### Why

The broker's consent dialog is drawn by an elevated process and read by the user as the truth about what will be
deleted: names, paths, counts and the confirmation code. At toolkit revision `294d330`, and still at `d789e8e` (the pin since 2026-11-27), every glyph of it comes from
a font that was found **by family name in the system's collection**:

- `Gfx::new()` is the only constructor (`mdshared-ui/src/gfx.rs:168`; line 183 at `d789e8e`). It takes `mdshared_text::shared_fonts()`
  (`mdshared-text/src/fonts.rs:16`): `parley::FontContext::new()`, which is the system's collection through
  DirectWrite, plus `add_fallbacks`, more families by name ("Segoe UI Symbol", "Segoe UI Emoji", "Microsoft
  YaHei", ...).
- Every layout asks for the family list `UI_FAMILY` (`gfx.rs:102`):
  `Segoe UI Variable Text, Segoe UI, Inter, Noto Sans, Cantarell, DejaVu Sans, sans-serif`.
- The frame is painted with a `Gfx` the host makes itself (`mdshared-ui/src/host/run.rs:113`, `gfx: Gfx::new()`);
  an application cannot give the host another.

The system's collection holds the fonts any process of the user installed for that user alone
(`%LOCALAPPDATA%\Microsoft\Windows\Fonts`, `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Fonts`): no
elevation is needed to add one. So a medium-integrity process chooses glyphs the elevated dialog draws:

- Windows 10 has no "Segoe UI Variable Text". A per-user font registered under that name is first in the list for
  **every string** of the dialog.
- On Windows 11 "Inter", "Noto Sans", "Cantarell" and "DejaVu Sans" are free names, asked before the generic
  family for every character the Segoe fonts lack. (The development machine has a per-user `Inter.ttc`: a font
  from that folder is already what the dialog would fall back to.)

A font can draw any character as any other. A path, a count or the code can then read as something else while the
text, the UI Automation tree and the tests all hold the right characters. The TaskDialog does not have this: its
text is drawn by the system with the system's fonts. It also means the elevated process parses font files a medium
process wrote.

### The API

Four additions, none of which changes what an existing caller gets.

```rust
// ---- mdshared-text

/// Fonts read from exactly these files, in this order, and from nowhere else. Immutable once made;
/// `Clone + Send + Sync` (a clone shares the file data).
pub struct FixedFonts { /* private */ }

pub enum FixedFontsError {
    /// The file could not be opened or read.
    Read { file: std::path::PathBuf, error: std::io::Error },
    /// The file was read and holds no font the collection could register.
    NotAFont { file: std::path::PathBuf },
    /// The list is empty.
    Empty,
}

/// Reads each file whole, once, by the path given (no search, no environment), and registers it in a
/// collection of its own: `fontique::Collection::new(CollectionOptions { shared: false, system_fonts:
/// false })`, then `Collection::register_fonts` for each file in order. The system's collection is never
/// enumerated, `add_fallbacks` is not applied, and no fallback family is set for any script. `Err` on the
/// first file that fails: never a shorter list, and never a silent return to the system's collection.
pub fn fixed_fonts(files: &[&std::path::Path]) -> Result<FixedFonts, FixedFontsError>;

impl FixedFonts {
    /// Whether a layout made with these fonts at `weight` draws `c` with a glyph of one of the files:
    /// the families in list order, in each the font the layout's own matching picks for `weight`, and
    /// that font's character map. Nothing is shaped. `false` means the layout would draw `.notdef`.
    pub fn has_glyph(&self, weight: f32, c: char) -> bool;
}

// ---- mdshared-ui

impl Gfx {
    /// A `Gfx` that lays out every `Face` with the families of `fonts`, in the order of the files that
    /// brought them, and nothing else: no family list of names, no generic family at the end, no
    /// fallback by script or locale. A character none of them has is drawn as the first font's
    /// `.notdef`. `shared_fonts()` is not called.
    pub fn with_fonts(fonts: &FixedFonts) -> Gfx;
}

impl Config {
    /// The host makes its own `Gfx` with `Gfx::with_fonts(&fonts)` instead of `Gfx::new()`, and every
    /// other `Gfx` the host or a widget of it makes for this window is made the same way. With this set,
    /// nothing on the window's thread calls `shared_fonts()` or `FontContext::new()`.
    pub fn fonts(self, fonts: FixedFonts) -> Config;
}

impl Face {
    /// The weight a layout of this face asks for (600 for `Semibold`, 400 otherwise): what
    /// `FixedFonts::has_glyph` is asked with.
    pub fn weight(self) -> f32;
}
```

What must hold, and what Purge will test against the new pin:

1. With `Config::fonts` set, a font installed per user under any name ("Segoe UI Variable Text", "Segoe UI",
   "Inter", ...) changes no pixel of the window. (Test: render the samples with and without a planted per-user
   font; the bitmaps are equal.)
2. `has_glyph` and the layout agree: for every character, `has_glyph(face.weight(), c)` is true exactly when the
   layout draws something other than `.notdef` for it. In particular a character the semibold file lacks and the
   regular file of the same family has is answered by what the layout really does for `Face::Semibold`.
3. A missing or unreadable file is an `Err`, not a window drawn with other fonts.
4. `Face::Mono` with fixed fonts lays out with the same list (the broker's dialog does not use it).

### Its use from the broker

All of it is in `bins/purge-broker/src/consent/toolkit/`; nothing else in Purge changes.

- `service.rs`, once, when the first dialog is asked for: `fixed_fonts(&files)` with the three paths below. An
  `Err` is one more "the window cannot be made": the toolkit is marked dead and this dialog and every later one
  is the TaskDialog.
- `service.rs`, `UiThread::run`: `Config::new(..).fonts(fonts.clone())`, and the `Gfx` of the first measuring is
  `Gfx::with_fonts(&fonts)`. `app.rs`, `ConsentApp::new`: its measuring `Gfx` the same.
- `service.rs`, `fonts_have(c)`, which today says yes to everything, becomes
  `fonts.has_glyph(Face::Ui.weight(), c) && fonts.has_glyph(Face::Semibold.weight(), c)`: the two faces the dialog
  draws with (`draw.rs`). It is already what `Sheet::drawable` and `text::fixed_words_drawable` are called with, on
  the serving thread, before the sheet is handed to the window; that is why `FixedFonts` must be `Send + Sync`
  and answer without a `Gfx`.
- `xtask check-deps` rule 6: the new pin, and `fixed_fonts`, `FixedFonts` and `FixedFontsError` of `mdshared_text`
  added to the names the dialog may use.

### The font files

From `GetSystemWindowsDirectoryW()\Fonts` (`purge_win::known_folders::system_windows_dir()`; not `%WINDIR%` or
`%SystemRoot%`: the environment is the caller's, design T7), each opened by its full path. The same three, in this
order, on Windows 10 and Windows 11:

| # | File | Family, weight | For |
|---|---|---|---|
| 1 | `segoeui.ttf` | Segoe UI, 400 | `Face::Ui`: all running text |
| 2 | `seguisb.ttf` | Segoe UI, 600 | `Face::Semibold`: the instruction, the headings, the buttons |
| 3 | `seguisym.ttf` | Segoe UI Symbol, 400 | the mark U+26A0, which Segoe UI does not have; last in the list |

Not in the list, on purpose:

- `SegUIVar.ttf` (Segoe UI Variable, Windows 11 only): the same three files give the same picture on both
  systems, and no variable-font instance has to be resolved in the elevated process.
- `seguiemj.ttf` (Segoe UI Emoji): it also has U+26A0, as a colour glyph; one mark does not need the colour-glyph
  tables parsed in the elevated process.
- `segoeuib.ttf`: the dialog draws nothing bold.
- Any font for another script (`msyh.ttc`, `malgun.ttf`, ...): see the escape rule. Adding one later is a longer
  list, not another mechanism.

Seen on this Windows 11 (build 26300), by the character maps of the files: all three have every printable ASCII
character (U+0021 to U+007E), U+2022 and U+00B7; U+26A0 is in `seguisym.ttf` (and `seguiemj.ttf`) and in neither
`segoeui.ttf`, `seguisb.ttf` nor `SegUIVar.ttf`; `segoeui.ttf` and `seguisb.ttf` have Cyrillic (U+0430),
`seguisym.ttf` does not; none has Han (U+65E5). The files belong to TrustedInstaller; users can only read them.
**Windows 10 was not looked at**: the three files ship with it under these names, and if one is missing or
`seguisym.ttf` there lacks U+26A0, the rules below give the TaskDialog, never a dialog drawn with something else.

### The escape rule for missing glyphs

Purge's side, in the broker already (`consent::text::drawable`, `consent::text::fixed_words_drawable`,
`consent::sheet::Sheet::drawable`, called from `ToolkitConsent::ask_sheet`), written here so that the toolkit's
side can be held to it:

1. **Fixed characters.** Printable ASCII (U+0020 to U+007E) and the three marks U+26A0, U+2022 and U+00B7 are
   what the dialog's own words and every escape are made of. If the fonts lack a glyph for one of them (the space
   needs none), the toolkit window draws **no dialog**: the request is asked with the TaskDialog.
2. **Every other character** of every line (the title, the instruction, each line of the list, the box, the
   button, the footer) is kept when `has_glyph` says the fonts have it for both faces, and is otherwise written in
   place as `\u{hex}`: lower-case hexadecimal, no padding, the form `consent::text::shown` already uses for a
   hidden character. `C:\日本\app.exe` with the three files is `C:\\u{65e5}\u{672c}\app.exe`.
3. **Said once.** A sheet in which a character was written so gets one more summary line, after the last summary
   line: "Characters this window has no font for are shown as \u{...}; they are part of the name."
4. **Nothing else changes.** The lines keep their number, order and kinds; the code in the footer is ASCII and is
   never rewritten; an escape is made of fixed characters only, so a second pass changes nothing. UI Automation
   reads the same escaped text the window draws.
5. **The toolkit never chooses for the broker.** The broker passes the window no character the fonts lack, so
   `.notdef` is never drawn in practice; if one is, it is `.notdef` of file 1 and never a glyph from a font
   outside the list.

The price: a name in a script the three files lack (Han, Arabic, most emoji) is read as escapes in the toolkit
dialog and as itself in the TaskDialog. That is what fonts nobody else can supply cost.

### Until it lands

`service::fonts_have` says yes to every character, so the escape pass changes nothing, and the toolkit dialog
draws with whatever the system's collection gives. The dialog is therefore compiled only with the cargo feature
`toolkit-consent`, which no release build turns on (M3_DESIGN 8.3, "The switch"): a toolkit build of the broker is
for the rig and the preview only, and the TaskDialog is the only consent dialog a release has.
