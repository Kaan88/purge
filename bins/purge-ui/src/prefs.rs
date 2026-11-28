//! The window's settings file: `%LOCALAPPDATA%\Purge\ui-settings.ini`, a `[purge-ui]` section of
//! `key=value` lines with a `version`, written whole and atomically on every change
//! (`mdshared_app::settings`).
//!
//! A value that is missing or not understood is the default, and a file of a newer version is
//! read for the keys this build knows; it is never refused, so a settings file can never keep the
//! window from opening. A file that cannot be read for any other reason (locked, no access) is
//! left alone: the defaults are used and nothing is written over it this run.
//!
//! The same file keeps where the window was (`window`, the toolkit's
//! [`WindowState::to_setting`]): not a choice shown on the Settings page, so it is kept apart from
//! [`Prefs`], in the [`Store`]. A missing or damaged value is a first launch (`winplace`).
//!
//! Deliberately not here: anything the engine or the broker decides (what is ticked, how long the
//! quarantine keeps things). Those are facts of the version, stated on the Settings page.

use std::path::PathBuf;

use mdshared_app::backdrop::Backdrop;
use mdshared_app::settings;
use mdshared_ui::window_state::WindowState;

use crate::look::{Choice, Design, Preset, ThemeChoice, Transition};

/// The file's format. Raise it when a key changes meaning, not when one is added (`backdrop`
/// came later than version 1 and needed none: a file without it has the default).
pub const VERSION: u32 = 1;
const SECTION: &str = "purge-ui";
/// The key of the window's place.
const WINDOW: &str = "window";

/// What the user chose on the Settings page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prefs {
    pub design: Design,
    pub transition: Transition,
    pub preset: Preset,
    pub theme: ThemeChoice,
    /// What shows behind the title row and the rail, in either design.
    pub backdrop: Backdrop,
    /// UI-FULLFROST: where the backdrop shows and how strongly (`backdrop_covers`,
    /// `backdrop_strength`; `glass::Glass`).
    pub glass: crate::glass::GlassPrefs,
}

impl Default for Prefs {
    fn default() -> Prefs {
        Prefs {
            design: Design::Bold,
            transition: Transition::Slide,
            preset: Preset::Violet,
            theme: ThemeChoice::System,
            backdrop: Backdrop::Acrylic,
            // UI-FULLFROST.
            glass: crate::glass::GlassPrefs::default(),
        }
    }
}

impl Prefs {
    /// Reads the text of a settings file; defaults for whatever it lacks.
    pub fn parse(text: &str) -> Prefs {
        let mut p = Prefs::default();
        for (key, value) in settings::pairs(text) {
            let v = settings::unescape(value.trim());
            // UI-FULLFROST: the backdrop's two keys.
            if p.glass.read(key, &v) {
                continue;
            }
            match key {
                "design" => p.design = Design::parse(&v).unwrap_or(p.design),
                "transition" => p.transition = Transition::parse(&v).unwrap_or(p.transition),
                "colour" => p.preset = Preset::parse(&v).unwrap_or(p.preset),
                "theme" => p.theme = ThemeChoice::parse(&v).unwrap_or(p.theme),
                "backdrop" => p.backdrop = Backdrop::parse(&v).unwrap_or(p.backdrop),
                _ => {}
            }
        }
        p
    }

    /// The text of the settings file, with no window place.
    #[cfg(test)]
    pub fn text(&self) -> String {
        self.text_with(None)
    }

    /// The text of the settings file, with the window's place when there is one.
    pub fn text_with(&self, window: Option<&WindowState>) -> String {
        let mut w = settings::Writer::new(SECTION);
        w.line("version", &VERSION.to_string());
        w.line("design", self.design.name());
        w.line("transition", self.transition.name());
        w.line("colour", self.preset.name());
        w.line("backdrop", self.backdrop.key());
        w.line("theme", self.theme.name());
        if let Some(state) = window {
            w.line(WINDOW, &state.to_setting());
        }
        // UI-FULLFROST.
        self.glass.write(&mut w);
        w.finish()
    }
}

/// The window's place a settings file keeps, or `None` (a first launch) when it has none or one
/// that does not read. The last `window` line counts.
pub fn window_of(text: &str) -> Option<WindowState> {
    settings::pairs(text)
        .filter(|(key, _)| *key == WINDOW)
        .last()
        .and_then(|(_, value)| WindowState::from_setting(value.trim()))
}

/// Where the settings live, and whether they may be written.
pub struct Store {
    path: Option<PathBuf>,
    writable: bool,
    /// The window's place, as read and as last saved: written with every save.
    window: Option<WindowState>,
}

impl Store {
    /// `%LOCALAPPDATA%\Purge\ui-settings.ini`.
    pub fn user() -> Store {
        Store {
            path: settings::data_dir("Purge").map(|d| d.join("ui-settings.ini")),
            writable: true,
            window: None,
        }
    }

    /// No file: the defaults, and nothing is saved (the scripted walk, tests).
    pub fn none() -> Store {
        Store {
            path: None,
            writable: false,
            window: None,
        }
    }

    /// The file at `path` (tests).
    #[cfg(test)]
    pub fn at(path: PathBuf) -> Store {
        Store {
            path: Some(path),
            writable: true,
            window: None,
        }
    }

    /// The settings, or the defaults. A file that exists but cannot be read is not written
    /// over later.
    pub fn load(&mut self) -> Prefs {
        let Some(path) = &self.path else {
            return Prefs::default();
        };
        match settings::read_patiently(path) {
            Ok(Some(text)) => {
                self.window = window_of(&text);
                Prefs::parse(&text)
            }
            Ok(None) => Prefs::default(),
            Err(e) => {
                eprintln!(
                    "Purge: {} could not be read ({e}); the defaults are used",
                    path.display()
                );
                self.writable = false;
                Prefs::default()
            }
        }
    }

    /// Writes the settings `p`. The window's place is the file's as it is now, when it has
    /// one: another Purge window may have saved its place since this one read the file, and a
    /// change of a setting here must not put an older place back. A failure is said on stderr
    /// and changes nothing else: the window goes on with what was chosen.
    ///
    /// A file that is there but cannot be read is not written over (review S3): it may hold
    /// what another window saved. Nothing more is written this run either, so a slider drag
    /// does not wait out the two-second patient read on every step.
    pub fn save(&mut self, p: &Prefs) {
        let Some(path) = self.writable_path() else {
            return;
        };
        match settings::read_patiently(&path) {
            Ok(Some(text)) => {
                if let Some(theirs) = window_of(&text) {
                    self.window = Some(theirs);
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "Purge: {} could not be read ({e}); the settings are not saved this run",
                    path.display()
                );
                self.writable = false;
                return;
            }
        }
        write(&path, &p.text_with(self.window.as_ref()));
    }

    /// The file, when it may be written and its folder is there.
    fn writable_path(&self) -> Option<PathBuf> {
        let (Some(path), true) = (&self.path, self.writable) else {
            return None;
        };
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            eprintln!("Purge: {} could not be made ({e})", dir.display());
            return None;
        }
        Some(path.clone())
    }
}

fn write(path: &std::path::Path, text: &str) {
    if let Err(e) = settings::write_atomic(path, text) {
        eprintln!("Purge: {} could not be written ({e})", path.display());
    }
}

/// Whether `text` has this file's `[purge-ui]` section header.
fn has_section(text: &str) -> bool {
    let header = format!("[{SECTION}]");
    text.lines().any(|l| l.trim() == header)
}

/// `text` with its `window` line (all of them) replaced by one for `state`, where the first
/// was, or at the end. Every other line is kept as it is, keys this build does not know too.
fn with_window(text: &str, state: &WindowState) -> String {
    let line = format!("{WINDOW}={}", state.to_setting());
    let mut out = String::with_capacity(text.len() + line.len() + 1);
    let mut placed = false;
    for l in text.lines() {
        let is_window = l.split_once('=').is_some_and(|(k, _)| k.trim() == WINDOW);
        if !is_window {
            out.push_str(l);
            out.push('\n');
        } else if !placed {
            out.push_str(&line);
            out.push('\n');
            placed = true;
        }
    }
    if !placed {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

impl Store {
    /// The window's place the file had: `None` is a first launch.
    pub fn window(&self) -> Option<WindowState> {
        self.window.clone()
    }

    /// Saves the window's place. The file is read again and only its `window` line is replaced:
    /// its settings are kept as they are now, so another Purge window's later change is not
    /// written over with this one's older settings. `p` (this run's file settings) is written
    /// only when there is no file yet; a file that cannot be read is left alone.
    pub fn save_window(&mut self, p: &Prefs, state: WindowState) {
        let Some(path) = self.writable_path() else {
            self.window = Some(state);
            return;
        };
        let text = match settings::read_patiently(&path) {
            // A damaged file (no `[purge-ui]` header: cut short, emptied, written by something
            // else) is written whole, so place saves heal it (review N3).
            Ok(Some(text)) if has_section(&text) => with_window(&text, &state),
            Ok(_) => p.text_with(Some(&state)),
            Err(e) => {
                eprintln!(
                    "Purge: {} could not be read ({e}); the window's place is not saved",
                    path.display()
                );
                self.window = Some(state);
                return;
            }
        };
        self.window = Some(state);
        write(&path, &text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = Prefs {
            design: Design::Bold,
            transition: Transition::Depth,
            preset: Preset::Amber,
            theme: ThemeChoice::Dark,
            backdrop: Backdrop::Mica,
            ..Prefs::default()
        };
        assert_eq!(Prefs::parse(&p.text()), p);
        assert!(p.text().starts_with("[purge-ui]\nversion=1\n"));
    }

    #[test]
    fn the_defaults_are_bold_violet_and_acrylic() {
        let p = Prefs::default();
        assert_eq!(
            (p.design, p.preset, p.backdrop),
            (Design::Bold, Preset::Violet, Backdrop::Acrylic)
        );
        // A version-1 file from before the backdrop key keeps what it says, and gets the
        // default backdrop.
        let old = Prefs::parse("[purge-ui]\nversion=1\ndesign=standard\ncolour=blue\n");
        assert_eq!(
            (old.design, old.preset, old.backdrop),
            (Design::Standard, Preset::Blue, Backdrop::Acrylic)
        );
    }

    #[test]
    fn unknown_and_missing_values_are_the_defaults() {
        let p = Prefs::parse("[purge-ui]\nversion=7\ndesign=sparkly\ncolour=teal\nnew-key=1\n");
        assert_eq!(
            p,
            Prefs {
                preset: Preset::Teal,
                ..Prefs::default()
            }
        );
        assert_eq!(Prefs::parse(""), Prefs::default());
        assert_eq!(
            Prefs::parse("[purge-ui]\nversion=1\nbackdrop=MICA\n").backdrop,
            Backdrop::Mica
        );
        assert_eq!(
            Prefs::parse("[purge-ui]\nversion=1\nbackdrop=glass\n").backdrop,
            Backdrop::Acrylic,
            "unknown is the default"
        );
        assert_eq!(Prefs::parse("garbage \u{0} lines"), Prefs::default());
    }

    #[test]
    fn saved_and_loaded_from_a_file() {
        let dir = std::env::temp_dir().join(format!("purge-ui-prefs-{}", std::process::id()));
        let path = dir.join("sub").join("ui-settings.ini");
        let mut store = Store::at(path.clone());
        assert_eq!(store.load(), Prefs::default(), "no file yet");
        let p = Prefs {
            transition: Transition::None,
            ..Prefs::default()
        };
        store.save(&p);
        assert_eq!(Store::at(path).load(), p);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn state() -> WindowState {
        WindowState::from_setting(
            r"x=120.5;y=64;w=1480;h=940;max=1;scale=1.5;mon=\\.\DISPLAY1;monx=0;mony=0;monw=2560;monh=1440",
        )
        .unwrap()
    }

    #[test]
    fn the_window_key_reads_back_and_keeps_the_version() {
        let s = state();
        let text = Prefs::default().text_with(Some(&s));
        assert!(text.starts_with("[purge-ui]\nversion=1\n"));
        assert!(text.contains("\nwindow=x=120.50;y=64.00;w=1480.00;h=940.00;max=1;"));
        assert_eq!(window_of(&text), Some(s.clone()));
        assert_eq!(Prefs::parse(&text), Prefs::default(), "the prefs ignore it");
        assert_eq!(
            window_of(&Prefs::default().text()),
            None,
            "missing: first launch"
        );
        assert_eq!(s.monitor.name.as_deref(), Some(r"\\.\DISPLAY1"));
    }

    #[test]
    fn a_damaged_window_value_is_a_first_launch() {
        for bad in [
            "window=",
            "window=garbage",
            "window=x=1;y=2;w=0;h=10;max=0;scale=1;mon=;monx=0;mony=0;monw=10;monh=10",
            "window=x=1;y=2;w=10;h=10;max=2;scale=1;mon=;monx=0;mony=0;monw=10;monh=10",
            "window=x=NaN;y=2;w=10;h=10;max=0;scale=1;mon=;monx=0;mony=0;monw=10;monh=10",
            "window=x=1;y=2;w=10;h=10;max=0;scale=1",
        ] {
            let text = format!("[purge-ui]\nversion=1\n{bad}\n");
            assert_eq!(window_of(&text), None, "{bad}");
        }
        // The last line counts.
        let good = state().to_setting();
        let text = format!("window=garbage\nwindow={good}\n");
        assert_eq!(window_of(&text), Some(state()));
    }

    #[test]
    fn a_prefs_save_keeps_the_window_and_a_window_save_keeps_the_prefs() {
        let dir = std::env::temp_dir().join(format!("purge-ui-window-{}", std::process::id()));
        let path = dir.join("ui-settings.ini");
        let mut store = Store::at(path.clone());
        store.load();
        assert_eq!(store.window(), None);
        let p = Prefs {
            preset: Preset::Rose,
            ..Prefs::default()
        };
        store.save_window(&p, state());
        let mut again = Store::at(path.clone());
        assert_eq!(again.load(), p);
        assert_eq!(again.window(), Some(state()));
        again.save(&Prefs::default());
        let mut third = Store::at(path);
        assert_eq!(third.load(), Prefs::default());
        assert_eq!(third.window(), Some(state()), "kept by a prefs save");
        let _ = std::fs::remove_dir_all(dir);
    }

    // ---- UI-FULLFROST ----

    #[test]
    fn the_backdrop_keys_round_trip_and_default_when_missing() {
        use crate::glass::{GlassPrefs, STRENGTH_DEFAULT};
        use crate::look::Covers;
        let p = Prefs {
            glass: GlassPrefs {
                covers: Covers::Window,
                strength: 35,
            },
            ..Prefs::default()
        };
        let text = p.text();
        assert!(text.contains("backdrop_covers=window\n"), "{text}");
        assert!(text.contains("backdrop_strength=35\n"), "{text}");
        assert!(
            text.starts_with("[purge-ui]\nversion=1\n"),
            "the version stays 1"
        );
        assert_eq!(Prefs::parse(&text), p);
        // A file from before the two keys: today's look, the default strength.
        let old = Prefs::parse("[purge-ui]\nversion=1\nbackdrop=mica\n");
        assert_eq!(
            (old.glass.covers, old.glass.strength),
            (Covers::Chrome, STRENGTH_DEFAULT)
        );
        // Not understood: the default; past the end: the end.
        let odd = Prefs::parse(
            "[purge-ui]\nversion=1\nbackdrop_covers=everything\nbackdrop_strength=lots\n",
        );
        assert_eq!(odd.glass, GlassPrefs::default());
        let big = Prefs::parse("[purge-ui]\nversion=1\nbackdrop_strength=250\n");
        assert_eq!(big.glass.strength, 100);
    }

    fn other_state() -> WindowState {
        WindowState::from_setting(
            r"x=10;y=20;w=900;h=700;max=0;scale=1;mon=\\.\DISPLAY2;monx=2560;mony=0;monw=1920;monh=1080",
        )
        .unwrap()
    }

    #[test]
    fn two_windows_on_one_file_keep_each_others_changes() {
        let dir = std::env::temp_dir().join(format!("purge-ui-two-{}", std::process::id()));
        let path = dir.join("ui-settings.ini");
        let _ = std::fs::remove_dir_all(&dir);
        let mut a = Store::at(path.clone());
        let mut b = Store::at(path.clone());
        let a_prefs = a.load();
        b.load();
        // B changes a setting; then A closes and saves its place with its older settings.
        let b_prefs = Prefs {
            preset: Preset::Teal,
            ..Prefs::default()
        };
        b.save(&b_prefs);
        a.save_window(&a_prefs, state());
        let mut read = Store::at(path.clone());
        assert_eq!(read.load(), b_prefs, "A's place save kept B's setting");
        assert_eq!(read.window(), Some(state()));
        // B moves and saves its place; then A changes a setting: B's place stays.
        b.save_window(&b_prefs, other_state());
        let a_change = Prefs {
            design: Design::Standard,
            ..b_prefs
        };
        a.save(&a_change);
        let mut read = Store::at(path.clone());
        assert_eq!(read.load(), a_change);
        assert_eq!(
            read.window(),
            Some(other_state()),
            "A's prefs save kept B's place"
        );
        // A key this build does not know survives a place save.
        let text = std::fs::read_to_string(&path).unwrap() + "later_key=7\n";
        std::fs::write(&path, text).unwrap();
        a.save_window(&a_change, state());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("later_key=7\n"), "{text}");
        assert_eq!(text.matches("window=").count(), 1, "{text}");
        assert_eq!(window_of(&text), Some(state()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_not_written_over() {
        // A folder where the file should be: every read fails, as for a locked file.
        let dir = std::env::temp_dir().join(format!("purge-ui-unread-{}", std::process::id()));
        let path = dir.join("ui-settings.ini");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(path.join("inside")).unwrap();
        let mut store = Store::at(path.clone());
        store.save(&Prefs::default());
        assert!(!store.writable, "no more saves this run");
        assert!(path.join("inside").is_dir(), "left alone");
        assert!(!dir.join("ui-settings.ini.tmp").exists(), "not even tried");
        // The next save (a slider's next step) returns at once.
        let began = std::time::Instant::now();
        store.save(&Prefs::default());
        assert!(began.elapsed() < std::time::Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_place_save_heals_a_damaged_file() {
        let dir = std::env::temp_dir().join(format!("purge-ui-heal-{}", std::process::id()));
        let path = dir.join("ui-settings.ini");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = Prefs {
            preset: Preset::Amber,
            ..Prefs::default()
        };
        for damaged in ["", "garbage \u{0}\n", "design=standard\nwindow=garbage\n"] {
            std::fs::write(&path, damaged).unwrap();
            let mut store = Store::at(path.clone());
            store.save_window(&p, state());
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.starts_with("[purge-ui]\nversion=1\n"),
                "{damaged:?}: {text}"
            );
            assert_eq!(text.matches("window=").count(), 1, "{text}");
            let mut read = Store::at(path.clone());
            assert_eq!(read.load(), p, "{damaged:?}");
            assert_eq!(read.window(), Some(state()));
        }
        // A whole file keeps its other lines through a place save, as before.
        std::fs::write(&path, p.text() + "later_key=7\n").unwrap();
        Store::at(path.clone()).save_window(&Prefs::default(), state());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("later_key=7\n"), "{text}");
        assert!(text.contains("colour=amber\n"), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn no_store_saves_nothing() {
        let mut s = Store::none();
        assert_eq!(s.load(), Prefs::default());
        s.save(&Prefs::default());
    }
}
