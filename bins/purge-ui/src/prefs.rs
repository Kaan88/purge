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
}

impl Default for Prefs {
    fn default() -> Prefs {
        Prefs {
            design: Design::Bold,
            transition: Transition::Slide,
            preset: Preset::Violet,
            theme: ThemeChoice::System,
            backdrop: Backdrop::Acrylic,
        }
    }
}

impl Prefs {
    /// Reads the text of a settings file; defaults for whatever it lacks.
    pub fn parse(text: &str) -> Prefs {
        let mut p = Prefs::default();
        for (key, value) in settings::pairs(text) {
            let v = settings::unescape(value.trim());
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

    /// Writes the settings. A failure is said on stderr and changes nothing else: the window
    /// goes on with what was chosen.
    pub fn save(&self, p: &Prefs) {
        let (Some(path), true) = (&self.path, self.writable) else {
            return;
        };
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            eprintln!("Purge: {} could not be made ({e})", dir.display());
            return;
        }
        if let Err(e) = settings::write_atomic(path, &p.text_with(self.window.as_ref())) {
            eprintln!("Purge: {} could not be written ({e})", path.display());
        }
    }
}

impl Store {
    /// The window's place the file had: `None` is a first launch.
    pub fn window(&self) -> Option<WindowState> {
        self.window.clone()
    }

    /// Saves the window's place with the settings `p` (the file's, not this run's).
    pub fn save_window(&mut self, p: &Prefs, state: WindowState) {
        self.window = Some(state);
        self.save(p);
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

    #[test]
    fn no_store_saves_nothing() {
        let mut s = Store::none();
        assert_eq!(s.load(), Prefs::default());
        s.save(&Prefs::default());
    }
}
