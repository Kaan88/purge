//! The window's settings file: `%LOCALAPPDATA%\Purge\ui-settings.ini`, a `[purge-ui]` section of
//! `key=value` lines with a `version`, written whole and atomically on every change
//! (`mdshared_app::settings`).
//!
//! A value that is missing or not understood is the default, and a file of a newer version is
//! read for the keys this build knows; it is never refused, so a settings file can never keep the
//! window from opening. A file that cannot be read for any other reason (locked, no access) is
//! left alone: the defaults are used and nothing is written over it this run.
//!
//! Deliberately not here: anything the engine or the broker decides (what is ticked, how long the
//! quarantine keeps things). Those are facts of the version, stated on the Settings page.

use std::path::PathBuf;

use mdshared_app::settings;

use crate::look::{Choice, Design, Preset, ThemeChoice, Transition};

/// The file's format. Raise it when a key changes meaning, not when one is added.
pub const VERSION: u32 = 1;
const SECTION: &str = "purge-ui";

/// What the user chose on the Settings page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prefs {
    pub design: Design,
    pub transition: Transition,
    pub preset: Preset,
    pub theme: ThemeChoice,
}

impl Default for Prefs {
    fn default() -> Prefs {
        Prefs {
            design: Design::Standard,
            transition: Transition::Slide,
            preset: Preset::Windows,
            theme: ThemeChoice::System,
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
                _ => {}
            }
        }
        p
    }

    /// The text of the settings file.
    pub fn text(&self) -> String {
        let mut w = settings::Writer::new(SECTION);
        w.line("version", &VERSION.to_string());
        w.line("design", self.design.name());
        w.line("transition", self.transition.name());
        w.line("colour", self.preset.name());
        w.line("theme", self.theme.name());
        w.finish()
    }
}

/// Where the settings live, and whether they may be written.
pub struct Store {
    path: Option<PathBuf>,
    writable: bool,
}

impl Store {
    /// `%LOCALAPPDATA%\Purge\ui-settings.ini`.
    pub fn user() -> Store {
        Store {
            path: settings::data_dir("Purge").map(|d| d.join("ui-settings.ini")),
            writable: true,
        }
    }

    /// No file: the defaults, and nothing is saved (the scripted walk, tests).
    pub fn none() -> Store {
        Store {
            path: None,
            writable: false,
        }
    }

    /// The file at `path` (tests).
    #[cfg(test)]
    pub fn at(path: PathBuf) -> Store {
        Store {
            path: Some(path),
            writable: true,
        }
    }

    /// The settings, or the defaults. A file that exists but cannot be read is not written
    /// over later.
    pub fn load(&mut self) -> Prefs {
        let Some(path) = &self.path else {
            return Prefs::default();
        };
        match settings::read_patiently(path) {
            Ok(Some(text)) => Prefs::parse(&text),
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
        if let Err(e) = settings::write_atomic(path, &p.text()) {
            eprintln!("Purge: {} could not be written ({e})", path.display());
        }
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
        };
        assert_eq!(Prefs::parse(&p.text()), p);
        assert!(p.text().starts_with("[purge-ui]\nversion=1\n"));
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

    #[test]
    fn no_store_saves_nothing() {
        let mut s = Store::none();
        assert_eq!(s.load(), Prefs::default());
        s.save(&Prefs::default());
    }
}
