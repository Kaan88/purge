//! The colours of the toolkit dialog. Purge.exe's default look, Bold with the Violet preset, in
//! light or dark as Windows is set; under a contrast theme, the theme's colours.
//!
//! **What the elevated process reads, and what it does not.** The broker never reads Purge's
//! settings file: a medium process can write it, and nothing a medium process writes may change what
//! this dialog looks like beyond what Windows itself lets any program change for the whole session.
//! So the look is fixed here ([`violet`]), not the user's saved preset, and nothing visual comes over
//! the pipe. Two things are taken from the system, as the TaskDialog takes them: light or dark (the
//! user's `AppsUseLightTheme`), and the contrast theme. A contrast theme's colours are the session's
//! system colours, which a medium process can set too, so they are used only when the pairs the dialog
//! reads still read ([`readable`]); otherwise the toolkit's own contrast palette is used, and the text
//! cannot be made to vanish into its ground.
//!
//! [`violet`] repeats `bins/purge-ui/src/look.rs` (`Preset::Violet`): a binary cannot be depended
//! on, and the broker must not link the UI. A test pins the values.

use mdshared_ui::cover::contrast;
use mdshared_ui::gfx::{Rgb, mix, rgb};
use mdshared_ui::platform;
use mdshared_ui::theme::Palette;
use mdshared_ui::tokens::{SystemColors, Tokens};

/// Violet's accent in light and in dark, and how far the surfaces lean towards it.
const VIOLET: (u32, u32, f32) = (0x6B4DE6, 0xB8A2FF, 0.04);

/// The colours a frame is drawn in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Look {
    /// The palette.
    pub pal: Palette,
    /// A contrast theme is on: colour alone carries nothing, and tinted fills become frames.
    pub contrast: bool,
}

/// Purge.exe's Violet preset in light or dark.
pub fn violet(dark: bool) -> Palette {
    let base = Tokens::new(dark);
    let (light, dark_accent, tint) = VIOLET;
    let accent = rgb(if dark { dark_accent } else { light });
    let lean = |c: Rgb, k: f32| mix(c, accent, tint * k);
    let mut pal = base.palette;
    pal.page = lean(pal.page, 1.0);
    pal.title = lean(pal.title, 1.4);
    pal.bar = lean(pal.bar, 1.2);
    pal.pane = lean(pal.pane, 1.2);
    pal.field = lean(pal.field, 0.8);
    pal.popup = lean(pal.popup, 0.8);
    pal.hover = lean(pal.hover, 1.2);
    pal.press = lean(pal.press, 1.2);
    pal.line = lean(pal.line, 1.5);
    Tokens {
        palette: pal,
        ..base
    }
    .with_accent(accent)
    .palette
}

/// Whether a contrast theme's colours can be used: the text reads on the window, the highlight text
/// on the highlight, and the disabled text is at least seen on the window.
///
/// The other system colours are not checked because the toolkit's contrast palette does not draw
/// with them (review N4, at the pinned toolkit): `button_text` and `hot_light` have no field in
/// [`Palette`], and `button_face` is the title row's fill only when the window text reads on it at
/// 4.5:1 (the window otherwise). A test pins both, so that a toolkit that starts drawing with them
/// fails it before the dialog does.
pub fn readable(c: &SystemColors) -> bool {
    contrast(c.window_text, c.window) >= 4.5
        && contrast(c.highlight_text, c.highlight) >= 4.5
        && contrast(c.gray_text, c.window) >= 2.0
}

/// The contrast palette: the theme's colours when they read, the toolkit's own otherwise.
pub fn contrast_palette(colors: Option<&SystemColors>, dark: bool) -> Palette {
    match colors.filter(|c| readable(c)) {
        Some(c) => Tokens::from_system_colors(c).palette,
        None => Tokens::high_contrast(dark).palette,
    }
}

impl Look {
    /// The look for a theme given by hand: the preview's.
    pub fn of(dark: bool, contrast: bool) -> Look {
        Look {
            pal: if contrast {
                Tokens::high_contrast(dark).palette
            } else {
                violet(dark)
            },
            contrast,
        }
    }

    /// The look for the system as it is now. `contrast`: whether a contrast theme is on, as the
    /// window host read it.
    pub fn system(contrast: bool) -> Look {
        let dark = platform::system_is_dark();
        Look {
            pal: if contrast {
                contrast_palette(platform::system_contrast_colors().as_ref(), dark)
            } else {
                violet(dark)
            },
            contrast,
        }
    }

    /// The fill of the button that approves an action that cannot be undone, and the text on it.
    pub fn danger(&self) -> (Rgb, Rgb) {
        if self.contrast {
            return (self.pal.accent, self.pal.on_accent);
        }
        let fill = self.pal.danger;
        let white = [255, 255, 255];
        let black = [0, 0, 0];
        let ink = if contrast(white, fill) >= contrast(black, fill) {
            white
        } else {
            black
        };
        (fill, ink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violet_is_purges_preset_and_reads() {
        assert_eq!(violet(false).accent, rgb(0x6B4DE6));
        for dark in [false, true] {
            let pal = violet(dark);
            assert_eq!(pal.dark, dark);
            assert_ne!(pal.popup, Tokens::new(dark).palette.popup, "tinted");
            for (what, ink, ground) in [
                ("text on popup", pal.text, pal.popup),
                ("text on title", pal.text, pal.title),
                ("muted on popup", pal.muted, pal.popup),
                ("on accent", pal.on_accent, pal.accent),
                ("accent on popup", pal.accent, pal.popup),
            ] {
                let r = contrast(ink, ground);
                assert!(r >= 4.5, "dark={dark}: {what} is {r:.2}");
            }
            let look = Look::of(dark, false);
            let (fill, ink) = look.danger();
            assert!(contrast(ink, fill) >= 4.5, "dark={dark}: danger");
        }
    }

    fn theme(window: u32, text: u32, highlight: u32, highlight_text: u32) -> SystemColors {
        SystemColors {
            window: rgb(window),
            window_text: rgb(text),
            highlight: rgb(highlight),
            highlight_text: rgb(highlight_text),
            hot_light: rgb(0x00FFFF),
            gray_text: rgb(0x3FF23F),
            button_face: rgb(window),
            button_text: rgb(text),
        }
    }

    #[test]
    fn a_contrast_theme_that_hides_the_text_is_not_used() {
        // Windows' "Night sky": used as it is.
        let night = theme(0x000000, 0xFFFFFF, 0xD6B4FD, 0x2B2B2B);
        assert!(readable(&night));
        assert_eq!(contrast_palette(Some(&night), true).text, rgb(0xFFFFFF));
        assert_eq!(contrast_palette(Some(&night), true).accent, rgb(0xD6B4FD));
        // Text set to the window's colour, or the button's text to its fill: the toolkit's own.
        let own_dark = Tokens::high_contrast(true).palette;
        for hidden in [
            theme(0x000000, 0x000000, 0xD6B4FD, 0x2B2B2B),
            theme(0x000000, 0x101010, 0xD6B4FD, 0x2B2B2B),
            theme(0x000000, 0xFFFFFF, 0xD6B4FD, 0xD6B4FD),
        ] {
            assert!(!readable(&hidden));
            assert_eq!(contrast_palette(Some(&hidden), true), own_dark);
        }
        assert_eq!(contrast_palette(None, true), own_dark);
        let own = Tokens::high_contrast(false).palette;
        assert_eq!(contrast_palette(None, false), own);
        for pal in [own, own_dark] {
            assert!(contrast(pal.text, pal.popup) >= 7.0);
            assert!(contrast(pal.on_accent, pal.accent) >= 4.5);
        }
    }

    /// Review N4: `readable` leaves out the button and link colours because the palette does not
    /// draw with them. Pinned here: a theme whose button text or link colour vanishes gives the
    /// same palette, and a button face the text does not read on is not the title row's fill.
    #[test]
    fn the_contrast_palette_draws_with_no_colour_readable_does_not_check() {
        let night = theme(0x000000, 0xFFFFFF, 0xD6B4FD, 0x2B2B2B);
        let pal = contrast_palette(Some(&night), true);
        for c in [
            SystemColors {
                button_text: night.button_face,
                ..night
            },
            SystemColors {
                hot_light: night.window,
                ..night
            },
        ] {
            assert!(readable(&c));
            assert_eq!(contrast_palette(Some(&c), true), pal);
        }
        // A button face the window text does not read on.
        let grey = SystemColors {
            button_face: rgb(0xF0F0F0),
            ..night
        };
        assert!(readable(&grey));
        let pal = contrast_palette(Some(&grey), true);
        for (what, ground) in [("title", pal.title), ("bar", pal.bar), ("popup", pal.popup)] {
            let r = contrast(pal.text, ground);
            assert!(r >= 4.5, "text on {what} is {r:.2}");
        }
    }
}
