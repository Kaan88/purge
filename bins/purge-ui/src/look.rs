//! The look the user chooses (docs/UI_RUST_PLAN.md, "What the user asked for"): the design, the
//! page transition, the colour preset and the theme mode. Four independent choices, each kept in
//! the settings file by its `name`, and the palette they make together.
//!
//! - **Design.** `Standard` is the approved mockup's D1 (refined) and D2 (flow) in one: D1's
//!   measures, quiet cards and stacked headings, D2's rounder cards and its uninstall flow (the
//!   pipeline and the review of its leftovers on one page). `Bold` is D3.
//! - **Transition.** How a page replaces the last one. The mockup tied one to each design; here it
//!   is a setting of its own, with more choices. "None", and Windows' "Show animations" off (the
//!   animator then animates nothing), both mean no motion.
//! - **Colour preset.** An accent and a faint tint of the surfaces, for light and for dark, usable
//!   with either design; or the Windows accent on the toolkit's own surfaces.
//! - **Theme mode.** System, light or dark.
//!
//! High contrast is none of these: under a contrast theme the system's colours replace every
//! preset (`app::PurgeApp::retheme`), and the backdrop is off.
//!
//! Deliberately not here: the drawing (`ui`, `screens`) and the motion itself (`transition`).

use mdshared_ui::anim::{Edge, PageEffect};
use mdshared_ui::gfx::{Rgb, mix, rgb};
use mdshared_ui::theme::Palette;
use mdshared_ui::tokens::Tokens;

/// A choice of a few named values, kept in the settings file by its name.
pub trait Choice: Copy + PartialEq + 'static {
    /// Every value, in the order a drop-down lists them.
    const ALL: &'static [Self];
    /// The name in the settings file and on the command line.
    fn name(self) -> &'static str;
    /// What the Settings page shows.
    fn title(self) -> &'static str;

    /// The value named `s` (any case), if any.
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL.iter().copied().find(|v| v.name() == s)
    }

    /// Its place in [`Choice::ALL`].
    fn index(self) -> usize {
        Self::ALL.iter().position(|v| *v == self).unwrap_or(0)
    }

    /// The value at `i`, the last one for an index past the end.
    fn at(i: usize) -> Self {
        Self::ALL[i.min(Self::ALL.len() - 1)]
    }

    /// The names, for a usage message.
    fn names() -> String {
        Self::ALL
            .iter()
            .map(|v| v.name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ---- design ------------------------------------------------------------------------------------

/// The two designs: one model, one set of pages, two looks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Design {
    /// D1 (refined) and D2 (flow) combined.
    Standard,
    /// D3: the icon rail, the command field, rings, a band of the accent behind a title.
    Bold,
}

impl Choice for Design {
    const ALL: &'static [Design] = &[Design::Standard, Design::Bold];

    fn name(self) -> &'static str {
        match self {
            Design::Standard => "standard",
            Design::Bold => "bold",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Design::Standard => "Standard",
            Design::Bold => "Bold",
        }
    }
}

// ---- transition --------------------------------------------------------------------------------

/// How a new page replaces the one before it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Transition {
    /// The new page is there at once.
    None,
    /// The old page fades into the new one (D3's).
    Fade,
    /// The new page rises a little and fades in (D1's, and WinUI's navigation view).
    Slide,
    /// The same from the side: from the right going down the rail, from the left going up.
    SlideSide,
    /// The new page pushes the old one out, up or down by their order in the rail (D2's).
    Flow,
    /// The new page pushes the old one up, whatever their order.
    SlideUp,
    /// The new page grows into place over the old one as it fades in.
    Scale,
    /// The old page sinks back and fades as the new one settles forward into place.
    Depth,
}

impl Choice for Transition {
    const ALL: &'static [Transition] = &[
        Transition::None,
        Transition::Fade,
        Transition::Slide,
        Transition::SlideSide,
        Transition::Flow,
        Transition::SlideUp,
        Transition::Scale,
        Transition::Depth,
    ];

    fn name(self) -> &'static str {
        match self {
            Transition::None => "none",
            Transition::Fade => "fade",
            Transition::Slide => "slide",
            Transition::SlideSide => "slide-side",
            Transition::Flow => "flow",
            Transition::SlideUp => "slide-up",
            Transition::Scale => "scale",
            Transition::Depth => "depth",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Transition::None => "None",
            Transition::Fade => "Fade",
            Transition::Slide => "Slide",
            Transition::SlideSide => "Slide sideways",
            Transition::Flow => "Flow",
            Transition::SlideUp => "Slide up",
            Transition::Scale => "Scale",
            Transition::Depth => "Crossfade with depth",
        }
    }
}

/// What `transition::PageSwitch` runs: one of the toolkit's effects, or one drawn here.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Effect {
    Toolkit(PageEffect),
    /// The new page from 94 % to full size over the old one, fading in.
    Scale,
    /// The old page to 96 % and out, the new one from 103 % to full size and in.
    Depth,
}

impl Transition {
    /// The effect for a move from the page at rail place `from` to the one at `to`; `None` for
    /// no motion.
    pub fn effect(self, from: usize, to: usize) -> Option<Effect> {
        let down = to > from;
        Some(match self {
            Transition::None => return None,
            Transition::Fade => Effect::Toolkit(PageEffect::Crossfade),
            Transition::Slide => Effect::Toolkit(PageEffect::SlideFade {
                from: Edge::Bottom,
                distance: 28.0,
            }),
            Transition::SlideSide => Effect::Toolkit(PageEffect::SlideFade {
                from: if down { Edge::Right } else { Edge::Left },
                distance: 40.0,
            }),
            Transition::Flow => Effect::Toolkit(PageEffect::Push {
                from: if down { Edge::Bottom } else { Edge::Top },
            }),
            Transition::SlideUp => Effect::Toolkit(PageEffect::Push { from: Edge::Bottom }),
            Transition::Scale => Effect::Scale,
            Transition::Depth => Effect::Depth,
        })
    }
}

// ---- colour preset -----------------------------------------------------------------------------

/// An accent and the tint of the surfaces, for light and dark.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Preset {
    /// The Windows accent on the toolkit's own surfaces (the toolkit's blue when Windows names
    /// none).
    Windows,
    Blue,
    Teal,
    Violet,
    Amber,
    Rose,
    Graphite,
}

impl Choice for Preset {
    const ALL: &'static [Preset] = &[
        Preset::Windows,
        Preset::Blue,
        Preset::Teal,
        Preset::Violet,
        Preset::Amber,
        Preset::Rose,
        Preset::Graphite,
    ];

    fn name(self) -> &'static str {
        match self {
            Preset::Windows => "windows",
            Preset::Blue => "blue",
            Preset::Teal => "teal",
            Preset::Violet => "violet",
            Preset::Amber => "amber",
            Preset::Rose => "rose",
            Preset::Graphite => "graphite",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Preset::Windows => "Follow Windows accent",
            Preset::Blue => "Blue (default)",
            Preset::Teal => "Teal",
            Preset::Violet => "Violet",
            Preset::Amber => "Amber",
            Preset::Rose => "Rose",
            Preset::Graphite => "Graphite",
        }
    }
}

impl Preset {
    /// The accent in light and in dark, and how far the surfaces lean towards it. `None` for
    /// the Windows accent.
    fn spec(self) -> Option<(u32, u32, f32)> {
        Some(match self {
            Preset::Windows => return None,
            Preset::Blue => (0x0F6CBD, 0x60CDFF, 0.0),
            Preset::Teal => (0x037F82, 0x4FD8CB, 0.035),
            // D3's own violet.
            Preset::Violet => (0x6B4DE6, 0xB8A2FF, 0.04),
            Preset::Amber => (0xA85300, 0xFFB547, 0.035),
            Preset::Rose => (0xBF2A4F, 0xFF8FA8, 0.035),
            Preset::Graphite => (0x4A5866, 0xB4C0CC, 0.03),
        })
    }

    /// The accent this preset shows on a swatch, before it is made legible on the page.
    pub fn swatch(self, dark: bool, system_accent: Option<Rgb>) -> Rgb {
        match self.spec() {
            Some((light, dark_c, _)) => rgb(if dark { dark_c } else { light }),
            None => system_accent.unwrap_or(Tokens::new(dark).palette.accent),
        }
    }

    /// The palette of this preset in light or dark. `system_accent` is Windows' accent, for
    /// [`Preset::Windows`].
    pub fn palette(self, dark: bool, system_accent: Option<Rgb>) -> Palette {
        let base = Tokens::new(dark);
        let Some((_, _, tint)) = self.spec() else {
            return match system_accent {
                Some(a) => base.with_accent(a).palette,
                None => base.palette,
            };
        };
        let accent = self.swatch(dark, None);
        let mut pal = base.palette;
        if tint > 0.0 {
            // The surfaces lean towards the accent; text keeps its own colour, and the lean is
            // small enough that every pair the toolkit chose still reads (see the tests).
            let lean = |c: Rgb, k: f32| mix(c, accent, tint * k);
            pal.page = lean(pal.page, 1.0);
            pal.title = lean(pal.title, 1.4);
            pal.bar = lean(pal.bar, 1.2);
            pal.pane = lean(pal.pane, 1.2);
            pal.field = lean(pal.field, 0.8);
            pal.popup = lean(pal.popup, 0.8);
            pal.hover = lean(pal.hover, 1.2);
            pal.press = lean(pal.press, 1.2);
            pal.line = lean(pal.line, 1.5);
        }
        Tokens {
            palette: pal,
            ..base
        }
        .with_accent(accent)
        .palette
    }
}

// ---- theme mode --------------------------------------------------------------------------------

/// Light, dark, or what Windows uses.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

impl Choice for ThemeChoice {
    const ALL: &'static [ThemeChoice] =
        &[ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark];

    fn name(self) -> &'static str {
        match self {
            ThemeChoice::System => "system",
            ThemeChoice::Light => "light",
            ThemeChoice::Dark => "dark",
        }
    }

    fn title(self) -> &'static str {
        match self {
            ThemeChoice::System => "Use Windows setting",
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
        }
    }
}

impl ThemeChoice {
    /// Dark or not, with `system_dark` for [`ThemeChoice::System`].
    pub fn dark(self, system_dark: bool) -> bool {
        match self {
            ThemeChoice::System => system_dark,
            ThemeChoice::Light => false,
            ThemeChoice::Dark => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdshared_ui::cover::contrast;

    #[test]
    fn names_parse_back() {
        fn round<C: Choice + std::fmt::Debug>() {
            for v in C::ALL {
                assert_eq!(C::parse(v.name()), Some(*v), "{v:?}");
                assert_eq!(C::parse(&v.name().to_uppercase()), Some(*v), "{v:?}");
                assert_eq!(C::at(v.index()), *v);
            }
            assert_eq!(C::parse("no such thing"), None);
        }
        round::<Design>();
        round::<Transition>();
        round::<Preset>();
        round::<ThemeChoice>();
    }

    #[test]
    fn at_least_the_seven_transitions_asked_for() {
        for name in [
            "none", "fade", "slide", "flow", "slide-up", "scale", "depth",
        ] {
            assert!(Transition::parse(name).is_some(), "{name}");
        }
        assert_eq!(Transition::None.effect(0, 3), None);
        for t in Transition::ALL.iter().filter(|t| **t != Transition::None) {
            assert!(t.effect(0, 3).is_some(), "{t:?}");
        }
    }

    #[test]
    fn flow_pushes_by_rail_order() {
        let down = Transition::Flow.effect(0, 2);
        let up = Transition::Flow.effect(2, 0);
        assert_eq!(
            down,
            Some(Effect::Toolkit(PageEffect::Push { from: Edge::Bottom }))
        );
        assert_eq!(
            up,
            Some(Effect::Toolkit(PageEffect::Push { from: Edge::Top }))
        );
    }

    #[test]
    fn every_preset_reads_in_light_and_dark() {
        for p in Preset::ALL {
            for dark in [false, true] {
                let pal = p.palette(dark, Some(rgb(0xE81123)));
                assert_eq!(pal.dark, dark, "{p:?}");
                for (what, c, ground) in [
                    ("text on page", pal.text, pal.page),
                    ("text on bar", pal.text, pal.bar),
                    ("text on field", pal.text, pal.field),
                    ("text on popup", pal.text, pal.popup),
                ] {
                    let r = contrast(c, ground);
                    assert!(r >= 4.5, "{p:?} dark={dark}: {what} is {r:.2}");
                }
                let r = contrast(pal.accent, pal.page);
                assert!(r >= 4.5, "{p:?} dark={dark}: accent on page is {r:.2}");
                let r = contrast(pal.on_accent, pal.accent);
                assert!(r >= 4.5, "{p:?} dark={dark}: text on accent is {r:.2}");
            }
        }
    }

    #[test]
    fn presets_differ_and_windows_follows_the_system() {
        let red = rgb(0xC50F1F);
        let accents: Vec<Rgb> = Preset::ALL
            .iter()
            .map(|p| p.palette(false, Some(red)).accent)
            .collect();
        for (i, a) in accents.iter().enumerate() {
            for b in &accents[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(Preset::Windows.palette(false, Some(red)).accent, red);
        assert_eq!(
            Preset::Windows.palette(true, None),
            Tokens::new(true).palette,
            "no system accent: the toolkit's own"
        );
    }
}
