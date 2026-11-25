//! The steps of `--script`: what is done and what is checked, in order.

use std::collections::HashSet;

use mdshared_ui::host::{App, Cx, Event};
use mdshared_ui::keys::KeyName;

use mdshared_app::backdrop::Backdrop;

use crate::app::PurgeApp;
use crate::look::{Choice, Design, Preset, ThemeChoice, Transition};
use purge_ui_model::leftovers::LeftoversPhase;

use crate::model::{Page, SortKey, Tab};
use crate::script::{CTRL, NONE, SHIFT, Step};
use crate::ui::{Id, Role, id};

const LIST: Id = Id("ProgramList", 0);

/// B1's long command: the interactive one, and with " /SILENT" the quiet one.
const LONG_COMMAND: &str = r#""C:\Program Files (x86)\Some Vendor\Some Application\unins000.exe""#;

/// The confirmation's command as the last frame declared it: its whole text, and its height.
fn shown_command(app: &PurgeApp) -> (String, f32) {
    app.ctl(id("CommandText"))
        .map(|c| (c.label.clone(), c.rect.h))
        .unwrap_or_default()
}

fn nothing(_: &mut PurgeApp, _: &mut Cx<'_, ()>) {}

fn ok(_: &PurgeApp) -> Result<String, String> {
    Ok("drawn".to_string())
}

fn want(cond: bool, what: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(what.into()) }
}

fn has_id(app: &PurgeApp, i: Id) -> Result<(), String> {
    want(app.ctl(i).is_some(), format!("no control {}", i.author()))
}

fn has(app: &PurgeApp, name: &'static str) -> Result<(), String> {
    want(app.ctl(id(name)).is_some(), format!("no control {name}"))
}

/// The middle of row `row` of the programs list, as the last frame drew it.
fn row_middle(app: &PurgeApp, row: usize) -> (f32, f32) {
    let l = &app.view.list;
    let r = l.rows().rect(l.area, row);
    (r.x + 220.0, r.cy())
}

fn click_row(app: &mut PurgeApp, cx: &mut Cx<'_, ()>, row: usize) {
    let (x, y) = row_middle(app, row);
    app.click_at(cx, x, y);
}

/// Presses Tab until the focus comes round again, and returns the controls it stopped on.
fn tab_round(app: &mut PurgeApp, cx: &mut Cx<'_, ()>, shift: bool) -> Vec<Id> {
    let mut seen = Vec::new();
    for _ in 0..200 {
        let mods = if shift { SHIFT } else { NONE };
        app.press_key(cx, KeyName::Tab, mods);
        match app.focus.focused() {
            Some(f) if seen.contains(&f) => break,
            Some(f) => seen.push(f),
            None => break,
        }
    }
    seen
}

fn focusable(app: &PurgeApp, modal: bool) -> HashSet<Id> {
    app.ctls
        .iter()
        .filter(|c| c.focusable && c.modal == modal)
        .map(|c| c.id)
        .collect()
}

fn page_step(name: &'static str, act: fn(&mut PurgeApp, &mut Cx<'_, ()>)) -> Step {
    Step {
        name,
        act,
        check: ok,
        settle: 700,
    }
}

pub fn steps() -> Vec<Step> {
    let mut s = vec![
        Step {
            name: "defaults",
            act: nothing,
            check: |app| {
                let p = app.model.prefs;
                want(
                    (p.design, p.preset, p.backdrop)
                        == (Design::Bold, Preset::Violet, Backdrop::Acrylic),
                    format!(
                        "the walk opens on the defaults, not {:?} {:?} {:?}",
                        p.design, p.preset, p.backdrop
                    ),
                )?;
                on(app, Page::Programs, Design::Bold)
            },
            settle: 300,
        },
        Step {
            name: "programs",
            // The walk's first half is the standard look's, in the blue it was written in; the
            // Bold steps come at the end and choose their own look.
            act: |app, cx| {
                app.set_design(cx, Design::Standard);
                app.set_preset(cx, Preset::Blue);
            },
            check: |app| {
                for name in [
                    "NavPrograms",
                    "NavQueue",
                    "NavLeftovers",
                    "NavHistory",
                    "NavVault",
                    "NavSettings",
                    "UninstallButton",
                    "SearchBox",
                    "TabApps",
                    "TabComponents",
                    "TabUnnamed",
                    "TabRecent",
                    "FilterButton",
                    "SortButton",
                    "SortName",
                    "SortSize",
                    "SortJunk",
                    "SortDate",
                    "ProgramList",
                    "DetailsCard",
                    "StatusLeft",
                    "StatusRight",
                    "Summary",
                ] {
                    has(app, name)?;
                }
                let pr = &app.model.programs;
                want(
                    pr.loaded && pr.rows.len() == pr.count(Tab::Apps) && pr.rows.len() > 12,
                    format!("the sample's apps are listed ({})", pr.rows.len()),
                )?;
                want(app.view.list.area.h > 200.0, "the list has a viewport")?;
                Ok(format!("{} controls declared", app.ctls.len()))
            },
            settle: 500,
        },
        Step {
            name: "tab-reaches-everything",
            act: |app, cx| {
                let forward = tab_round(app, cx, false);
                let back = tab_round(app, cx, true);
                app.note = format!("{}|{}", forward.len(), back.len());
                app.visited = forward;
            },
            check: |app| {
                let all = focusable(app, false);
                let seen: HashSet<Id> = app.visited.iter().copied().collect();
                let missed: Vec<&Id> = all.difference(&seen).collect();
                want(missed.is_empty(), format!("Tab never reached {missed:?}"))?;
                Ok(format!(
                    "Tab stops forward|back {} of {} focusable",
                    app.note,
                    all.len()
                ))
            },
            settle: 300,
        },
        Step {
            name: "click-selects-details-follow",
            act: |app, cx| click_row(app, cx, 3),
            check: |app| {
                let pr = &app.model.programs;
                want(
                    pr.sel.len() == 1 && pr.sel.contains(3),
                    "row 3 alone is selected",
                )?;
                let name = &pr.all[pr.rows[3]].name;
                let shown = app
                    .ctl(id("DName"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    name.starts_with(shown.trim_end_matches('\u{2026}')),
                    format!("details show {shown:?}, want {name:?}"),
                )?;
                want(
                    app.ctl(id("UninstallButton")).is_some_and(|c| !c.disabled),
                    "Uninstall is enabled",
                )?;
                Ok(format!("details pane shows {shown}"))
            },
            settle: 300,
        },
        Step {
            name: "ctrl-and-shift-click",
            act: |app, cx| {
                app.fake_mods = Some(CTRL);
                click_row(app, cx, 5);
                app.fake_mods = Some(SHIFT);
                click_row(app, cx, 8);
                app.fake_mods = None;
            },
            check: |app| {
                let got: Vec<usize> = app.model.programs.sel.iter().collect();
                want(
                    got == vec![5, 6, 7, 8],
                    format!("Ctrl+click 5 then Shift+click 8 gave {got:?}"),
                )?;
                Ok(format!("selection {got:?}"))
            },
            settle: 300,
        },
        Step {
            name: "arrows-space-ctrl-a",
            act: |app, cx| {
                click_row(app, cx, 1);
                app.press_key(cx, KeyName::Down, NONE);
                app.press_key(cx, KeyName::Down, NONE);
                app.press_key(cx, KeyName::Down, SHIFT);
                app.press_key(cx, KeyName::Down, SHIFT);
                // Ctrl+Down moves the cursor only; Space then adds that row.
                app.press_key(cx, KeyName::Down, CTRL);
                app.press_key(cx, KeyName::Down, CTRL);
                app.press_key(cx, KeyName::Space, NONE);
            },
            check: |app| {
                let got: Vec<usize> = app.model.programs.sel.iter().collect();
                want(
                    got == vec![3, 4, 5, 7],
                    format!("arrows and Space gave {got:?}"),
                )?;
                want(
                    app.focus.focused() == Some(LIST),
                    "the list has the keyboard",
                )?;
                Ok(format!(
                    "selection {got:?}, cursor {:?}",
                    app.model.programs.sel.cursor()
                ))
            },
            settle: 300,
        },
        Step {
            name: "end-key-scrolls",
            act: |app, cx| {
                app.press_key(cx, KeyName::Char('a'), CTRL);
                app.note = app.model.programs.sel.len().to_string();
                app.press_key(cx, KeyName::End, NONE);
            },
            check: |app| {
                let pr = &app.model.programs;
                want(
                    app.note == pr.rows.len().to_string(),
                    format!("Ctrl+A selected {}", app.note),
                )?;
                want(
                    pr.sel.cursor() == Some(pr.rows.len() - 1),
                    "End put the cursor on the last row",
                )?;
                want(
                    app.view.list.offset > 240.0,
                    format!("the list scrolled to {}", app.view.list.offset),
                )?;
                Ok(format!("offset {:.0}", app.view.list.offset))
            },
            settle: 900,
        },
        Step {
            name: "wheel-scrolls",
            act: |app, cx| {
                let (x, y) = (app.view.list.area.cx(), app.view.list.area.cy());
                app.event(cx, Event::PointerMove { x, y });
                app.note = format!("{}", app.view.list.offset);
                for _ in 0..5 {
                    app.event(
                        cx,
                        Event::Wheel {
                            dx: 0.0,
                            dy: 48.0,
                            precise: false,
                        },
                    );
                }
            },
            check: |app| {
                let before: f32 = app.note.parse().unwrap_or(0.0);
                let now = app.view.list.offset;
                want(
                    (before - now - 240.0).abs() < 1.0,
                    format!("wheel moved {before} to {now}"),
                )?;
                Ok(format!("offset {before:.0} to {now:.0}"))
            },
            settle: 900,
        },
        Step {
            name: "sort-by-size",
            act: |app, cx| {
                app.press_key(cx, KeyName::Home, NONE);
                app.click(cx, id("SortSize"));
            },
            check: |app| {
                let pr = &app.model.programs;
                want(
                    pr.sort == SortKey::Size && pr.descending,
                    "sorted by size, largest first",
                )?;
                let sizes: Vec<f32> = pr.rows.iter().map(|i| pr.all[*i].size_mb).collect();
                want(
                    sizes.windows(2).all(|w| w[0] >= w[1]),
                    "rows are in size order",
                )?;
                let label = app
                    .ctl(id("SortSize"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                Ok(format!("largest {} MB; header says {label:?}", sizes[0]))
            },
            settle: 500,
        },
        Step {
            name: "search-ctrl-f",
            act: |app, cx| {
                app.click(cx, id("SortName"));
                app.press_key(cx, KeyName::Char('f'), CTRL);
                app.type_text(cx, "fire");
            },
            check: |app| {
                let pr = &app.model.programs;
                want(
                    app.focus.focused() == Some(id("SearchBox")),
                    "Ctrl+F put the keyboard in the search field",
                )?;
                want(pr.query == "fire", format!("query is {:?}", pr.query))?;
                want(
                    !pr.rows.is_empty()
                        && pr
                            .rows
                            .iter()
                            .all(|i| pr.all[*i].name.to_lowercase().contains("fire")),
                    "only matching rows",
                )?;
                Ok(format!("{} row(s) for 'fire'", pr.rows.len()))
            },
            settle: 600,
        },
        Step {
            name: "search-no-match",
            act: |app, cx| app.type_text(cx, "zzz"),
            check: |app| {
                want(app.model.programs.rows.is_empty(), "no rows")?;
                has(app, "NoMatchText")?;
                Ok("the empty state is shown".to_string())
            },
            settle: 400,
        },
        Step {
            name: "esc-clears-search",
            act: |app, cx| {
                app.press_key(cx, KeyName::Escape, NONE);
            },
            check: |app| {
                want(app.model.programs.query.is_empty(), "query cleared")?;
                let pr = &app.model.programs;
                want(pr.rows.len() == pr.count(Tab::Apps), "all rows back")?;
                Ok(format!("{} rows", pr.rows.len()))
            },
            settle: 400,
        },
        Step {
            name: "filter-tabs",
            act: |app, cx| {
                app.click(cx, id("TabComponents"));
            },
            check: |app| {
                let pr = &app.model.programs;
                want(
                    pr.tab == Tab::Components
                        && !pr.rows.is_empty()
                        && pr.rows.len() == pr.count(Tab::Components),
                    "the components are listed",
                )?;
                Ok(format!("Components: {}", pr.rows.len()))
            },
            settle: 500,
        },
        Step {
            name: "tabs-by-arrow-keys",
            act: |app, cx| {
                app.press_key(cx, KeyName::Right, NONE);
                app.note = format!("{:?}", app.model.programs.tab);
                app.press_key(cx, KeyName::Home, NONE);
            },
            check: |app| {
                want(app.note == "Unnamed", format!("Right went to {}", app.note))?;
                want(
                    app.model.programs.tab == Tab::Apps,
                    "Home went back to Apps",
                )?;
                want(
                    app.focus.focused() == Some(id("TabApps")),
                    "the keyboard is on the Apps tab",
                )?;
                Ok("Right then Home".to_string())
            },
            settle: 500,
        },
        // Its own step: a click goes by the controls of the last frame, and Uninstall is drawn
        // enabled only in the frame after the selection.
        Step {
            name: "search-then-down-selects",
            act: |app, cx| {
                // Rows ticked earlier stay ticked while a search hides them ("1 selected (3 not
                // shown)", the WinUI rule) and Uninstall would take them too: Esc on the whole
                // list unticks them first.
                app.focus.focus(LIST);
                app.press_key(cx, KeyName::Escape, NONE);
                app.press_key(cx, KeyName::Char('f'), CTRL);
                app.type_text(cx, "firefox");
                app.press_key(cx, KeyName::Down, NONE);
            },
            check: |app| {
                let pr = &app.model.programs;
                want(
                    pr.rows.len() == 1 && pr.sel.len() == 1 && pr.page.ticked().len() == 1,
                    format!(
                        "{} row(s), {} selected, {} ticked",
                        pr.rows.len(),
                        pr.sel.len(),
                        pr.page.ticked().len()
                    ),
                )?;
                Ok("Firefox selected from the search field".to_string())
            },
            settle: 500,
        },
        // The first launch of the broker in a run is explained first (`ElevationPrompts.cs`); with
        // sample data the broker is the made-up one, which answers from the protocol fixtures.
        Step {
            name: "explain-opens",
            act: |app, cx| {
                app.click(cx, id("UninstallButton"));
            },
            check: |app| {
                want(
                    app.model.flow.elevation.showing().is_some(),
                    "the first-elevation explanation is open",
                )?;
                want(
                    app.model.flow.confirm.is_none(),
                    "no confirmation before it",
                )?;
                has(app, "DialogPrimaryButton")?;
                has(app, "DialogCloseButton")?;
                want(
                    app.focus.focused() == Some(id("DialogPrimaryButton")),
                    format!(
                        "the keyboard starts on Continue, is on {:?}",
                        app.focus.focused()
                    ),
                )?;
                Ok("Continue / Not now, keyboard on Continue".to_string())
            },
            settle: 700,
        },
        Step {
            name: "explain-not-now",
            act: |app, cx| {
                app.click(cx, id("DialogCloseButton"));
            },
            check: |app| {
                want(!app.model.flow.dialog_open(), "Not now closed it")?;
                want(!app.model.flow.page.is_busy(), "nothing runs")?;
                want(app.model.page == Page::Pipeline, "on the Uninstall page")?;
                let said = app
                    .ctl(Id("InfoBarHost", 0))
                    .map(|c| c.label.clone())
                    .ok_or("no bar says what happened")?;
                Ok(format!("bar: {said}"))
            },
            settle: 700,
        },
        page_step("explain-back-to-programs", |app, cx| {
            app.press_key(cx, KeyName::Char('1'), CTRL);
        }),
        Step {
            name: "explain-again",
            act: |app, cx| {
                app.click(cx, id("UninstallButton"));
            },
            check: |app| {
                want(
                    app.model.flow.elevation.showing().is_some(),
                    "asked again: it was not answered with Continue",
                )?;
                Ok("open again".to_string())
            },
            settle: 700,
        },
        Step {
            name: "confirm-opens",
            act: |app, cx| {
                app.click(cx, id("DialogPrimaryButton"));
            },
            check: |app| {
                want(app.model.flow.elevation.explained, "Continue is remembered")?;
                let c = app
                    .model
                    .flow
                    .confirm
                    .as_ref()
                    .ok_or("the confirmation is not open")?;
                want(
                    c.dialog.check_again,
                    "firefox.exe runs: Check again is offered",
                )?;
                for name in [
                    "ConfirmUninstallButton",
                    "ConfirmCheckAgainButton",
                    "ConfirmNotNowButton",
                    "QuietSwitch",
                    "RestorePointBox",
                    "DialogTitle",
                    "CommandText",
                    "SignerText",
                    "RunningText",
                ] {
                    has(app, name)?;
                }
                for k in 1..=5 {
                    has_id(app, Id("ConfirmStep", k))?;
                }
                want(
                    app.focus.focused() == Some(id("ConfirmNotNowButton")),
                    format!(
                        "the keyboard starts on Not now, is on {:?}",
                        app.focus.focused()
                    ),
                )?;
                Ok(format!("'{}', keyboard on Not now", c.dialog.title))
            },
            settle: 1800,
        },
        Step {
            name: "tab-stays-in-dialog",
            act: |app, cx| {
                app.visited = tab_round(app, cx, false);
            },
            check: |app| {
                let inside = focusable(app, true);
                let seen: HashSet<Id> = app.visited.iter().copied().collect();
                want(
                    seen == inside,
                    format!("Tab visited {seen:?}, the dialog has {inside:?}"),
                )?;
                Ok(format!("{} stops, all in the dialog", seen.len()))
            },
            settle: 300,
        },
        // The WinUI bug: the dialog kept showing the quiet command with quiet mode off.
        Step {
            name: "quiet-switch-changes-the-command",
            act: |app, cx| {
                let before = app.ctl(id("CommandText")).map(|c| c.label.clone());
                app.note = before.unwrap_or_default();
                app.click(cx, id("QuietSwitch"));
            },
            check: |app| {
                let c = app.model.flow.confirm.as_ref().ok_or("closed")?;
                let now = app
                    .ctl(id("CommandText"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(now == c.command(), "the command shown is the dialog's")?;
                if c.dialog.quiet_enabled {
                    want(now != app.note, format!("the command stayed {now}"))?;
                }
                Ok(format!("quiet {}: {now}", c.quiet_on))
            },
            settle: 400,
        },
        // B1: a long command is drawn whole, wrapped, and follows the switch.
        Step {
            name: "long-command-wraps",
            act: |app, _| {
                if let Some(c) = &mut app.model.flow.confirm {
                    let mut k = c.dialog.confirmation.clone();
                    let quiet = format!("{LONG_COMMAND} /SILENT");
                    k.interactive_command = LONG_COMMAND.into();
                    k.command = quiet.clone();
                    k.quiet_command = Some(quiet);
                    k.quiet_available = true;
                    k.quiet = true;
                    *c = crate::flow::Confirm::new(k);
                }
            },
            check: |app| {
                let c = app.model.flow.confirm.as_ref().ok_or("closed")?;
                want(c.quiet_on, "quiet is on")?;
                let (said, h) = shown_command(app);
                let quiet = format!("{LONG_COMMAND} /SILENT");
                want(said == quiet, format!("the command says {said:?}"))?;
                // One line of 12 px mono with the box's padding is about 32 px.
                want(h > 40.0, format!("the command is one line ({h} px)"))?;
                Ok(format!("{h:.0} px: {said}"))
            },
            settle: 500,
        },
        Step {
            name: "long-command-quiet-off",
            act: |app, cx| {
                app.click(cx, id("QuietSwitch"));
            },
            check: |app| {
                let c = app.model.flow.confirm.as_ref().ok_or("closed")?;
                want(!c.quiet_on, "quiet is off")?;
                let (said, h) = shown_command(app);
                want(
                    said == LONG_COMMAND,
                    format!("the interactive command is shown, not {said:?}"),
                )?;
                Ok(format!("{h:.0} px: {said}"))
            },
            settle: 500,
        },
        // B1: a command taller than the window scrolls the dialog; the buttons stay.
        Step {
            name: "huge-command-scrolls",
            act: |app, _| {
                if let Some(c) = &mut app.model.flow.confirm {
                    let mut k = c.dialog.confirmation.clone();
                    let huge = vec![LONG_COMMAND; 40].join(" ");
                    k.command = huge.clone();
                    k.quiet_command = Some(huge);
                    k.quiet_available = true;
                    k.quiet = true;
                    *c = crate::flow::Confirm::new(k);
                }
            },
            check: |app| {
                let v = &app.view;
                want(
                    v.confirm_content > v.confirm_area.h + 100.0,
                    format!(
                        "the body is {} px in {} px",
                        v.confirm_content, v.confirm_area.h
                    ),
                )?;
                let (said, _) = shown_command(app);
                want(said.len() > 2000, "the whole command is its name")?;
                let b = app
                    .ctl(id("ConfirmUninstallButton"))
                    .ok_or("no Uninstall")?
                    .rect;
                want(
                    b.bottom() <= app.view.confirm_area.bottom() + 80.0 && b.h > 0.0,
                    "the buttons stay in the window",
                )?;
                Ok(format!(
                    "{:.0} px of body in {:.0} px",
                    v.confirm_content, v.confirm_area.h
                ))
            },
            settle: 500,
        },
        Step {
            name: "confirm-wheel-scrolls",
            act: |app, cx| {
                let a = app.view.confirm_area;
                app.event(
                    cx,
                    Event::PointerMove {
                        x: a.cx(),
                        y: a.cy(),
                    },
                );
                for _ in 0..40 {
                    app.event(
                        cx,
                        Event::Wheel {
                            dx: 0.0,
                            dy: -120.0,
                            precise: false,
                        },
                    );
                }
            },
            check: |app| {
                let t = app.view.confirm_scroll.target();
                want(t > 0.0, "the wheel scrolled the dialog")?;
                let q = app.ctl(id("QuietSwitch")).ok_or("no quiet switch")?.rect;
                want(
                    q.h > 0.0,
                    "at the end the quiet switch is in view and takes the pointer",
                )?;
                Ok(format!("scrolled {t:.0} px"))
            },
            settle: 700,
        },
        Step {
            name: "check-again-rereads",
            act: |app, cx| {
                app.click(cx, id("ConfirmCheckAgainButton"));
            },
            check: |app| {
                let c = app
                    .model
                    .flow
                    .confirm
                    .as_ref()
                    .ok_or("it did not open again")?;
                want(
                    c.dialog.still_running.is_none(),
                    "firefox.exe is closed now",
                )?;
                want(
                    app.ctl(id("ConfirmCheckAgainButton")).is_none(),
                    "no Check again",
                )?;
                Ok("read again: nothing running".to_string())
            },
            settle: 1800,
        },
        Step {
            name: "esc-closes",
            act: |app, cx| app.press_key(cx, KeyName::Escape, NONE),
            check: |app| {
                want(app.model.flow.confirm.is_none(), "closed")?;
                want(!app.model.flow.page.is_busy(), "nothing runs")?;
                want(
                    app.model.programs.all.iter().all(|p| !p.removed),
                    "nothing was uninstalled",
                )?;
                Ok("closed by Esc; nothing ran".to_string())
            },
            settle: 600,
        },
        page_step("confirm-back-to-programs", |app, cx| {
            app.press_key(cx, KeyName::Char('1'), CTRL);
        }),
        Step {
            name: "confirm-again",
            act: |app, cx| {
                app.click(cx, id("UninstallButton"));
            },
            check: |app| {
                want(
                    app.model.flow.elevation.showing().is_none(),
                    "explained once: no explanation the second time",
                )?;
                want(app.model.flow.confirm.is_some(), "the confirmation is open")?;
                Ok("straight to the confirmation".to_string())
            },
            settle: 1800,
        },
        Step {
            name: "uninstall-runs",
            act: |app, cx| {
                app.click(cx, id("ConfirmUninstallButton"));
            },
            check: |app| {
                want(app.model.page == Page::Pipeline, "on the Uninstall page")?;
                want(app.model.flow.page.is_busy(), "running")?;
                for name in ["StepperHost", "ProgramNameText", "CommandText", "RouteText"] {
                    has(app, name)?;
                }
                for k in 1..=5 {
                    has_id(app, Id("Step", k))?;
                }
                Ok("running".to_string())
            },
            settle: 1200,
        },
        Step {
            name: "pipeline-midway",
            act: nothing,
            check: |app| {
                let c = app.model.flow.page.controller();
                want(
                    c.state_of(purge_ui_model::pipeline::UninstallStep::Record)
                        == purge_ui_model::pipeline::StepState::Done,
                    "the record step is done",
                )?;
                let said = app
                    .ctl(Id("Step", 2))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                Ok(said)
            },
            settle: 3000,
        },
        Step {
            name: "pipeline-reaches-review",
            act: nothing,
            check: |app| {
                want(!app.model.flow.page.is_busy(), "the run ended")?;
                want(
                    app.model.flow.leftovers.phase() == LeftoversPhase::Review,
                    format!(
                        "leftovers wait for review, are {:?}",
                        app.model.flow.leftovers.phase()
                    ),
                )?;
                let said: Vec<String> = (1..=5)
                    .filter_map(|k| app.ctl(Id("Step", k)).map(|c| c.label.clone()))
                    .collect();
                want(
                    said.iter().any(|s| s.contains("exit code")),
                    format!("a step says the exit code: {said:?}"),
                )?;
                let pr = &app.model.programs;
                want(
                    pr.all
                        .iter()
                        .any(|p| p.removed && p.name.contains("Firefox"))
                        && pr.rows.iter().all(|i| !pr.all[*i].removed),
                    "the program left the list",
                )?;
                Ok(format!(
                    "{} leftovers to review",
                    app.model.flow.leftovers.items().len()
                ))
            },
            settle: 8000,
        },
        Step {
            name: "leftovers-review",
            act: |app, cx| {
                app.press_key(cx, KeyName::Char('3'), CTRL);
            },
            check: |app| {
                want(app.model.page == Page::Leftovers, "on the leftovers page")?;
                let l = &app.model.flow.leftovers;
                for i in l.items() {
                    want(
                        i.checked == i.preselected,
                        format!("{} starts {}", i.display_name, i.checked),
                    )?;
                }
                for name in [
                    "TitleText",
                    "MoveButton",
                    "MoveText",
                    "FooterCount",
                    "ExpandButton",
                    "WeakButton",
                    "VerdictText",
                    "SafePill",
                ] {
                    has(app, name)?;
                }
                // What the page shows must be what the model holds.
                for c in &app.ctls {
                    if c.id.0 == "ItemTick" {
                        let item = l
                            .items()
                            .get(c.id.1 as usize - 1)
                            .ok_or("a box for no item")?;
                        want(
                            c.role == Role::Check(Some(item.checked)),
                            format!("{} is drawn {:?}", item.display_name, c.role),
                        )?;
                    }
                }
                Ok(format!(
                    "{} ticked of {}",
                    l.selected_count(),
                    l.selectable_count()
                ))
            },
            settle: 900,
        },
        Step {
            name: "leftovers-tick-and-evidence",
            act: |app, cx| {
                let l = &app.model.flow.leftovers;
                let n = l
                    .items()
                    .iter()
                    .position(|i| i.checked)
                    .map_or(0, |i| i + 1);
                app.note = n.to_string();
                app.click(cx, Id("ItemTick", n as u32));
            },
            check: |app| {
                let n: usize = app.note.parse().unwrap_or(0);
                let l = &app.model.flow.leftovers;
                let item = l
                    .items()
                    .get(n.wrapping_sub(1))
                    .ok_or("no ticked item to start")?;
                want(!item.checked, "the box unticked it")?;
                want(
                    l.selected() == Some(&item.candidate_id),
                    "the evidence pane follows the box",
                )?;
                let shown = app
                    .ctl(id("DPath"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    shown == item.display_name,
                    format!("evidence shows {shown}"),
                )?;
                has(app, "DEvidence")?;
                Ok(format!("unticked {}", item.display_name))
            },
            settle: 1400,
        },
        Step {
            name: "leftovers-group-box",
            act: |app, cx| {
                app.click(cx, Id("GroupTick", 1));
            },
            check: |app| {
                let l = &app.model.flow.leftovers;
                let h = l.group_header(0, 0).ok_or("no first group")?;
                let c = app.ctl(Id("GroupTick", 1)).ok_or("no group box")?;
                want(
                    c.role == Role::Check(h.checked),
                    format!("the group box is drawn {:?}, is {:?}", c.role, h.checked),
                )?;
                Ok(format!("{}: {:?}", h.name, h.checked))
            },
            settle: 600,
        },
        Step {
            name: "leftovers-expanders",
            act: |app, cx| {
                app.note = format!(
                    "{:?}",
                    app.model
                        .flow
                        .leftovers
                        .groups()
                        .first()
                        .map(|g| g.expanded)
                );
                app.click(cx, Id("Group", 1));
            },
            check: |app| {
                let g = app
                    .model
                    .flow
                    .leftovers
                    .groups()
                    .first()
                    .ok_or("no group")?;
                want(
                    format!("{:?}", Some(!g.expanded)) == app.note,
                    "the group opened or closed",
                )?;
                Ok(format!("first group expanded: {}", g.expanded))
            },
            settle: 600,
        },
        // S1: another page's launch asks before it ends the review the session holds, and
        // "Not now" leaves it, the asking page saying why.
        page_step("takeover-to-history", |app, cx| {
            app.click(cx, id("NavHistory"));
        }),
        Step {
            name: "takeover-asks",
            act: |app, cx| {
                app.click(cx, id("ShowItems"));
            },
            check: |app| {
                let t = app
                    .model
                    .flow
                    .takeover
                    .as_ref()
                    .ok_or("no question was asked")?;
                has(app, "TakeoverEndButton")?;
                has(app, "TakeoverNotNowButton")?;
                let title = app
                    .ctl(id("DialogTitle"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    title.starts_with("End the leftovers review of"),
                    format!("the question is {title:?}"),
                )?;
                want(
                    app.focus.focused() == Some(id("TakeoverNotNowButton")),
                    "the keyboard starts on Not now",
                )?;
                Ok(format!("{title} ({:?} for {:?})", t.holder, t.asking))
            },
            settle: 900,
        },
        Step {
            name: "takeover-not-now",
            act: |app, cx| {
                app.click(cx, id("TakeoverNotNowButton"));
            },
            check: |app| {
                want(app.model.flow.takeover.is_none(), "the question closed")?;
                want(
                    app.model.flow.leftovers.phase() == LeftoversPhase::Review,
                    "the review is kept",
                )?;
                let holder = app.link.as_ref().and_then(|l| l.broker.holder());
                want(
                    holder == Some(crate::link::Owner::Leftovers),
                    format!("the session is the review's, is {holder:?}'s"),
                )?;
                let bar = app
                    .ctl(id("InfoBarHost"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    bar.contains("in use by the Leftovers page"),
                    format!("History's bar says {bar:?}"),
                )?;
                Ok(bar)
            },
            settle: 700,
        },
        // S3: History's bar closes on History, not on the Uninstall page.
        Step {
            name: "history-bar-closes",
            act: |app, cx| {
                app.note = app.model.flow_bars().len().to_string();
                app.click(cx, Id("HBarClose", 1));
            },
            check: |app| {
                let bar = app
                    .ctl(id("InfoBarHost"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    !bar.contains("in use by the Leftovers page"),
                    format!("the bar is still there: {bar:?}"),
                )?;
                want(
                    app.model.flow_bars().len().to_string() == app.note
                        && app.model.flow.hidden.is_empty(),
                    "the Uninstall page's bars are untouched",
                )?;
                Ok("closed on History".to_string())
            },
            settle: 500,
        },
        page_step("takeover-back-to-leftovers", |app, cx| {
            app.press_key(cx, KeyName::Char('3'), CTRL);
        }),
        Step {
            name: "leftovers-move-waits",
            act: |app, cx| {
                app.click(cx, Id("Group", 1));
                app.click(cx, id("MoveButton"));
            },
            check: |app| {
                want(
                    app.model.flow.leftovers.phase() == LeftoversPhase::Waiting,
                    format!("waiting, is {:?}", app.model.flow.leftovers.phase()),
                )?;
                let t = app
                    .ctl(id("WaitingTitleText"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    t.starts_with("Confirm") && t.contains("Purge security prompt"),
                    format!("the wait says {t}"),
                )?;
                has(app, "WaitingCodeText")?;
                Ok(t)
            },
            settle: 1800,
        },
        Step {
            name: "leftovers-moved",
            act: nothing,
            check: |app| {
                want(
                    app.model.flow.leftovers.phase() == LeftoversPhase::Result,
                    format!("moved, is {:?}", app.model.flow.leftovers.phase()),
                )?;
                for name in [
                    "ResultTitleText",
                    "ResultDetailText",
                    "UndoAllButton",
                    "DoneButton",
                ] {
                    has(app, name)?;
                }
                Ok(app.model.flow.leftovers.result_title_text().to_string())
            },
            settle: 3500,
        },
        Step {
            name: "leftovers-undone",
            act: |app, cx| {
                app.click(cx, id("UndoAllButton"));
            },
            check: |app| {
                want(
                    app.model.flow.leftovers.phase() == LeftoversPhase::Undone,
                    format!("undone, is {:?}", app.model.flow.leftovers.phase()),
                )?;
                has(app, "UndoTitleText")?;
                has(app, "UndoDetailText")?;
                Ok(app.model.flow.leftovers.undo_title_text().to_string())
            },
            settle: 5000,
        },
        // UI-PAGES2: History and Quarantine on the sample's cleanups. Reads are answered from the
        // sample; every change is refused with "Sample data".
        Step {
            name: "history",
            act: |app, cx| {
                app.click(cx, id("NavHistory"));
            },
            check: |app| {
                want(app.model.page == Page::History, "on History")?;
                for name in [
                    "CheckInterrupted",
                    "StripCard",
                    "Ops",
                    "RestoreSelected",
                    "RestoreAll",
                    "DTitle",
                    "DSummary",
                    "ShowItems",
                    "DExpiry",
                ] {
                    has(app, name)?;
                }
                let h = &app.model.history.page;
                want(h.sessions().len() == 8, "the sample's eight cleanups")?;
                want(
                    h.selected().is_some_and(|s| s.name == "Zoom Workplace"),
                    "the newest is selected",
                )?;
                want(
                    app.ctls.iter().any(|c| c.id.0 == "StripItem"),
                    "the strip's markers",
                )?;
                Ok(format!("{} cleanups", h.sessions().len()))
            },
            settle: 700,
        },
        Step {
            name: "history-items",
            act: |app, cx| {
                app.click(cx, Id("Op", 3));
                app.click(cx, id("ShowItems"));
            },
            check: |app| {
                let h = &app.model.history.page;
                want(
                    h.selected().is_some_and(|s| s.name == "CCleaner"),
                    "CCleaner selected",
                )?;
                want(h.items().is_some_and(|i| i.len() == 4), "its four items")?;
                Ok("four items".to_string())
            },
            settle: 700,
        },
        Step {
            name: "history-item-ticked",
            act: |app, cx| {
                app.click(cx, Id("DItemTick", 1));
            },
            check: |app| {
                let h = &app.model.history.page;
                want(h.checked_count() == 1, "one ticked")?;
                has(app, "DItems")?;
                has_id(app, Id("DItemTick", 4))?;
                let label = app
                    .ctl(id("RestoreSelected"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    label == "Put back 1 selected",
                    format!("the button says {label:?}"),
                )?;
                Ok(label)
            },
            settle: 700,
        },
        Step {
            name: "history-restore-refused",
            act: |app, cx| {
                app.click(cx, id("RestoreSelected"));
            },
            check: |app| {
                let h = &app.model.history.page;
                let error = h.action_error().unwrap_or_default();
                want(
                    error.contains("Sample data"),
                    format!("the error says {error:?}"),
                )?;
                want(!h.busy(), "nothing waits")?;
                let bar = app
                    .ctl(id("InfoBarHost"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    bar.starts_with("Couldn't finish that."),
                    format!("the bar says {bar:?}"),
                )?;
                Ok(bar)
            },
            settle: 700,
        },
        Step {
            name: "history-interrupted",
            act: |app, cx| {
                app.click(cx, Id("Op", 4));
            },
            check: |app| {
                let h = &app.model.history.page;
                want(
                    h.selected().is_some_and(|s| s.interrupted),
                    "the interrupted cleanup",
                )?;
                has(app, "RecoverResume")?;
                has(app, "RecoverRollBack")?;
                Ok("Resume and Roll back offered".to_string())
            },
            settle: 700,
        },
        Step {
            name: "quarantine",
            act: |app, cx| {
                app.click(cx, id("NavVault"));
            },
            check: |app| {
                want(app.model.page == Page::Quarantine, "on Quarantine")?;
                for name in [
                    "ReviewButton",
                    "Volumes",
                    "Totals",
                    "ItemsTitle",
                    "VRestore",
                    "VDeleteNow",
                    "BarReview",
                    "BarOpenHistory",
                ] {
                    has(app, name)?;
                }
                let q = &app.model.quarantine.page;
                want(q.batches().len() == 6, "six cleanups hold something")?;
                want(q.review_button().enabled, "something is past its retention")?;
                Ok(q.totals().to_string())
            },
            settle: 700,
        },
        Step {
            name: "quarantine-items",
            act: |app, cx| {
                app.click(cx, id("VChooseItems"));
            },
            check: |app| {
                let q = &app.model.quarantine.page;
                want(!q.items().is_empty(), "the items are listed")?;
                has_id(app, Id("ItemDelete", 1))?;
                has(app, "ItemsClose")?;
                Ok(format!("{} items", q.items().len()))
            },
            settle: 700,
        },
        Step {
            name: "quarantine-delete-choice",
            act: |app, cx| {
                app.click(cx, id("VDeleteNow"));
            },
            check: |app| {
                want(app.model.quarantine.flyout.is_some(), "the choice is open")?;
                has(app, "AlsoBackups")?;
                Ok("Delete now: the choice".to_string())
            },
            settle: 700,
        },
        Step {
            name: "quarantine-delete-also-backups",
            act: |app, cx| {
                app.click(cx, id("AlsoBackups"));
            },
            check: |app| {
                let f = app
                    .model
                    .quarantine
                    .flyout
                    .as_ref()
                    .ok_or("no choice open")?;
                want(f.also_backups, "the backups ticked")?;
                has(app, "FlyoutContinue")?;
                has(app, "FlyoutCancel")?;
                Ok("Delete now: also its registry backups".to_string())
            },
            settle: 700,
        },
        Step {
            name: "quarantine-delete-refused",
            act: |app, cx| {
                app.click(cx, id("FlyoutContinue"));
            },
            check: |app| {
                let q = &app.model.quarantine;
                want(q.flyout.is_none(), "the choice closed")?;
                let error = q.page.action_error().unwrap_or_default();
                want(
                    error.contains("Sample data"),
                    format!("the error says {error:?}"),
                )?;
                want(q.page.batches().len() == 6, "nothing was deleted")?;
                Ok(error.to_string())
            },
            settle: 700,
        },
        Step {
            name: "settings",
            act: |app, cx| {
                app.click(cx, id("NavSettings"));
            },
            check: |app| {
                want(app.model.page == Page::Settings, "on Settings")?;
                for name in [
                    "ThemeChoice",
                    "LookChoice",
                    "ColourChoice",
                    "TransitionChoice",
                    "BackdropChoice",
                    "PreviewTransition",
                    "TransitionPreview",
                    "ConfirmEach",
                ] {
                    has(app, name)?;
                }
                for i in 0..Preset::ALL.len() {
                    let sid = crate::screens::swatch_id(i);
                    want(app.ctl(sid).is_some(), format!("no swatch {sid:?}"))?;
                }
                let about = app
                    .ctl(id("AboutLine"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    about.starts_with(&format!("Purge {}", env!("CARGO_PKG_VERSION")))
                        && about.ends_with("sample data"),
                    format!("About says {about:?}"),
                )?;
                Ok(about)
            },
            settle: 700,
        },
        Step {
            // UI-FULLFROST: the backdrop's two rows took the room the tick rules had at the
            // first sight of the page; they are a little way down.
            name: "settings-tick-rules",
            act: |app, _| {
                let v = &mut app.view;
                v.page_scroll.jump_to(360.0, v.page_content, v.page_area.h);
            },
            check: |app| {
                has_id(app, Id("TickRule", 1))?;
                Ok("the tick rules".to_string())
            },
            settle: 400,
        },
        Step {
            name: "settings-scrolled-down",
            act: |app, cx| {
                let r = app.view.page_area;
                app.event(
                    cx,
                    Event::PointerMove {
                        x: r.cx(),
                        y: r.cy(),
                    },
                );
                for _ in 0..12 {
                    app.event(
                        cx,
                        Event::Wheel {
                            dx: 0.0,
                            dy: -120.0,
                            precise: true,
                        },
                    );
                }
            },
            check: |app| {
                for name in ["MarkersExpander", "AboutLine", "OpenQuarantine"] {
                    has(app, name)?;
                }
                Ok("the foot of the page".to_string())
            },
            settle: 900,
        },
        Step {
            name: "settings-markers-expander",
            act: |app, cx| {
                app.click(cx, id("MarkersExpander"));
            },
            check: |app| {
                want(app.model.settings.markers_open, "the expander opened")?;
                has(app, "Markers")?;
                Ok("launch markers shown".to_string())
            },
            settle: 700,
        },
        Step {
            name: "settings-back-to-top",
            act: |app, _| {
                app.view.page_scroll = mdshared_ui::scroll::SmoothScroll::new();
            },
            check: |_| Ok("back at the top".to_string()),
            settle: 300,
        },
        Step {
            name: "settings-theme-by-keys",
            act: |app, cx| {
                // The theme drop-down by keyboard: focus it, open it, go down to Dark, choose.
                app.focus.focus(id("ThemeChoice"));
                app.press_key(cx, KeyName::Enter, NONE);
                app.note = format!("{}", app.view.dds.theme.is_open());
                app.press_key(cx, KeyName::Down, NONE);
                app.press_key(cx, KeyName::Down, NONE);
                app.press_key(cx, KeyName::Enter, NONE);
            },
            check: |app| {
                want(app.note == "true", "Enter opened the menu")?;
                want(
                    app.model.prefs.theme == ThemeChoice::Dark,
                    format!("theme is {:?}", app.model.prefs.theme),
                )?;
                want(app.pal.dark, "the palette is dark")?;
                Ok("drop-down by keys; dark".to_string())
            },
            settle: 800,
        },
        Step {
            name: "settings-dropdown-by-mouse",
            act: |app, cx| {
                app.click(cx, id("ThemeChoice"));
            },
            check: |app| {
                want(app.view.dds.theme.is_open(), "a click opened the menu")?;
                Ok("menu open".to_string())
            },
            settle: 600,
        },
        Step {
            name: "dark-programs",
            act: |app, cx| {
                app.press_key(cx, KeyName::Escape, NONE);
                app.press_key(cx, KeyName::Char('1'), CTRL);
                // The search still says "firefox", which is uninstalled by now: clear it, so
                // this frame and the ones after it show a list.
                app.press_key(cx, KeyName::Char('f'), CTRL);
                app.press_key(cx, KeyName::Escape, NONE);
            },
            check: |app| {
                want(!app.view.dds.theme.is_open(), "Esc closed the menu")?;
                want(app.model.page == Page::Programs, "Ctrl+1 opened Programs")?;
                let pr = &app.model.programs;
                want(
                    pr.query.is_empty(),
                    format!("the search is cleared, is {:?}", pr.query),
                )?;
                want(
                    pr.rows.len() == pr.count(pr.tab) && !pr.rows.is_empty(),
                    format!("{} rows listed", pr.rows.len()),
                )?;
                Ok(format!("Programs in dark, {} rows", pr.rows.len()))
            },
            settle: 700,
        },
        Step {
            name: "high-contrast",
            act: |app, cx| {
                app.hc_forced = Some(true);
                app.event(cx, Event::Contrast(true));
            },
            check: |app| {
                want(app.hc, "the high-contrast palette is in use")?;
                Ok("Event::Contrast(true) remade the palette".to_string())
            },
            settle: 700,
        },
        page_step("high-contrast-leftovers", |app, cx| {
            app.press_key(cx, KeyName::Char('3'), CTRL);
        }),
        page_step("high-contrast-settings", |app, cx| {
            app.press_key(cx, KeyName::Char('6'), CTRL);
        }),
        Step {
            name: "contrast-off-light",
            act: |app, cx| {
                app.hc_forced = None;
                app.set_theme(cx, ThemeChoice::Light);
                app.event(cx, Event::Contrast(false));
                app.press_key(cx, KeyName::Char('1'), CTRL);
            },
            check: |app| {
                want(!app.hc && !app.pal.dark, "light again")?;
                Ok("light".to_string())
            },
            settle: 600,
        },
    ];
    s.extend(flow_steps());
    s.extend(appearance_steps());
    s.extend(bold_steps());
    s
}

fn on(app: &PurgeApp, page: Page, design: Design) -> Result<String, String> {
    want(
        app.model.prefs.design == design,
        format!("design is {:?}", app.model.prefs.design),
    )?;
    want(
        app.model.page == page,
        format!("page is {:?}", app.model.page),
    )?;
    want(app.ctls.len() > 12, "controls are declared")?;
    Ok(format!("{} controls", app.ctls.len()))
}

macro_rules! page {
    ($name:literal, $page:expr, $key:literal, $design:expr) => {
        Step {
            name: $name,
            act: |app, cx| {
                app.set_design(cx, $design);
                app.press_key(cx, KeyName::Char($key), CTRL);
            },
            check: |a| on(a, $page, $design),
            settle: 800,
        }
    };
}

/// The flow of the standard look: the run and then the review of its leftovers on one page.
fn flow_steps() -> Vec<Step> {
    vec![
        Step {
            name: "flow-select",
            act: |app, cx| click_row(app, cx, 4),
            check: |app| {
                want(
                    app.model.programs.sel.len() == 1,
                    format!("{} selected", app.model.programs.sel.len()),
                )?;
                Ok("one program selected".to_string())
            },
            settle: 500,
        },
        Step {
            name: "flow-confirm",
            act: |app, cx| {
                app.click(cx, id("UninstallButton"));
            },
            check: |app| {
                want(app.model.flow.confirm.is_some(), "the confirmation opens")?;
                let c = app.model.flow.page.controller();
                want(
                    c.state_of(purge_ui_model::pipeline::UninstallStep::Run)
                        == purge_ui_model::pipeline::StepState::Pending,
                    "nothing runs before it is confirmed",
                )?;
                Ok("open".to_string())
            },
            settle: 1800,
        },
        Step {
            name: "flow-runs",
            act: |app, cx| {
                app.click(cx, id("ConfirmUninstallButton"));
            },
            check: |app| {
                want(app.model.page == Page::Pipeline, "on the pipeline page")?;
                want(app.model.flow.page.is_busy(), "running")?;
                for name in [
                    "StepperHost",
                    "StepCaption",
                    "ProgressText",
                    "ProgramNameText",
                    "CommandText",
                ] {
                    has(app, name)?;
                }
                want(
                    app.ctl(id("MoveButton")).is_none(),
                    "no review while it runs",
                )?;
                Ok("running".to_string())
            },
            settle: 1500,
        },
        Step {
            name: "flow-arrives-at-review",
            act: nothing,
            check: |app| {
                want(
                    app.model.page == Page::Pipeline,
                    "still on the pipeline page",
                )?;
                let l = &app.model.flow.leftovers;
                want(
                    l.phase() == LeftoversPhase::Review,
                    format!("the review is there, is {:?}", l.phase()),
                )?;
                has(app, "MoveButton")?;
                for c in &app.ctls {
                    if c.id.0 == "ItemTick" {
                        let item = l.items().get(c.id.1 as usize - 1).ok_or("no item")?;
                        want(
                            c.role == Role::Check(Some(item.checked)),
                            "boxes show the model",
                        )?;
                    }
                }
                let program = &app.model.flow.page.view(app.model.flow_env()).program_name;
                want(
                    l.program_name() == program,
                    format!("the review is {}'s, not {}", program, l.program_name()),
                )?;
                Ok(format!(
                    "review in the flow, {} ticked of {}",
                    l.selected_count(),
                    l.selectable_count()
                ))
            },
            settle: 9000,
        },
        Step {
            name: "flow-moved",
            act: |app, cx| {
                app.click(cx, id("MoveButton"));
            },
            check: |app| {
                want(
                    app.model.page == Page::Pipeline,
                    "the result stays in the flow",
                )?;
                want(
                    app.model.flow.leftovers.phase() == LeftoversPhase::Result,
                    format!("moved, is {:?}", app.model.flow.leftovers.phase()),
                )?;
                for name in [
                    "ResultTitleText",
                    "UndoAllButton",
                    "DoneButton",
                    "StepperHost",
                ] {
                    has(app, name)?;
                }
                Ok(app.model.flow.leftovers.result_title_text().to_string())
            },
            settle: 5000,
        },
        Step {
            name: "flow-done",
            act: |app, cx| {
                app.click(cx, id("DoneButton"));
            },
            check: |app| {
                want(
                    app.model.page == Page::Programs,
                    "Done goes back to Programs",
                )?;
                want(!app.model.flow.page.is_busy(), "nothing runs")?;
                Ok("back on Programs".to_string())
            },
            settle: 800,
        },
    ]
}

/// The look's choices: presets in light and dark, the transitions, and none.
fn appearance_steps() -> Vec<Step> {
    vec![
        page_step("settings-again", |app, cx| {
            app.press_key(cx, KeyName::Char('6'), CTRL);
        }),
        Step {
            name: "preset-teal-light",
            act: |app, cx| {
                app.click(cx, crate::screens::swatch_id(Preset::Teal.index()));
                app.press_key(cx, KeyName::Char('1'), CTRL);
            },
            check: |app| {
                want(
                    app.model.prefs.preset == Preset::Teal,
                    "a click on the swatch chose Teal",
                )?;
                want(
                    app.pal.accent == Preset::Teal.palette(false, None).accent,
                    "the palette is Teal's",
                )?;
                Ok("Teal, light".to_string())
            },
            settle: 800,
        },
        Step {
            name: "preset-teal-dark",
            act: |app, cx| app.set_theme(cx, ThemeChoice::Dark),
            check: |app| {
                want(app.pal.dark, "dark")?;
                want(
                    app.pal.accent == Preset::Teal.palette(true, None).accent,
                    "the palette is Teal's dark one",
                )?;
                Ok("Teal, dark".to_string())
            },
            settle: 700,
        },
        page_step("settings-dark", |app, cx| {
            app.press_key(cx, KeyName::Char('6'), CTRL);
        }),
        Step {
            name: "preset-rose-dark-settings",
            act: |app, cx| {
                app.focus.focus(id("ColourChoice"));
                // Enter opens the menu on Teal; Rose is three further down.
                app.press_key(cx, KeyName::Enter, NONE);
                for _ in 0..(Preset::Rose.index() - Preset::Teal.index()) {
                    app.press_key(cx, KeyName::Down, NONE);
                }
                app.press_key(cx, KeyName::Enter, NONE);
            },
            check: |app| {
                want(
                    app.model.prefs.preset == Preset::Rose,
                    format!("the drop-down chose {:?}", app.model.prefs.preset),
                )?;
                want(app.pal.dark, "still dark")?;
                Ok("Rose, dark".to_string())
            },
            settle: 800,
        },
        Step {
            name: "preset-rose-light-history",
            act: |app, cx| {
                app.set_theme(cx, ThemeChoice::Light);
                app.press_key(cx, KeyName::Char('4'), CTRL);
            },
            check: |app| {
                want(!app.pal.dark, "light")?;
                want(app.model.page == Page::History, "on History")?;
                Ok("Rose, light".to_string())
            },
            settle: 800,
        },
        page_step("settings-light", |app, cx| {
            app.press_key(cx, KeyName::Char('6'), CTRL);
        }),
        Step {
            name: "backdrop-by-keys",
            act: |app, cx| {
                // From Acrylic (the last) up to Mica.
                app.focus.focus(id("BackdropChoice"));
                app.press_key(cx, KeyName::Enter, NONE);
                app.press_key(cx, KeyName::Up, NONE);
                app.press_key(cx, KeyName::Enter, NONE);
            },
            check: |app| {
                want(
                    app.model.prefs.backdrop == Backdrop::Mica,
                    format!("chose {:?}", app.model.prefs.backdrop),
                )?;
                let said = app
                    .ctl(id("BackdropChoice"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(
                    said.contains("Window backdrop"),
                    format!("the drop-down is named {said:?}"),
                )?;
                Ok("Mica".to_string())
            },
            settle: 600,
        },
        // ---- UI-FULLFROST: the backdrop's cover and strength ----
        Step {
            name: "glass-whole-window-by-keys",
            act: |app, cx| {
                // "Title and rail" down to "Whole window", then the slider two steps up.
                app.focus.focus(id("BackdropCoversChoice"));
                app.press_key(cx, KeyName::Enter, NONE);
                app.press_key(cx, KeyName::Down, NONE);
                app.press_key(cx, KeyName::Enter, NONE);
                app.focus.focus(id("BackdropStrength"));
                app.press_key(cx, KeyName::Right, NONE);
                app.press_key(cx, KeyName::Right, NONE);
            },
            check: |app| {
                let g = app.model.prefs.glass;
                want(
                    g.covers == crate::look::Covers::Window,
                    format!("covers {:?}", g.covers),
                )?;
                let to = (crate::glass::STRENGTH_DEFAULT + 10).min(100);
                want(
                    g.strength == to,
                    format!("strength {} (want {to})", g.strength),
                )?;
                let c = app
                    .ctl(id("BackdropStrength"))
                    .ok_or("no strength slider")?;
                want(
                    c.role == Role::Slider(f32::from(to)) && c.label == "Backdrop strength",
                    format!("the slider says {:?} {:?}", c.label, c.role),
                )?;
                want(!c.disabled, "the slider is usable")?;
                Ok(format!("whole window, {to}%"))
            },
            settle: 600,
        },
        Step {
            name: "glass-strength-by-pointer",
            act: |app, cx| {
                // A press a fifth of the way along the slider's travel, then the arrows
                // and Home.
                if let Some(r) = app.ctl(id("BackdropStrength")).map(|c| c.rect) {
                    let t = mdshared_ui::slider::THUMB;
                    app.click_at(cx, r.x + t / 2.0 + 0.2 * (r.w - t), r.cy());
                }
                app.note = app.model.prefs.glass.strength.to_string();
                app.press_key(cx, KeyName::Left, NONE);
                app.press_key(cx, KeyName::PageUp, NONE);
            },
            check: |app| {
                want(app.note == "20", format!("the press set {}", app.note))?;
                let s = app.model.prefs.glass.strength;
                want(s == 40, format!("Left then Page Up gave {s}"))?;
                Ok("20% by a press, 40% by the keys".to_string())
            },
            settle: 600,
        },
        Step {
            name: "glass-waits-without-a-backdrop",
            act: |app, cx| app.set_backdrop(cx, Backdrop::Off),
            check: |app| {
                for name in ["BackdropCoversChoice", "BackdropStrength"] {
                    let c = app.ctl(id(name)).ok_or(format!("no {name}"))?;
                    want(c.disabled && !c.focusable, format!("{name} still usable"))?;
                }
                Ok("both wait".to_string())
            },
            settle: 500,
        },
        Step {
            name: "glass-back",
            act: |app, cx| {
                app.set_backdrop(cx, Backdrop::Mica);
                app.set_covers(cx, crate::look::Covers::Chrome);
                app.set_strength(cx, crate::glass::STRENGTH_DEFAULT);
            },
            check: |app| {
                want(
                    app.model.prefs.glass == crate::glass::GlassPrefs::default(),
                    "back to the defaults",
                )?;
                Ok("title and rail, the default strength".to_string())
            },
            settle: 500,
        },
        Step {
            name: "transition-by-keys",
            act: |app, cx| {
                app.focus.focus(id("TransitionChoice"));
                app.press_key(cx, KeyName::Enter, NONE);
                // From Slide (the third) down to Scale (the seventh).
                for _ in 0..4 {
                    app.press_key(cx, KeyName::Down, NONE);
                }
                app.press_key(cx, KeyName::Enter, NONE);
                app.note = format!("{}", app.view.preview_tx.running());
            },
            check: |app| {
                want(
                    app.model.prefs.transition == Transition::Scale,
                    format!("chose {:?}", app.model.prefs.transition),
                )?;
                Ok("Scale; its preview played".to_string())
            },
            settle: 120,
        },
        Step {
            name: "transition-scale-midway",
            act: |app, cx| app.press_key(cx, KeyName::Char('1'), CTRL),
            check: |app| {
                want(app.view.page_tx.running(), "the page is still scaling in")?;
                Ok("midway".to_string())
            },
            settle: 90,
        },
        Step {
            name: "transition-depth-midway",
            act: |app, cx| {
                app.set_transition(cx, Transition::Depth);
                app.press_key(cx, KeyName::Char('5'), CTRL);
            },
            check: |app| {
                want(app.view.page_tx.running(), "the page is still settling")?;
                Ok("midway".to_string())
            },
            settle: 120,
        },
        Step {
            name: "transition-none-is-still",
            act: |app, cx| {
                app.set_transition(cx, Transition::None);
                app.press_key(cx, KeyName::Char('1'), CTRL);
            },
            check: |app| {
                want(!app.view.page_tx.running(), "no motion")?;
                want(app.model.page == Page::Programs, "on Programs")?;
                Ok("none".to_string())
            },
            settle: 60,
        },
        // UI-REDRAW: a page coming in is drawn once and laid over the old one from then on, and
        // a click on it is passed over until it is in place.
        Step {
            name: "paint-matches-the-toolkit",
            act: |_, _| {},
            check: |app| match &app.paint_check {
                Some(Ok(n)) => Ok(format!("{n} boxes and gradients, pixel for pixel")),
                Some(Err(e)) => Err(e.clone()),
                None => Err("not checked".to_string()),
            },
            settle: 10,
        },
        Step {
            name: "transition-away-plainly",
            act: |app, cx| app.press_key(cx, KeyName::Char('3'), CTRL),
            check: |app| {
                want(app.model.page == Page::Leftovers, "on Leftovers")?;
                Ok("Leftovers".to_string())
            },
            settle: 60,
        },
        Step {
            name: "transition-lays-the-held-page",
            act: |app, cx| {
                app.set_transition(cx, Transition::Depth);
                app.press_key(cx, KeyName::Char('1'), CTRL);
            },
            check: |app| {
                want(app.view.page_tx.running(), "the page is still settling")?;
                want(!app.view.page_drawn, "the last frame drew the page again")?;
                want(
                    app.ctl(crate::screens::programs_tab_id(Tab::Apps))
                        .is_some(),
                    "the held page's controls are declared",
                )?;
                Ok("laid, not drawn".to_string())
            },
            settle: 60,
        },
        Step {
            name: "transition-passes-over-a-click",
            act: |app, cx| {
                let from = app.model.programs.tab;
                app.note = format!("{from:?}");
                let to = if from == Tab::Apps {
                    Tab::Components
                } else {
                    Tab::Apps
                };
                app.click(cx, crate::screens::programs_tab_id(to));
            },
            check: |app| {
                want(app.view.page_tx.running(), "the page is still settling")?;
                want(
                    format!("{:?}", app.model.programs.tab) == app.note,
                    format!("the click went through: {:?}", app.model.programs.tab),
                )?;
                Ok("passed over".to_string())
            },
            settle: 20,
        },
        Step {
            name: "transition-in-place-takes-clicks",
            act: |app, cx| {
                let to = if app.model.programs.tab == Tab::Apps {
                    Tab::Components
                } else {
                    Tab::Apps
                };
                app.click(cx, crate::screens::programs_tab_id(to));
                app.set_transition(cx, Transition::None);
            },
            check: |app| {
                want(!app.view.page_tx.running(), "still moving")?;
                want(
                    format!("{:?}", app.model.programs.tab) != app.note,
                    "the click was passed over",
                )?;
                Ok(format!("{:?}", app.model.programs.tab))
            },
            settle: 100,
        },
        Step {
            name: "transition-tab-back",
            act: |app, cx| {
                let back = Tab::ALL
                    .iter()
                    .copied()
                    .find(|t| format!("{t:?}") == app.note);
                if let Some(t) = back {
                    app.click(cx, crate::screens::programs_tab_id(t));
                }
            },
            check: |app| {
                want(
                    format!("{:?}", app.model.programs.tab) == app.note,
                    "the tab is not back",
                )?;
                Ok(app.note.clone())
            },
            settle: 100,
        },
    ]
}

/// Bold: every page, the palette, the rail's card, the command field, dark and contrast.
fn bold_steps() -> Vec<Step> {
    vec![
        Step {
            name: "bold-keeps-state",
            act: |app, cx| {
                app.set_transition(cx, Transition::Fade);
                click_row(app, cx, 2);
                app.note = format!("{:?}", app.model.programs.selected());
                app.set_preset(cx, Preset::Violet);
                app.set_design(cx, Design::Bold);
            },
            check: |app| {
                on(app, Page::Programs, Design::Bold)?;
                want(
                    !app.model.programs.sel.is_empty()
                        && app.note == format!("{:?}", app.model.programs.selected()),
                    "the selection is kept",
                )?;
                Ok("Bold, violet, same selection".to_string())
            },
            settle: 800,
        },
        Step {
            name: "bold-palette",
            act: |app, cx| {
                app.press_key(cx, KeyName::Char('k'), CTRL);
                app.type_text(cx, "quar");
            },
            check: |app| {
                let p = app
                    .view
                    .palette
                    .as_ref()
                    .ok_or("Ctrl+K opened no palette")?;
                want(
                    p.query() == "quar",
                    format!("the palette's query is {:?}", p.query()),
                )?;
                want(
                    p.selected_id() == Some(4),
                    format!("it found {:?}", p.selected_id()),
                )?;
                Ok("palette open, Quarantine found".to_string())
            },
            settle: 700,
        },
        Step {
            name: "bold-palette-runs",
            act: |app, cx| app.press_key(cx, KeyName::Enter, NONE),
            check: |app| {
                want(app.view.palette.is_none(), "closed")?;
                on(app, Page::Quarantine, Design::Bold)?;
                want(
                    app.focus.focused() == Some(crate::screens::nav_id(Page::Quarantine)),
                    format!(
                        "the keyboard went with the page, is on {:?}",
                        app.focus.focused()
                    ),
                )?;
                Ok("Quarantine".to_string())
            },
            settle: 800,
        },
        page!("bold-pipeline", Page::Pipeline, '2', Design::Bold),
        page!("bold-leftovers", Page::Leftovers, '3', Design::Bold),
        page!("bold-history", Page::History, '4', Design::Bold),
        page!("bold-settings", Page::Settings, '6', Design::Bold),
        // The compact rail says what an icon is when the pointer is over it.
        Step {
            name: "bold-rail-hover",
            act: |app, cx| {
                if let Some(r) = app
                    .ctl(crate::screens::nav_id(Page::History))
                    .map(|c| c.rect)
                {
                    app.event(
                        cx,
                        Event::PointerMove {
                            x: r.cx(),
                            y: r.cy(),
                        },
                    );
                }
            },
            check: |app| {
                let tip = app
                    .ctl(Id("NavTip", 0))
                    .ok_or("no card beside the rail's item")?;
                want(
                    tip.label.starts_with("History"),
                    format!("the card says {:?}", tip.label),
                )?;
                want(tip.label.ends_with("Ctrl+4"), "the card names the shortcut")?;
                Ok(tip.label.clone())
            },
            settle: 700,
        },
        Step {
            name: "bold-command-field",
            act: |app, cx| {
                app.click(cx, id("CommandField"));
            },
            check: |app| {
                want(
                    app.view.palette.is_some(),
                    "the field in the title row opens the palette",
                )?;
                want(
                    app.ctl(Id("NavTip", 0)).is_none(),
                    "the rail's card is gone",
                )?;
                Ok("palette open".to_string())
            },
            settle: 700,
        },
        Step {
            name: "bold-programs",
            act: |app, cx| {
                app.press_key(cx, KeyName::Escape, NONE);
                app.press_key(cx, KeyName::Char('1'), CTRL);
            },
            check: |a| on(a, Page::Programs, Design::Bold),
            settle: 800,
        },
        Step {
            name: "bold-dark",
            act: |app, cx| {
                app.press_key(cx, KeyName::Escape, NONE);
                app.set_theme(cx, ThemeChoice::Dark);
                app.press_key(cx, KeyName::Char('5'), CTRL);
            },
            check: |app| {
                want(app.pal.dark, "dark")?;
                Ok("dark".to_string())
            },
            settle: 800,
        },
        page_step("bold-dark-programs", |app, cx| {
            app.press_key(cx, KeyName::Char('1'), CTRL);
        }),
        Step {
            name: "bold-backdrop-acrylic",
            act: |app, cx| app.set_backdrop(cx, Backdrop::Acrylic),
            check: |app| {
                on(app, Page::Programs, Design::Bold)?;
                want(app.model.prefs.backdrop == Backdrop::Acrylic, "Acrylic")?;
                Ok("Bold over Acrylic".to_string())
            },
            settle: 600,
        },
        Step {
            name: "bold-backdrop-off",
            act: |app, cx| app.set_backdrop(cx, Backdrop::Off),
            check: |app| {
                want(app.model.prefs.backdrop == Backdrop::Off, "Off")?;
                Ok("Bold, flat".to_string())
            },
            settle: 600,
        },
        Step {
            name: "bold-high-contrast",
            act: |app, cx| {
                app.hc_forced = Some(true);
                app.event(cx, Event::Contrast(true));
                app.press_key(cx, KeyName::Char('2'), CTRL);
            },
            check: |app| {
                want(app.hc, "the high-contrast palette is in use")?;
                Ok("Bold under high contrast".to_string())
            },
            settle: 700,
        },
        Step {
            name: "back-to-standard",
            act: |app, cx| {
                app.hc_forced = None;
                app.event(cx, Event::Contrast(false));
                app.set_design(cx, Design::Standard);
                app.press_key(cx, KeyName::Char('1'), CTRL);
            },
            check: |app| {
                on(app, Page::Programs, Design::Standard)?;
                want(!app.hc, "contrast off")?;
                Ok("standard again".to_string())
            },
            settle: 700,
        },
    ]
}
