//! The steps of `--script`: what is done and what is checked, in order.

use std::collections::HashSet;

use mdshared_ui::host::{App, Cx, Event};
use mdshared_ui::keys::KeyName;

use crate::app::PurgeApp;
use crate::look::{Choice, Design, Preset, ThemeChoice, Transition};
use crate::model::{LeftoverPhase, OpState, Page, Rating, RunPhase, SortKey, Tab};
use crate::script::{CTRL, NONE, SHIFT, Step};
use crate::ui::{Id, Role, id};

const LIST: Id = Id("ProgramList", 0);

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
            name: "programs",
            act: nothing,
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
                want(app.model.programs.rows.len() == 128, "128 apps")?;
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
                want(app.note == "128", format!("Ctrl+A selected {}", app.note))?;
                let pr = &app.model.programs;
                want(
                    pr.sel.cursor() == Some(127),
                    "End put the cursor on the last row",
                )?;
                want(
                    app.view.list.offset > 1000.0,
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
                want(app.model.programs.rows.len() == 128, "all rows back")?;
                Ok("128 rows".to_string())
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
                    pr.tab == Tab::Components && pr.rows.len() == 64,
                    "64 components",
                )?;
                Ok("Components: 64".to_string())
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
                app.press_key(cx, KeyName::Char('f'), CTRL);
                app.type_text(cx, "firefox");
                app.press_key(cx, KeyName::Down, NONE);
            },
            check: |app| {
                let pr = &app.model.programs;
                want(
                    pr.rows.len() == 1 && pr.sel.len() == 1,
                    format!("{} row(s), {} selected", pr.rows.len(), pr.sel.len()),
                )?;
                Ok("Firefox selected from the search field".to_string())
            },
            settle: 500,
        },
        Step {
            name: "confirm-opens",
            act: |app, cx| {
                app.click(cx, id("UninstallButton"));
            },
            check: |app| {
                want(app.model.confirm.is_some(), "the confirmation is open")?;
                want(app.model.pipeline.run.is_none(), "nothing runs yet")?;
                for name in [
                    "PrimaryButton",
                    "SecondaryButton",
                    "CloseButton",
                    "QuietSwitch",
                    "RestorePointBox",
                    "DialogTitle",
                ] {
                    has(app, name)?;
                }
                want(
                    app.focus.focused() == Some(id("CloseButton")),
                    format!(
                        "the keyboard starts on Not now, is on {:?}",
                        app.focus.focused()
                    ),
                )?;
                Ok("keyboard on Not now; nothing in the pipeline".to_string())
            },
            settle: 700,
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
        Step {
            name: "esc-closes-and-restores-focus",
            act: |app, cx| app.press_key(cx, KeyName::Escape, NONE),
            check: |app| {
                want(app.model.confirm.is_none(), "closed")?;
                want(
                    app.model.pipeline.run.is_none() && app.model.pipeline.queue.is_empty(),
                    "nothing went to the pipeline",
                )?;
                want(
                    app.focus.focused() == Some(id("UninstallButton")),
                    format!("focus went back to {:?}", app.focus.focused()),
                )?;
                Ok("focus is back on Uninstall".to_string())
            },
            settle: 500,
        },
        Step {
            name: "cancel-button-closes",
            act: |app, cx| {
                app.press_key(cx, KeyName::Enter, NONE);
                app.note = format!("{}", app.model.confirm.is_some());
            },
            check: |app| {
                want(app.note == "true", "Enter on Uninstall opened it again")?;
                Ok("open again".to_string())
            },
            settle: 600,
        },
        Step {
            name: "not-now",
            act: |app, cx| {
                app.click(cx, id("CloseButton"));
            },
            check: |app| {
                want(app.model.confirm.is_none(), "Not now closed it")?;
                want(app.model.pipeline.run.is_none(), "nothing runs")?;
                Ok("closed by Not now".to_string())
            },
            settle: 500,
        },
        Step {
            name: "confirm-check-again",
            act: |app, cx| {
                app.click(cx, id("DUninstallButton"));
            },
            check: |app| {
                want(app.model.confirm.is_some(), "opened from the details pane")?;
                want(
                    app.model.pipeline.still_running,
                    "Firefox is said to be running",
                )?;
                Ok("still running is shown".to_string())
            },
            settle: 600,
        },
        Step {
            name: "uninstall-starts-pipeline",
            act: |app, cx| {
                app.click(cx, id("SecondaryButton"));
                app.click(cx, id("QuietSwitch"));
                app.click(cx, id("PrimaryButton"));
            },
            check: |app| {
                want(app.model.page == Page::Pipeline, "on the pipeline page")?;
                want(app.model.pipeline.quiet, "quiet mode was switched on")?;
                let run = app.model.pipeline.run.as_ref().ok_or("no run")?;
                want(run.phase == RunPhase::Running, "running")?;
                has(app, "StepperHost")?;
                has(app, "ProgramNameText")?;
                Ok(format!("running, step {}", run.step + 1))
            },
            settle: 1200,
        },
        Step {
            name: "pipeline-midway",
            act: nothing,
            check: |app| {
                let run = app.model.pipeline.run.as_ref().ok_or("no run")?;
                want(
                    run.phase == RunPhase::Running && run.step >= 2,
                    format!("steps advance on the timer: step {}", run.step + 1),
                )?;
                Ok(format!("step {} of 6", run.step + 1))
            },
            settle: 4000,
        },
        Step {
            name: "pipeline-finished",
            act: nothing,
            check: |app| {
                let run = app.model.pipeline.run.as_ref().ok_or("no run")?;
                want(run.phase == RunPhase::Finished, "finished")?;
                want(
                    app.model.leftovers.phase == LeftoverPhase::Review,
                    "leftovers wait for review",
                )?;
                // The flow shows the review on this page; the other layout has a Next button.
                want(
                    app.ctl(id("NextButton")).is_some() || app.ctl(id("MoveButton")).is_some(),
                    "a way on to the review",
                )?;
                want(
                    app.model.programs.count(Tab::Apps) == 127,
                    "the program left the list",
                )?;
                Ok("finished; 9 leftovers to review".to_string())
            },
            settle: 5500,
        },
        Step {
            name: "leftovers-review",
            act: |app, cx| {
                if app.ctl(id("NextButton")).is_some() {
                    app.click(cx, id("NextButton"));
                } else {
                    app.press_key(cx, KeyName::Char('3'), CTRL);
                }
            },
            check: |app| {
                want(app.model.page == Page::Leftovers, "on the leftovers page")?;
                let l = &app.model.leftovers;
                for i in l.groups.iter().flat_map(|g| &g.items) {
                    want(
                        i.ticked == (i.rating == Rating::Safe),
                        format!("{} starts {}", i.path, i.ticked),
                    )?;
                }
                for name in [
                    "TitleText",
                    "MoveButton",
                    "FooterCount",
                    "ExpandButton",
                    "WeakButton",
                    "DTitle",
                    "DEvidence",
                ] {
                    has(app, name)?;
                }
                // What the page shows must be what the model holds: no Likely box drawn ticked.
                for c in &app.ctls {
                    if c.id.0 == "ItemTick" {
                        let at = crate::app::item_at(c.id.1);
                        let item = l.item(at).ok_or("a box for no item")?;
                        want(
                            c.role == Role::Check(Some(item.ticked)),
                            format!("{} is drawn {:?}", item.path, c.role),
                        )?;
                        want(
                            c.disabled == (item.rating == Rating::Protected),
                            "a protected box is disabled",
                        )?;
                    }
                }
                Ok(format!(
                    "{} ticked of {}; Likely and Protected unticked",
                    l.ticked().0,
                    l.count()
                ))
            },
            settle: 900,
        },
        Step {
            name: "leftovers-group-mixed",
            act: |app, cx| {
                // Tick the one Likely item of the first group by hand, then untick a Safe one.
                app.click(cx, Id("ItemTick", crate::app::item_no(0, 2)));
                app.click(cx, Id("ItemTick", crate::app::item_no(0, 0)));
            },
            check: |app| {
                let g = app
                    .model
                    .leftovers
                    .groups
                    .first()
                    .ok_or("no leftovers to review")?;
                want(g.items.len() >= 3, "the first group has its items")?;
                want(
                    g.items[2].ticked && !g.items[0].ticked,
                    "the two boxes changed",
                )?;
                want(g.tick().is_none(), "the group's box is mixed")?;
                let c = app.ctl(Id("GroupTick", 1)).ok_or("no group box")?;
                want(
                    c.role == Role::Check(None),
                    format!("the group box is drawn {:?}", c.role),
                )?;
                want(
                    app.model.leftovers.selected == Some((0, 0)),
                    "the evidence pane follows the last item",
                )?;
                let shown = app
                    .ctl(id("DPath"))
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                want(shown == g.items[0].path, format!("evidence shows {shown}"))?;
                Ok("group box mixed; evidence follows the selection".to_string())
            },
            settle: 600,
        },
        Step {
            name: "leftovers-expanders",
            act: |app, cx| {
                app.click(cx, Id("GroupTick", 1));
                app.click(cx, Id("Group", 3));
                app.click(cx, Id("Group", 2));
            },
            check: |app| {
                let l = &app.model.leftovers;
                want(l.groups.len() >= 3, "no leftovers to review")?;
                want(
                    l.groups[2].open && !l.groups[1].open,
                    "one group opened, one closed",
                )?;
                // From mixed, the group box ticks the Safe ones again. The Likely one stays as the
                // user left it: ticked by hand in the step before, so the box is now fully ticked.
                let g = &l.groups[0];
                want(
                    g.items
                        .iter()
                        .filter(|i| i.rating == Rating::Safe)
                        .all(|i| i.ticked),
                    "the group box ticked the Safe ones",
                )?;
                want(
                    g.items[2].rating == Rating::Likely && g.items[2].ticked,
                    "the hand-ticked Likely item is left alone",
                )?;
                want(
                    g.items
                        .iter()
                        .all(|i| i.rating != Rating::Protected || !i.ticked),
                    "nothing protected is ticked",
                )?;
                want(g.tick() == Some(true), "the group's box is ticked")?;
                Ok("expanders toggled; the hand-ticked Likely item is kept".to_string())
            },
            settle: 700,
        },
        // The group box on its own: off, then on again. Coming back it ticks the Safe items and
        // leaves the Likely one unticked, so the group is back at its defaults.
        Step {
            name: "leftovers-group-box-skips-likely",
            act: |app, cx| {
                app.click(cx, Id("GroupTick", 1));
                app.note = format!("{:?}", app.model.leftovers.groups.first().map(|g| g.tick()));
                app.click(cx, Id("GroupTick", 1));
            },
            check: |app| {
                want(
                    app.note == "Some(Some(false))",
                    format!("the first click unticked the group: {}", app.note),
                )?;
                let l = &app.model.leftovers;
                let g = l.groups.first().ok_or("no leftovers to review")?;
                want(
                    g.items
                        .iter()
                        .all(|i| i.ticked == (i.rating == Rating::Safe)),
                    "the group box ticked the Safe ones only",
                )?;
                want(
                    g.tick().is_none(),
                    "with the Likely one unticked the box is mixed",
                )?;
                let c = app.ctl(Id("GroupTick", 1)).ok_or("no group box")?;
                want(
                    c.role == Role::Check(None),
                    format!("the group box is drawn {:?}", c.role),
                )?;
                Ok(format!(
                    "{} ticked of {}; the group box never ticks Likely",
                    l.ticked().0,
                    l.count()
                ))
            },
            settle: 700,
        },
        Step {
            name: "leftovers-moved",
            act: |app, cx| {
                app.click(cx, id("MoveButton"));
            },
            check: |app| {
                want(app.model.leftovers.phase == LeftoverPhase::Moved, "moved")?;
                for name in [
                    "ResultTitleText",
                    "ResultDetailText",
                    "UndoAllButton",
                    "DoneButton",
                ] {
                    has(app, name)?;
                }
                Ok(format!("{} items moved", app.model.leftovers.moved.0))
            },
            settle: 700,
        },
        Step {
            name: "leftovers-undone",
            act: |app, cx| {
                app.click(cx, id("UndoAllButton"));
            },
            check: |app| {
                want(app.model.leftovers.phase == LeftoverPhase::Undone, "undone")?;
                has(app, "UndoTitleText")?;
                has(app, "UndoDetailText")?;
                Ok("undo shown".to_string())
            },
            settle: 700,
        },
        Step {
            name: "history",
            act: |app, cx| {
                app.click(cx, id("NavHistory"));
            },
            check: |app| {
                want(app.model.page == Page::History, "on History")?;
                for name in [
                    "CheckInterrupted",
                    "RestoreSelected",
                    "RestoreAll",
                    "DTitle",
                    "DSummary",
                    "ShowItems",
                    "DExpiry",
                ] {
                    has(app, name)?;
                }
                Ok("drawn".to_string())
            },
            settle: 700,
        },
        Step {
            name: "history-restore",
            act: |app, cx| {
                app.click(cx, Id("Op", 2));
                app.click(cx, id("ShowItems"));
                app.click(cx, id("RestoreSelected"));
            },
            check: |app| {
                let h = &app.model.history;
                want(h.selected == 1 && h.show_items, "second entry, items shown")?;
                want(
                    h.ops.get(1).is_some_and(|o| o.state == OpState::Restored),
                    "restored",
                )?;
                want(h.notice.is_some(), "the info bar says so")?;
                has(app, "InfoBarHost")?;
                Ok(h.notice.clone().unwrap_or_default())
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
                for name in ["ReviewButton", "Volumes", "Totals", "ItemsTitle"] {
                    has(app, name)?;
                }
                Ok("drawn".to_string())
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
                    "PreviewTransition",
                    "TransitionPreview",
                    "ConfirmEach",
                ] {
                    has(app, name)?;
                }
                has_id(app, Id("TickRule", 1))?;
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
            app.model.leftovers.found_for(0, &app.model.programs.all[0]);
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
                app.model.leftovers.done();
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

/// The flow of the standard look: the review of the leftovers inside the pipeline page.
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
                want(app.model.confirm.is_some(), "the confirmation opens")?;
                want(
                    app.model.pipeline.queue.is_empty()
                        && !app
                            .model
                            .pipeline
                            .run
                            .as_ref()
                            .is_some_and(|r| r.phase == RunPhase::Running),
                    "nothing runs before it is confirmed",
                )?;
                Ok("open".to_string())
            },
            settle: 700,
        },
        Step {
            name: "flow-runs",
            act: |app, cx| {
                app.click(cx, id("PrimaryButton"));
            },
            check: |app| {
                want(app.model.page == Page::Pipeline, "on the pipeline page")?;
                let run = app.model.pipeline.run.as_ref().ok_or("no run")?;
                want(
                    run.phase == RunPhase::Running && run.step >= 1,
                    format!("steps advance: step {}", run.step + 1),
                )?;
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
                Ok(format!("running, step {} of 6", run.step + 1))
            },
            settle: 2600,
        },
        Step {
            name: "flow-arrives-at-review",
            act: nothing,
            check: |app| {
                want(
                    app.model.page == Page::Pipeline,
                    "still on the pipeline page",
                )?;
                want(
                    app.model.leftovers.phase == LeftoverPhase::Review,
                    "the run finished and the review is there",
                )?;
                has(app, "MoveButton")?;
                for c in &app.ctls {
                    if c.id.0 == "ItemTick" {
                        let item = app
                            .model
                            .leftovers
                            .item(crate::app::item_at(c.id.1))
                            .ok_or("no item")?;
                        want(
                            c.role == Role::Check(Some(item.ticked)),
                            "boxes show the model",
                        )?;
                        want(
                            item.ticked == (item.rating == Rating::Safe),
                            "defaults hold in the flow",
                        )?;
                    }
                }
                let l = &app.model.leftovers;
                let program = l
                    .program
                    .and_then(|p| app.model.programs.all.get(p))
                    .ok_or("the review has no program")?;
                let first = &l.groups[0].items[0].path;
                want(
                    *first == program.location,
                    format!("the leftovers are {}'s, not {first}", program.name),
                )?;
                Ok(format!(
                    "review in the flow, {} ticked of {}",
                    l.ticked().0,
                    l.count()
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
                want(app.model.leftovers.phase == LeftoverPhase::Moved, "moved")?;
                for name in [
                    "ResultTitleText",
                    "UndoAllButton",
                    "DoneButton",
                    "StepperHost",
                ] {
                    has(app, name)?;
                }
                Ok(format!(
                    "{} items moved, shown in the flow",
                    app.model.leftovers.moved.0
                ))
            },
            settle: 900,
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
                want(app.model.pipeline.run.is_none(), "nothing runs")?;
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
