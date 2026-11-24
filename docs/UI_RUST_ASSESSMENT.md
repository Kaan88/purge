# Can markdown-shared-rs replace Purge's WinUI 3 UI?

Research only, 2026-11-24. Nothing was built, committed or pushed in either repo. Toolkit clone:
`C:\Users\kaank\.claude\jobs\22395df2\tmp\toolkit` (all branches fetched; checked out at `origin/feat/anim`).
No `cargo` build was run (C: had 6.1 GB free), so no toolkit code was compiled or run by me; CI results were read
from GitHub instead. Purge paths are relative to `C:\Users\kaank\Desktop\uninstall\purge`.

**Short answer.** Yes, it can replace the UI, and Purge would become all Rust. Launch time and binary size get much
better. One prerequisite blocks shipping: **accessibility (roadmap W8) is not built.** Until it is, a toolkit window
is one opaque pane to Narrator and to the VM rig's UI Automation driver, so the e2e gate cannot run at all. W8 has to
be fast-tracked, at Purge's minimum scope, before the Rust UI can replace WinUI. The second-largest item is the
window loop (W1). Every application currently writes its own loop, and Purge would have to as well. Everything else
needed is either already there or small.

---

## 0. Toolkit readiness checklist (the precondition for the port)

**Decision (user, 2026-11-25):** the Purge port starts only when the shared toolkit is completely ready. Until then
Purge keeps shipping WinUI, and M3 finishes on WinUI. "Ready" means every item below is on `main` of
`Kaan88/markdown-shared-rs` with CI green on Windows. Purge then pins one `main` rev and never needs a feature branch.
Ids **P1-P..** are new and are proposed as roadmap rows; W/L/X ids are the toolkit's own (`docs/ROADMAP.md` on
`feat/anim`). Sizes: S = a day or two, M = about a week, L = several weeks.

### A. Merge to `main` (what exists already)

Of the toolkit's 36k-line `feat/anim` branch (`e08f3dc`), Purge needs these modules. They depend on each other, so
merging the whole branch is the simplest route. If you would rather merge in slices, these are the ones Purge
needs, in this order:

| # | Module(s) on `feat/anim` | Why Purge needs it |
|---|---|---|
| A1 | `tokens.rs`, `anim.rs` + `anim/*`, `gfx/shapes.rs`, the `gfx.rs` / `glyph.rs` / `check.rs` / `segments.rs` / `overlay.rs` / `menu.rs` / `place.rs` / `platform.rs` / `plan.rs` changes | the base the rest builds on: tokens and HC, Expander motion, the vault's days-left ring |
| A2 | `focus.rs` (W2), `cursor.rs` (W4), `commands.rs` (keymap) | Tab order and dialog scopes, Ctrl+F, column-resize cursors |
| A3 | `rows.rs` changes, `select.rs`, `table.rs`, `scroll.rs` changes, `viewport.rs` (L3), `sections.rs` (L2), `grid.rs` | the Programs list (multi-select, sorted columns), Leftovers' grouped list, History's horizontal strip |
| A4 | `slider.rs` (progress, indeterminate bar, spinner), `splitter.rs` | uninstall and scan progress, vault usage bars, the details pane split |
| A5 | `mdshared-app/src/fmt.rs` | sizes and dates ("1.2 GB", "3 days ago") |
| A6 | Dependabot PRs #3-#7 (parley 0.13, windows-sys 0.61, libloading 0.9, x11rb 0.14, notify 8.2.2) | merge or close before Purge pins, so Purge does not start on versions that are about to change |

Not needed by Purge; merge them or not as you like: `knob`, `meter`, `waveform`, `spectrum`, `seek`, `cover`,
`thumbs`, `media_session`, `tray`, `notify`, `window_state`, `submenu`, `mdshared-text/image.rs`, the whole
`mdshared-term` crate, `mdshared-app/pool.rs`. The closed `feat/classic-widgets` (PR #8) isn't needed either.

**Before or while merging:**
- **Open a PR from `feat/anim`.** CI has never run on it: CI runs only on `main` pushes and PRs.
- **Fix the red Linux and macOS `cargo test` on `main`,** or mark those jobs as non-blocking. Purge itself only
  needs Windows to be green.
- **The toolkit rule "a piece reaches `main` only once an application uses it"** can't be met by Purge, because
  Purge only starts after the merge. Proposal: a toolkit example `examples/purge_shape.rs` counts as that consumer.
  It is one window with a 2,000-row multi-select list, a search field, a grouped list, a dialog and AccessKit (the
  spike in §5 step 1). Alternatively, mdmix counts if it already uses these modules.

### B. Build (what doesn't exist yet)

| # | Item | Size | Done when |
|---|---|---|---|
| B1 | **W8 Accessibility**, Windows UIA at Purge's scope (AccessKit behind `a11y`) | L | A UIA client run against `purge_shape` (PowerShell `System.Windows.Automation`, as in `vm/guest/m3-e2e-ui.ps1`) can: find elements by **AutomationId** (author id) and by name; **Invoke** buttons; **Toggle** check boxes; **SelectionItem** select list rows; **ScrollItem** scroll a virtualized row into view; read **RangeValue** of a progress bar; **ExpandCollapse** an expander; and see a dialog as a window with its buttons. Narrator reads names, check states and "row 5 of 2,000". The list reports its full row count while realizing only visible rows. Focus changes raise UIA focus events. |
| B2 | **W1 window host**, single-window minimum | L | One undecorated window with min size; Mica and frost; scale changes; damage-only present; one wake-up for animation, caret, tooltips and an app channel (`EventLoopProxy`, for engine replies); the first frame is drawn hidden then shown, with no white flash; the AccessKit adapter is plugged in. No tabs, no multiple windows. (Purge could own this loop instead, but with "completely ready" it belongs in shared.) |
| B3 | **W5 extension:** the system's high-contrast colours | S | Under Windows HC, the tokens use the active scheme's `GetSysColor` colours (window, text, highlight, hotlight, gray text, button face/text), and Mica / Acrylic / frost are turned off. Switching HC while running repaints. |
| B4 | **X8 caret blink** | S | Text fields blink at the system rate (`GetCaretBlinkTime`, off when it is infinite) and wake the loop only while focused. |
| P1 | **Selector bar with N options** (tabs) | S | `segments` with any count; keyboard arrows; one UIA tab or radio item each. |
| P2 | **InfoBar** (extends `notice`) | S | Info / success / warning / error colours and glyphs; title, message and up to two action buttons; close button; several stacked; in-page, not only at the top. |
| P3 | **Expander** | S | A header with a chevron, an animated body (respects reduced motion), and the UIA ExpandCollapse state. |
| P4 | **Dropdown (ComboBox) and toggle switch,** standalone | S | Usable outside `settings::Form`; the dropdown opens a `menu` under itself; keyboard operable. |
| P5 | **Hyperlink button** | S | Underlined on hover, hand cursor, Invoke in UIA. |
| P6 | **Anchored flyout card** | S | Arbitrary content (text, a check box, a button) in a card placed like `Menu::around`; Esc and click-outside close it; it is its own focus scope. |
| P7 | **Read-only selectable text** | M | Drag, double-click and Shift-select in a non-editable paragraph (wrap and monospace); Ctrl+C; a context-menu Copy; UIA Text pattern optional. |
| P8 | **Named-mutex single instance** in `mdshared-app` (optional) | S | A second launch brings the first window forward through a named mutex and `FindWindow`, with no TCP listener. Only needed if Purge wants single instance. Today's loopback-TCP `single` must not be used by Purge. |

### C. Checks that the ready toolkit meets Purge's gates

| # | Check | Pass |
|---|---|---|
| C1 | Launch: `purge_shape` with the real `purge-engine --stdio` program list, timed with `cargo xtask bench-launch` on the laptop | names visible ≤ 400 ms (today WinUI takes about 450 ms); a bare winit+softbuffer window replaces `BareWinUI` as the "bare + 60 ms" reference |
| C2 | The UIA run from B1, on the host (no VM needed) | every action listed in B1 works |
| C3 | Size | `purge_shape` release exe under 10 MB |

When A, B and C are all done, the Purge-side steps start (§5 steps 3-6). §5 step 1 (the spikes) becomes C1/C2 above,
and §5 step 2 is this checklist.

---

## 1. What the toolkit is

**Repo and scope.** `Kaan88/markdown-shared-rs` is a Cargo workspace (edition 2024, MIT). "Shared" means the whole
repo. The GUI part is the crate **`mdshared-ui`**; the other crates supply text, plumbing and downloads. Its own
description (`AGENTS.md` on `feat/anim`) is "a small GUI toolkit and the application plumbing that goes with it". It
started as the code shared by mdview and mdedit, and is growing into the base for mdmix, a music player, a file
manager and a terminal.

**What it is built on.** It is not egui, not wgpu, not native controls and not a GPU renderer. It draws everything
itself:
- **Painting:** a CPU software painter (`mdshared_ui::gfx::Painter`) draws each frame into a BGRA `Bitmap`
  (`mdshared-text/src/bitmap.rs`). The application presents the bitmap with **softbuffer** in its own **winit 0.30**
  loop.
- **Text:** parley shapes and swash rasterizes, with subpixel masks.
- **Icons:** stroked with zeno.
- **OS calls:** windows-sys on Windows; zbus and objc2 elsewhere.
- **Retained state:** none. There is no widget tree and no callbacks. Each widget is a pure model plus `draw_*`
  functions, and the application owns the events, the hits and the loop (AGENTS.md "Shape of the code").
- **Idle behaviour:** the loop redraws only on events (`ControlFlow::Wait`/`WaitUntil`), so an idle window does no
  work.

So the "no egui" rule is not broken in the literal sense. In spirit, this is the same family as egui: a custom-drawn
UI with no native controls. The user has now said they accept that and like the look (Mica/Acrylic through `frost`).

### Crates

| Crate | Holds | Relevance to Purge |
|---|---|---|
| `mdshared-text` | Bitmap, TextEngine (parley/swash), shared fonts, PNG/JPEG decode (`image`, feat/anim) | needed |
| `mdshared-ui` | painter, palettes, tokens, widgets, list models, anim, focus, platform glue | needed |
| `mdshared-app` | settings file, single instance (loopback TCP), job/pool workers, fmt, fuzzy, updater, crash reports | partly |
| `mdshared-fetch` | WinHTTP downloads | not needed |
| `mdshared-highlight` | syntect + scanners | not needed (keeps syntect out of the exe) |
| `mdshared-term` (feat/anim only) | VT terminal model | not needed |

### Parts and maturity
"Provisional" means the catalogue (`docs/CATALOGUE.md`) marks it so: on a branch, used by fewer than two apps.

| Area | State |
|---|---|
| Painter (boxes, text, elide, paragraph, icons, clip, opacity, shapes/arcs/rings/gradients) | **Mature** on main (used by mdview/mdedit since 2026-11-12); shapes on feat/anim |
| Window chrome: hand-drawn title row, caption buttons, resize edges, Win11 snap-layouts flyout (`snap`), DWM corners/shadow, Mica/Acrylic (`platform::set_backdrop`, `frost`) | Mature on Windows |
| Theme: `theme::LIGHT/DARK` | Mature |
| Theme: `tokens` (system accent, toolkit-made high-contrast palettes at 7:1) | Provisional (feat/anim). It does **not** use the Windows HC scheme's own system colours (`tokens.rs` doc: "Deliberately not here") |
| Text: textfield with IME preedit (`textfield::Preedit`); multi-line paragraphs; selection inside a field only | Mature. No read-only selectable text block |
| DPI: per-monitor v2 (`platform::system_scale`, winit scale factor); logical px everywhere; painter snaps to device px | Mature |
| Lists: `rows` (fixed-height virtualization), `sections` (variable height, sticky collapsible group headings), `grid`, `select` (click/Ctrl/Shift/keys/rubber band, type-ahead), `table` (columns, resize, sort, saved widths), `scroll`/`viewport`, `splitter` | `rows`/`scroll` mature; the rest provisional (feat/anim) |
| Controls: `check` (tick box), `segments` (2-3 option switch), `slider` (+ progress bar, indeterminate bar, spinner), `menu` + `submenu`, `palette` (command palette), `settings::Form` (toggle/choice/number/text/action rows), `overlay` (toast, tooltip, modal dialog card and buttons), `notice` (top bars: update/crash/offer), `classic` (menu bar, column header, field, push button) | menu/overlay/notice/settings/textfield mature; `classic` only on a closed-unmerged PR branch (#8, CI failed on `cargo fmt`) |
| Focus: `focus` (Tab order, scopes, rings on keyboard use only) | Provisional (feat/anim); no arrow/Enter/Escape handling |
| Animation: `anim` (tweens, springs, Fluent timings, reduced motion, page transitions) | Provisional; reviewed; "seen" only in mdmix |
| Platform: clipboard, open URL/file, reveal in Explorer, file dialogs (rfd), system dark/accent/HC, reduced motion | Mature |
| Platform: `tray`, `notify` (WinRT toasts), `window_state`, `media_session` | Provisional; Windows run by example, Linux unverified |
| Accessibility (UIA / screen readers) | **None.** Roadmap W8, decided "AccessKit behind feature `a11y`", status open, XL, high risk. The only accessibility code reads the HC and reduced-motion settings |
| Window loop / host | **None.** Roadmap W1, XL, open. Each app has its own loop (mdview's `bins/mdv-app/src/app.rs` is about 90 KB, mdedit's about 230 KB) |
| Shell icons of files (F5) | Open; Purge does not need it (see §2) |
| Translations (W9) | Open |

### Conventions the user follows
From `AGENTS.md`, `docs/NEW-MODULE.md` and `docs/ROADMAP.md`:
- **Model and drawing:** models and drawing are kept separate; no callbacks; no clock inside a model (time is passed
  in; tests use `ManualClock`).
- **Code:** one file per job, with a "Deliberately not here" doc section. Code is hand-written where the job is
  bounded. Every new dependency is pinned exactly with a written reason. `unsafe` only in the platform modules, each
  block with a `// SAFETY:` line.
- **Tests:** drawing is tested by pixels; specimen PNG sheets are `#[ignore]` tests.
- **Compatibility:** "add; do not change". Consumers pin a `rev`, so a change must not break mdview or mdedit.
- **Workflow:** roadmap items are claimed before work starts. A piece reaches `main` only once an application uses
  it and it has been reviewed.
- **Reporting:** results say "compiled, not run" and "not seen by a person". Agent commits carry a model trailer.

### Branches

| Branch | What it adds | State |
|---|---|---|
| `main` (b5fe402) | the five crates as used by mdview/mdedit (pinned `ef88814`) | CI: Windows green; Linux/macOS `cargo test` red on the last pushes |
| `feat/anim` (54 commits, +36k lines, last 2026-11-24 20:41) | `AGENTS.md`/`CLAUDE.md`/CATALOGUE/ROADMAP/FEATURES/ANIMATION/NEW-MODULE docs; `anim`, `tokens`, `focus`, `cursor`, `select`, `table`, `grid`, `rows` additions, `sections`, `viewport`/hscroll, `splitter`, `slider` (progress/spinner), `submenu`, `commands` (keymap), `tray`, `notify`, `window_state`, `media_session`, audio widgets (meter, waveform, spectrum, knob, seek, cover), `thumbs`, `image`, `gfx/shapes`; `mdshared-app::{fmt, pool}`; the new `mdshared-term` crate | Not merged, no PR, so CI never ran on it (CI runs on main pushes and PRs only) |
| `feat/classic-widgets` (1 commit) | `classic.rs`: menu bar, column header, field, button, for a two-panel file manager | PR #8 closed unmerged; CI failed at `cargo fmt` |
| `chore/dependabot`, `dependabot/*` | dependency bumps (parley 0.13, windows-sys 0.61, …) | open PRs |

**Consumers:**
- **markdown-viewer-rs (mdview):** pins `ef88814`. README "Numbers": first frame 63-98 ms, 24 MiB private memory,
  `mdview.exe` 7.5 MB (with a Markdown renderer, Mermaid and syntect inside).
- **markdown-editor-rs (mdedit).**
- **mdmix:** the Rust app is not on GitHub's default branch (only Python there), so I could not read how it uses
  `feat/anim`.

---

## 2. Mapping: every Purge UI element to the toolkit

Inventory from `ui/Purge.App` (9,689 lines of C# and XAML) and `ui/Purge.Client` (7,849 lines of C#).

Legend:
- **Have:** a module exists.
- **Partly:** pieces exist and the app or a small addition composes the rest.
- **Missing:** nothing exists.

| Purge element (file) | Toolkit | Notes |
|---|---|---|
| Window, Mica backdrop (`MainWindow.xaml.cs` l.30) | **Have** | `platform::set_backdrop(Backdrop::Mica)`, `frost` key-out of chrome pixels |
| Custom title bar with app glyph and "Administrator" chip (`MainWindow.xaml` l.93-107) | **Have** | `chrome` caption buttons, `window::edge_at`, `snap::set_maximize_button_rect`; the chip is app drawing |
| Minimum size 760×520, initial 1360×860 centred and clamped to work area | **Have** | winit `with_min_inner_size`; `place::work_area`; `window_state` if placement should persist (Purge does not persist today) |
| Narrow layout < 720 px (designed, not built) | Partly | app layout code; no layout engine in the toolkit (by design) |
| Left rail: 6 buttons, selection pill, count badges, dynamic names ("Leftovers, 3 to review") | Partly | `pane::draw_row_fill`, painter; app view (S) |
| Page switch, lazy pages | **Have** | app state; `anim::PageTransition` optional |
| S1 tabs (4 RadioButtons: Apps/Components/Unnamed/Recent) | Partly | `segments` takes 2-3 options only; a 4+ option selector bar is a small generic addition |
| S1 search TextBox, Ctrl+F, Esc to clear or move focus to the list | **Have** | `textfield` (+IME), `keys::parse("Ctrl+F")`/`commands` keymap, `focus`; caret blink is X8 (open) |
| S1 filter MenuFlyout with ToggleMenuFlyoutItems; sort DropDownButton | **Have** | `menu::Menu` with `Item::checked()`, `Menu::around(rect)` |
| S1 lazy CommandBar "More actions" (Open folder, Search web, Refresh) | **Have** | `menu`; `platform::open_url`, `reveal_in_file_manager` |
| S1 list: virtualized, multi-select, 40 px rows, icon, column-header sort buttons, 300-2,000 rows | **Have** | `rows` (virtualization arithmetic), `select` (multi-select), `table` (header, sort, widths), `scroll::SmoothScroll` |
| Row icons from exe files | **Have** (engine side) | The engine already extracts them (`crates/purge-win/src/icons.rs`, SHGetFileInfoW to 24 px BGRA) and sends `icon.batch`; the UI premultiplies and draws with `Painter::image`. Toolkit F5 is not needed. The icon atlas (`Shell/IconAtlas.cs`) ports to Rust |
| "Removed outside Purge" group with per-row Check/Dismiss | Partly | `sections` + buttons; app view |
| InfoBars, made in code, with action buttons, on every page | Partly | `notice::draw_offer_bar` / `bar_button` are top-of-page bars; missing are severity colours (info/warning/error/success), several stacked, and a close button. Small generic addition |
| Details pane: card, ScrollViewer, 44 px icon, "What Purge expects" list, HyperlinkButton, Expander, selectable monospace text | Partly | painter, `scroll`, `splitter` optional. Missing generic pieces: **Expander** (S, `anim::Transient`), **hyperlink button** (S), **read-only selectable text** (M; today selection exists only inside `textfield`) |
| S2 stepper (○ ● ✓ ! ×), run card with the exact command | **Have** | painter text and glyphs |
| S2 restore-point ComboBox, quiet-mode ToggleSwitch | Partly | ComboBox = button + `menu`; `settings::Form` has `choice` and `toggle` rows, but only inside its own dialog. A standalone dropdown and a toggle switch are small additions (or `classic::button` + `menu`) |
| S2 "Uninstall X?" ContentDialog with a toggle and a combo inside; first-elevation ContentDialog | Partly | `overlay::dialog_card`, `draw_backdrop`, `draw_dialog_button`, `focus::push_scope`; the app composes the content |
| S3 Leftovers: flattened virtualized list with group headers (chevron, group CheckBox), item CheckBoxes, band chips, 2,000 items | **Have** | `sections` (sticky, collapsible groups), `check::Tick`, painter chips |
| S3 verdict bar, evidence list, waiting panel (indeterminate ProgressRing, "code in the security prompt"), result panels | **Have** | `slider::draw_spinner`, painter |
| S4 History: horizontal ListView "Strip", Ops list, detail with CheckBoxes, loading ring | **Have** | `viewport`/`hscrollbar` or `grid` one row, `rows`, `check`, spinner |
| Vault: volume cards with ProgressBar; determinate ring with days left; Flyout with CheckBox + Continue | **Have** / Partly | `slider::draw_progress`; `Painter::arc`/`ring` for the ring; flyout = small anchored card (compose from `overlay` + `Menu::around` placement) |
| S5 Settings: Theme ComboBox, About, debug Expander | **Have** | `settings::Form` fits; settings persistence via `mdshared_app::settings` (Purge has none today) |
| Theme: light/dark following Windows, `--theme` override | **Have** | `platform::system_is_dark`, `theme`/`tokens` |
| High contrast (designed: system colours, no Mica, four HC themes) | Partly | `platform::system_high_contrast` + `tokens::high_contrast`; missing the system HC scheme colours (GetSysColor) and turning off `frost` in HC. Small generic addition |
| Tooltips | **Have** | `overlay::Bubble::tip` |
| Toasts / system notifications | Not used by Purge today | `notify` exists if wanted later |
| Keyboard navigation (default XAML Tab/arrows, Esc) | Partly | `focus` (Tab, scopes) + `rows::nav`/`select::nav` (arrows); Enter/Space/Escape are the app's per widget |
| Screen-reader names (43 XAML + 12 code names; 0.1.9 shipped fixes) | **Missing** | W8 |
| UI Automation for the VM rig (`vm/guest/m3-e2e-ui.ps1` finds 16 AutomationIds, uses Invoke/ScrollItem/SelectionItem patterns) | **Missing** | W8 |
| Context menus (designed right-click copy, not built) | **Have** | `menu`, `platform::set_clipboard_text` |
| Clipboard | **Have** | `platform` |
| File/folder pickers (designed Force-remove picker, not built) | **Have** | `platform::pick_*_async` (rfd) |
| Updater UI | Not needed | ENGINE_PLAN says "No … update checker"; releases go through the Hub. `mdshared_app::updater` swaps exes in place, which cannot work in an admin-only `{autopf}\Purge` and would break the broker's image check. Do not use it |
| Single instance | Not built in Purge | `mdshared_app::single` exists but listens on a **loopback TCP port**, a new local attack surface for a security tool. If Purge wants single instance, use a named mutex plus `FindWindow`/`SetForegroundWindow` in Purge (S) |
| Tray, drag and drop, localisation | Not in Purge today | (`tray`; L7 open; W9 open) |
| Launch markers (`Shell/LaunchMarkers.cs`, `PURGE_BENCH_OUT`) | Purge | trivial in Rust: write the same `marker=ms` line |

---

## 3. Gaps: toolkit vs Purge

### Belongs in the shared toolkit (generic)

| Gap | Size | Note |
|---|---|---|
| **W8 accessibility (AccessKit, `a11y` feature), Windows UIA minimum** | **L** at Purge's scope (XL in the roadmap for all three systems) | Blocker. See §6 |
| **W1 window host**, or at least a reusable single-window loop | L-XL shared / M if Purge writes its own | Not a blocker: Purge can write its own loop as mdview and mdedit did |
| Selector bar with N options (tabs as segments with more than 3) | S | extend `segments` with a new function |
| InfoBar: severity, stack, close, action buttons | S | extend `notice` |
| Expander (header + chevron + animated body) | S | |
| Standalone dropdown (ComboBox) and toggle switch outside `settings::Form` | S | `settings` already draws both, so expose them |
| Hyperlink button | S | |
| Anchored flyout card (content, not menu rows) | S | placement from `Menu::around` |
| Read-only selectable text (copy a command, a registry key) | M | Purge can fall back to a "Copy" button until then |
| HC with the system's colours; Mica off in HC | S | extend `tokens`/`platform` |
| X8 caret blink | S | open roadmap item |
| Merge `feat/anim` to `main` (Purge needs `focus`, `select`, `table`, `sections`, `viewport`, `slider`, `tokens`) | n/a | Purge can pin a `feat/anim` rev meanwhile (the roadmap allows it: "provisional until a second application uses it") |

### Belongs in Purge
App-specific views and plumbing.

| Piece | Size | Note |
|---|---|---|
| Rust engine client: spawn `purge-engine --stdio` suspended in a KILL_ON_JOB_CLOSE job with two inherited pipes; reader thread; id correlation; notification fan-out to the loop's wake | M | port of `Stdio/EngineProcess.cs` + `StdioEngineClient.cs` (512 lines); **reuses `purge-rpc`** (`frame.rs` `FrameReader`/`FrameWriter`/`parse_server_line`, `methods.rs` types) |
| Broker client: `ShellExecuteExW("runas")` on demand, random pipe name, `SECURITY_IDENTIFICATION`, server check, NDJSON | M | port of `Broker/*.cs`; much of the Win32 probably already exists in `purge-win` or the broker (to check) |
| Sample/stub engine (`FakeEngineClient`, `--sample`, `--bench-stub`) | S | the 87 `crates/purge-rpc/fixtures/*.json` can be the sample data |
| View models: `UninstallPipeline.cs`, `LeftoversModel.cs` (1,301), `HistoryModel.cs` (629), `VaultModel.cs` (665), `ProgramRow.cs` / `LeftoversRow.cs` / `VaultRows.cs` | L | plain logic, ports well to Rust models in the toolkit's style; tests move from xunit (219 facts) to `cargo test` |
| Icon atlas cache (`%LOCALAPPDATA%\Purge\icons.atlas`) | S | |
| Window loop (if W1 is not done first) | M-L | |
| Shell + rail + page host | S-M | |
| S1 Programs view | L | biggest page: list, tabs, search, filter, sort, details pane, removed-outside group |
| S2 Uninstall pipeline view + confirm dialog | M | |
| S3 Leftovers view | L | |
| S4 History view | M | |
| Vault view | M | |
| S5 Settings + settings file | S | |
| First-elevation dialog, cancelled bar | S | |
| Accessibility tree content: names, AutomationIds matching today's x:Names | M | once W8 exists |
| Launch markers, `--theme`, `--page`, `--bench-*` switches | S | |
| App manifest: asInvoker, PerMonitorV2, comctl32 v6, icon, VERSIONINFO (`bins/versioninfo.rs` exists) | S | |

Rough total for Purge's side: about 12-18k lines of Rust, replacing 17.5k lines of C#/XAML plus 2,235 lines of
hand-written DTOs, 49 JSON schemas and the `gen-dto` glue.

---

## 4. Risks

**Launch time (confirmation, not a blocker).**
- **Expected first frame:** the toolkit's path is Win32 + winit + softbuffer + CPU raster, with no GPU device, no
  XAML and no .NET runtime. Purge's own ENGINE_PLAN §9.1 bench measured a bare Win32 window at 27 ms against 280 ms
  for slim AOT WinUI, and said about 175 ms of the WinUI floor is GPU device creation. mdview, built on the same
  crates, reports 63-98 ms to first frame on Windows (its README "Numbers").
- **Purge today on the laptop:**
  - first Rendering tick p50: 386 ms
  - names visible: 444 ms (stub engine) and 461 ms (real engine), against a 400 ms gate
  - Files: `bench/launch/2026-11-23-*`; DECISIONS 2026-11-23 marks these as "not judged on the laptop".
- **My expectation:** about 80-150 ms to names visible. Since the engine is started before the window, names visible
  is likely bounded by `programs.list`, not by the UI. I did not measure this (no build, tight disk).
- **What to measure:** re-use `tools/xtask/src/bench_launch.rs`. It only reads the `marker=ms` line, so a Rust UI
  writing the same markers plugs straight in.
- **The gate needs redefining:** "≤ bare control + 60 ms" compares against `ui/bench/BareWinUI`. For a Rust UI the
  bare control should be a bare winit+softbuffer window. Keep the absolute guards (360/420 ms, names 400/460 ms) as
  they are.
- **Cost per frame:** a software painter redraws on the CPU. A full 1360×860 frame at 150% scale is 2.6 Mpx. mdview
  uses damage rectangles and redraws only on events. Fast scrolling of a 2,000-row list at 4K is the case to watch;
  `bench --s3-open` gives a number.

**Accessibility (the real risk).**
- **Today:** Purge has screen-reader names and fixes in 0.1.9, a designed keyboard and Narrator pass (M3-UI-A11Y),
  and UIA-driven e2e tests. The toolkit has none of this.
- **AccessKit:** gives UIA providers on Windows. The roadmap already picked it, but it is a new dependency
  (`accesskit`, `accesskit_winit`) and the roadmap rates W8 XL / high risk.
- **To verify in a spike:**
  - that AccessKit maps a node's `author_id` to UIA AutomationId (I believe it does)
  - which UIA patterns it exposes. Invoke, Toggle, Selection/SelectionItem, ExpandCollapse, RangeValue and Value
    are in AccessKit as far as I know, but ScrollPattern and ScrollItemPattern on a virtualized list are the
    uncertain part, and `m3-e2e-ui.ps1` uses them on `ProgramList`.
- **Virtualized lists:** they need care. Expose realized rows plus a list node with the row count and scroll
  actions; AccessKit has no built-in virtualization contract.
- **Keyboard and HC:** Tab order comes from `focus`. The system HC colours are missing.
- **Trade-off:** this is the main thing the old "WinUI / native" rule protected. It is recovered only once W8 is done.

**Native feel.**
- **What changes:** the look is the toolkit's own, not Fluent controls. No system context-menu styling, no Fluent
  reveal or focus visuals, and text rendering is parley/swash with subpixel masks, not DirectWrite.
- **What stays:** Mica/Acrylic, rounded corners, shadow and snap layouts.
- **What gets dropped:** Fluent/WinUI parity, which the user has accepted. The look of each new widget has to be
  approved by the owner ("not seen by a person" until then).

**Binary size (win).**
- **Today:** the WinUI publish is 62.6 MB slim (ENGINE_PLAN §9.1). `target/ui-publish` is 130 MB with about 61 MB
  of pdb; `Purge.exe` is 12.8 MB and `Microsoft.ui.xaml.dll` 15.2 MB.
- **Rust UI estimate:** 3-6 MB. mdview is 7.5 MB with a full Markdown/Mermaid/syntect renderer; Purge would not link
  `mdshared-highlight` or `mdshared-fetch`. Not measured.
- **Installer and toolchain:** the installer shrinks a lot, and the .NET SDK and VS C++ workload drop out of the
  build.

**Porting Purge.Client (win).**
- **Types:** `crates/purge-rpc` (5,273 lines) already has every params, result and notification type as `pub` with
  `Serialize + Deserialize + JsonSchema` (80 derive lines in `methods.rs`). It also has the method and notice tables
  (`table.rs`) and client-side framing (`frame.rs`: `parse_server_line`, `ServerMessage`). `purge-mcp` already
  depends on it.
- **What goes away:** a Rust UI uses the same types the engine and broker serialize, so the C# DTO drift risk is
  gone, along with `RpcModels.cs` (2,235 lines), `cargo xtask gen-dto` and the C# fixture round trip. The schemas
  may still serve `purge-mcp` or docs.
- **What is missing:** a Rust client (process launch, pipe, id correlation). That is about M of work.

**Security model (unchanged if done right).**
- **Integrity levels:** the UI stays medium integrity (`asInvoker` manifest). The broker still starts on demand
  through `runas` and still shows its own TaskDialogs (`bins/purge-broker/src/consent/*`,
  `crates/purge-win/src/taskdialog.rs`). UIPI still protects them (`vm/guest/m3-uipi-probe.ps1`). Nothing in the
  toolkit needs elevation.
- **Image check:** the broker accepts only a client whose image is `<install dir>\Purge.exe`
  (`bins/purge-broker/src/link.rs` l.60/82, `start.rs` l.320). The Rust UI binary must be named `Purge.exe` and
  installed there. Do not add a second allowed name to make side-by-side easier; that would weaken a security check.
- **Do not adopt:** `mdshared_app::single` (a loopback TCP listener any local process can connect to) and
  `mdshared_app::updater` (unsigned in-place exe swap). If `notify` is ever used, it writes
  `HKCU\Software\Classes\AppUserModelId\<id>`, which Purge's own uninstaller and KB must then clean up.
- **Review:** this is critical work under the Fable review rule.

**Other risks.**
- `feat/anim` has never been through CI, and main's Linux/macOS tests are red. Purge is Windows-only, and main's
  Windows CI job is green.
- The toolkit forbids changing existing APIs, so Purge must pin a rev.
- Shared work competes with the music player / file manager / terminal order in the roadmap; the owner decides.

---

## 5. Suggested migration order

1. **Spikes, before anything else (about 1-2 days):**
   - **Launch:** a winit+softbuffer window using `mdshared-ui` (pinned to a `feat/anim` rev) that starts the real
     `purge-engine --stdio`, draws the `programs.list` names in a `rows` list, and writes `first_tick` /
     `names_visible` markers. Run `cargo xtask bench-launch` against it. This confirms the launch numbers.
   - **Accessibility:** the same window with AccessKit, a button and a 2,000-row list. Point
     `m3-e2e-ui.ps1`-style UIA code at it (on the host, no VM): find by AutomationId, Invoke, SelectionItem,
     ScrollItem, and check Narrator reads names. This decides whether W8 is feasible at Purge's scope.
2. **Toolkit fast-track:** W8 minimum (Windows UIA only), then the small generic pieces from §3 (selector bar,
   InfoBar, Expander, dropdown/toggle, hyperlink, flyout card, HC colours). Claim each in ROADMAP.md, and merge
   `feat/anim` to `main` when the owner agrees. W1 is optional; Purge can own its loop.
3. **Purge plumbing:**
   - a new bin, e.g. `bins/purge-ui` (exe name `Purge.exe`)
   - a Rust engine client on `purge-rpc`
   - a stub engine from fixtures
   - view models ported from `Pipeline/`, `LeftoversModel`, `HistoryModel`, `VaultModel`, with their xunit tests
     moved to `cargo test`. This step is testable headless, as the toolkit's tests are.
4. **Read-only pages first:**
   - shell and rail
   - S1 Programs (list, tabs, search, icons, details)
   - S5 Settings
   - History list
   
   These need only the stdio engine, so the Rust UI can run next to the installed WinUI build on the host without
   the broker.
5. **Broker pages:** S2 Uninstall, S3 Leftovers, Vault, and History restore/undo.
   - **Constraint:** these need the binary installed as `<install dir>\Purge.exe`, so they are tested in the VM with
     an installer that carries the Rust UI instead of WinUI, one or the other, never both.
   - **Shipping:** WinUI stays the shipping UI until the Rust UI passes the e2e and launch gates. The switch is one
     release (installer change) that then deletes `ui/`.
6. **Accessibility pass:**
   - author ids equal to today's x:Names (see below)
   - names on every control
   - keyboard path
   - HC (Mica off)
   - the 760×520 minimum and the < 720 px narrow layout
   
   This is the M3-UI-A11Y package, redone in Rust.

**Effect on tests and the rig.**
- **`ui/Purge.Client.Tests` (7,155 lines, 219 tests):** these test view models and clients, not XAML. They port to
  Rust tests (the fixture round trip becomes unnecessary). Until the switch they keep testing the WinUI side.
- **`vm/guest/m3-e2e-ui.ps1`, `m3-clean.ps1`, `m3sec.cs`:** they find elements by AutomationId, which today comes
  from x:Name:
  - `ProgramList`, `UninstallButton`, `DUninstallButton`, `NavQueue`, `NavLeftovers`, `MoveButton`, `MoveText`,
    `FooterCount`
  - `WaitingTitleText`, `WaitingCodeText`, `ResultTitleText`, `ResultDetailText`, `UndoAllButton`, `UndoTitleText`,
    `UndoDetailText`, `EmptyTitle`, `InfoBarHost`
  
  If the Rust UI's AccessKit nodes carry the same ids, most of the scripts keep working. These parts will need
  edits:
  - the ContentDialog lookups ("PrimaryButton" template part + Name "Uninstall"/"Continue"); give the dialog buttons
    ids
  - the ScrollPattern / ScrollItemPattern use on `ProgramList`
  - any text matching that relies on WinUI's tree shape
- **`m3-uipi-probe.ps1`:** targets the broker's TaskDialog, so it is unaffected.
- **Launch bench:** `bench_launch.rs` works unchanged once the markers are written; replace `BareWinUI` with a bare
  winit+softbuffer control and update the G2 gate definition in DECISIONS and ENGINE_PLAN §1.3. The DECISIONS rows to
  reverse or update: ENGINE_PLAN §1.1/§1.2 ("WinUI 3, Fluent, Mica", "No egui. No Rust WinUI…"), §9.1 "Rejected",
  and the 2026-11-21 stopgap-tree row.

---

## 6. Roadmap items Purge would use, ranked by how much they unblock the port

Ids are from `docs/ROADMAP.md` on `feat/anim`.

| Rank | Item | Verdict | What Purge needs (minimum scope) |
|---|---|---|---|
| 1 | **W8 Accessibility** (open, XL) | **Fast-track for Purge**; blocks shipping and the e2e rig | Windows UIA only (AT-SPI/macOS later), behind `a11y`. Roles: window, button, check box, list + list item (virtualized: realized rows + count), text, dialog, progress bar, expander, combo/menu items. Properties: name, help text, **author_id = AutomationId**, toggled/selected/expanded state, range value. Actions: invoke/click, toggle, select, scroll-into-view, focus. Fed from the same models (`focus` ids). Verify ScrollItem/Scroll on lists early |
| 2 | **W1 Window host** (open, XL) | Fast-track only partly; Purge can write its own loop meanwhile | One undecorated window: min size, scale change, damage present, one `WaitUntil` for anim + caret + tooltip + engine wakes (EventLoopProxy), hidden first frame, frost key-out, AccessKit adapter hook. No tabs, no multi-window |
| 3 | **W2 Focus** (done on feat/anim) | Fast-track: needs merging to `main` | as built; plus arrow/Enter/Escape conventions per widget (in Purge) |
| 4 | **L2 Sections** (done on feat/anim) | Fast-track: merge | Leftovers' grouped list with collapsible groups; S1's "Removed outside Purge" group |
| 5 | **W5 Tokens / high contrast** (done, provisional) | Fast-track an extension | add the Windows HC scheme's system colours (GetSysColor) as a token set, and a rule that `frost`/Mica is off in HC |
| 6 | **X8 Caret blink** (open, S) | Fast-track (small) | blink in the S1 search field and any dialog field |
| 7 | **L3 Viewport / horizontal scroll** (done) | Used as is | History's horizontal strip |
| 8 | **W4 Cursors** (done) | Used as is | column resize, links |
| 9 | **X4 Toast stack** (open) | Not needed for Purge | Purge uses in-page InfoBars, which are a `notice` extension (not on the roadmap; add a row) |
| 10 | **L10 Settings form with motion** (open) | Not needed | Purge's settings fit today's `settings::Form` |
| 11 | **W3 Window state** (done) | Not needed now | optional if Purge wants to remember placement |
| 12 | **W9 Translations** (open) | Not needed (Purge is English only) | later |
| 13 | **L4 Table hidden/reordered columns** | Not needed | |
| 14 | **L1 Submenus** (done) | Not needed | menus are flat |
| 15 | **W6 Tray, W7 Notify** (done) | Not needed | Purge has neither; avoid `notify`'s HKCU AUMID unless asked |
| 16 | **F5 Shell icons** | Not needed | the engine extracts icons already |
| 17 | **L5-L9, F1-F4, F6-F7, M\*, T\*, X1-X3, X5-X7, X9-X10** | Not needed | file manager, media and terminal items |

**Not on the roadmap but needed (propose new rows):**
- a selector bar with N options
- InfoBar (severity, stack, close, actions)
- Expander
- standalone dropdown and toggle switch
- hyperlink button
- anchored flyout card
- read-only selectable text (M)

All are S except the last.
