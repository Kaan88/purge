# M3-CONSENT: writer notes

Package: `bins/purge-broker/src/consent/{view,text,dialog}.rs` (+ `tests.rs`), the `Consent::ask` / `Ctx::consent`
change in `serve.rs` (`consent.shown`), and in `purge-win` `taskdialog.rs` the cursor's monitor, a fix to
the arming/verification order and `taskdialog::check`. Branch `m3-consent`, cut from `baseline` 2ec05f2.
No `purge-rpc` type changed (no gen-dto). `ui/Purge.App/Shell/ConsentPrompt.cs` is **not** deleted: `ReviewView` and
`VaultView` still call it, and the UI packages are changing those files in parallel; delete it with the last UI
package that stops using it.

## Shape

| Piece | What |
|---|---|
| `view::view(&BoundPlan, &Facts)` | quarantine dialog of `plan.execute` |
| `view::view_restore(&BoundPlan, &RestoreFacts)` | `undo.run`: ops to put back, conflicts as attention |
| `view::view_recover(&BoundPlan, &RecoverFacts)` | `journal.resume`, `.rollback`, `.retry_held` |
| `view::view_purge(&[PurgeUnit])`, `view_purge_user_data(unit)`, `split_purge(items, backups)` | `quarantine.purge`; user data one unit per dialog |
| `view::view_uninstall(&UninstallFacts)` | `uninstall.run` (R2 M1): program name, the frozen command's program file and arguments, signer, quiet or interactive, the restore-point choice; `ConsentView::describes_uninstall(&QuietCommand, quiet)` is the handler's check |
| `ConsentView` | strings only (instruction, summary, attention entries, other entries, box, button, footer), counts, code |
| `dialog::pages(&ConsentView) -> Vec<Page>`, `dialog::ask(ctx, &view) -> Outcome` | TaskDialog pages; asks through `Ctx::consent`, which sends `consent.shown {request, code}` once the window is up |
| `text::{shown, quote}` | the only way a name or path reaches the dialog |

All functions are pure and return `Result<_, ViewError>`; a handler that gets `Err` declines without a dialog.
`ConsentView::describes_plan(&BoundPlan)` is for the handler: call it right before running the plan that was asked
about (B3).

## Choices (DECISIONS candidates)

1. **Drawn from the op, not the scan.** Each line takes verb and target from `BoundItem::exec_op` (`ExecOp::target()`).
   The button, the counts and the groups count items that will act. An item with no op (service, task or firewall rule
   without a scan digest) is listed as "Leave alone". A removal without an undo (package) when the plan does
   not carry `allow_irreversible` is also "Leave alone": `execute.rs` `package_item` decides it as not done.
2. **Attention rules** beyond the design's three (user data, ticked and not chosen, over 1 GB; "chosen" = Safe band and
   preselected): *no undo* (the dialog changes to "Remove N leftovers of X? K cannot be put back.", warning icon,
   "restore the rest"), *an absorbed item inside it needs attention* (those items are listed as entries of their own,
   they go with the parent), and *the name needed escapes or a cut* (below). Restore: conflicts only. Recover:
   user data and no-undo. Large is 1 GiB, strictly over.
3. **Codes.** Quarantine and recover: `ConfirmCode::of(confirm_hash(plan_hash, selection_hash))`, the one `plan.create`
   gave the UI. Restore: the same recipe over the ids of the ops shown. Purge: `selection_hash` over the expiry ids.
4. **Paging.** 40 attention entries per page, and a page also closes at 12,000 characters (never drops an entry). The
   summary is on page 1, the box, the other items (first 100, and 12,000 characters) and the button only on the last
   page. Every page has the footer with the code and, but the last, "Use Next to continue".
5. **Purge** names every item (quarantine path and the original) and every backup file as its own entry; all are
   attention entries (no undo), the box is always there. A backup unit without files is refused.
6. **Cursor's monitor** (taskdialog): `GetCursorPos`, nearest monitor's work area, window centred on it at
   `TDN_CREATED` and again after each page (a page resizes the window); a window larger than the area keeps its top left.
7. **Arming vs. box** (taskdialog): ticking the box inside the first second no longer enables the primary button; the
   first `TDN_TIMER` past the delay enables it if the box is ticked by then.
8. **Trait change.** `Consent::ask(pages, primary, closer, shown)`; `Ctx::consent(pages, primary, code)`.
   `TaskDialogConsent` calls `shown` after `wait_created`; `ScriptedConsent` calls it only after `announce_shown()`
   (otherwise tests that read "the next line" would meet the notification).

## Anti-misleading measures (design T12, T15)

- Everything from a scan, a program or a journal goes through `text::shown`: control characters, bidi controls,
  zero-width and other invisible characters, line/paragraph separators, non-plain spaces, private-use, non-characters and
  `"` are written `\u{hex}`; NUL too (the dialog layer refuses NUL).
- Leading, trailing and repeated plain spaces of a path component are written `\u{20}` (`Program Files` vs
  `Program Files ` vs `Program  Files`).
- In a word with an ASCII letter or digit, letters of Cyrillic, Greek, Armenian, Cherokee, Coptic, full-width forms,
  mathematical letters, IPA and letter-like symbols are written `\u{...}` (`Mozill\u{430}`); a whole word in one such
  script stays readable. (Dotless i is left alone on purpose: `KullanÄ±cÄ±` is a normal Turkish profile folder.)
- Every name or path is in double quotes and cannot contain a double quote: it cannot run on into the band, size or
  reason text around it.
- A component over 80 characters keeps 56 + 24 around `[N characters not shown]`; a whole text over 400 shown
  characters keeps both ends; an escape counts as one character of the name; the text of one name is bounded even when
  every character is an escape.
- An item whose name was escaped or cut is an attention item, so it is listed in full, never folded into "and N more",
  and brings the verification box. A legend line explains `\u{...}` and the cut.
- The app name in the instruction goes the same way.
- The 5,000-item test: 50 attention items among 5,000, all 50 listed, the others 100 plus "and 4,850 more of the same
  kinds: ...".

## Tests

`consent::tests` (view and pages, 23), `consent::text::tests` (escapes, spaces, look-alikes, cuts, bounds, sizes),
`serve::tests::consent_shown_is_sent_when_the_dialog_is_up`, `taskdialog::tests::centring_on_a_work_area`.
`xtask ui-strings` scans `bins/**/*.rs`, so the dialog literals are covered; it was skipped here (`PURGE_UT_STRINGS`
not set on this host): run it where the reference file is. Test plans of 5,000 use registry values: `plan_in::bind` is
quadratic in the number of selected items (`check_order`, `check_protected_descendants`); 5,000 files take 97 s in
a debug build (see open points).

## Needs the VM (UAC on, manifested `purge-broker.exe`)

- The four variants rendered by the real TaskDialog, with screenshots; text wrapping, window height with 40 entries and
  with the expanded list of 100 on a 768 px screen, the `âš ` mark in the dialog font.
- Real paging: Next/Back with `TDM_NAVIGATE_PAGE`, the button and box only on the last page, gate, Esc and close box.
- The arming delay (a click in the first second does nothing; box ticked early enables the button after the delay).
- The dialog on the monitor of the cursor (two monitors, negative origin), re-centred after each page, on the secure
  desktop session of the elevated broker; foreground and taskbar flash.
- `consent.shown` arriving at the UI before the dialog can be answered; the code in the footer equal to the UI's.
- A string over the dialog's practical limit (hostile names, 12,000-character pages) shows or fails safe (`Err` = Cancel).
- T1: the `m3-consent` rig mode against the real pages.

## Open points

- `plan.create`'s `attention` list (rpc `AttentionReason`: user data, not preselected, large) has no "no undo", "inside"
  or "name" reason: the dialog shows more than the review page. BROKER-FLOW may want to compute the review's attention
  list from the same function (`consent::view::view(...).attention`) so the UI and the dialog never differ.
- `plan_in::bind` is O(n^2) in the selected items (see above); a 5,000-item plan in a release build is a BROKER-FLOW
  question (T15 test).
- Soft blockers (`BaselineInferred` and the like) are not attention reasons.
- Restore facts (`RestoreFacts::conflicts`) and recover facts (`RecoverFacts::ops`, `done`, `total`) are the caller's
  to compute from the journal; the view trusts only that the ops are in the plan.
- Time and date come in as `Stamp` (the caller converts); the purge listing's `expires` is not shown.
- 80-character cuts flag some real names (long AppX full names); they become attention entries.

## R2 M1: the uninstall dialog

`uninstall.run` no longer starts anything before the broker's own dialog is approved (design B4, T2, T11).

- **Drawn from the frozen command.** `uninstall::run` picks the session's `QuietCommand` (interactive or quiet),
  builds `UninstallFacts` from it and calls `view_uninstall`. The view keeps that `QuietCommand` and the mode
  (`UninstallDrawn`); `describes_uninstall` is checked before the dialog and again after the answer, against the very
  value passed to `Machine::run_uninstall`. A mismatch is `runtime`, nothing starts.
- **What it says.** Instruction `Run the uninstaller of "<name>" as administrator?`; lines `Starts: "<program file>"`,
  `Arguments: "<arguments>"` (or `none`), `Signed by: "<signer>"` (or `no signer known`; read from the program file
  by the broker's own sources), `Mode: quiet|interactive`, the restore-point choice for the leftover cleanup that
  follows (a new optional `restore_point` of `RunParams`, shown only: the run makes no restore point and
  `plan.execute` has its own dialog), and "Purge cannot undo what it does. Nothing has been started yet."
  Warning icon, one button "Run the uninstaller", Cancel the default, armed after 1 s by the TaskDialog layer.
- **Names.** Program, program file, arguments and signer go through `text::shown` / `text::quote` (the arguments and
  the signer through the new `text::shown_line`, which does not read `/` and `\` as component ends or cut at 80
  characters, only at the 400 of a whole text). Anything escaped or cut becomes an attention entry and brings the
  verification box; plain commands need only the button.
- **Code.** `ConfirmCode` of `selection_hash` over `uninstall \n program id \n quiet \n exe \n args`; `consent.shown`
  is sent as for every variant (`Ctx::consent`).
- **Declined, lost.** Cancel, a dialog that cannot be built or shown, a lost pipe or parent (the closer closes the
  window as Cancel) and a loss noticed just after an approval are `consent_declined` or nothing at all: no process
  starts and the session stays usable (a declined request can be asked again).
- **UI.** `BrokerUninstallClient.RunAsync` takes the restore point, lets the broker's window come to the front
  (`AllowForeground`) and forwards `consent.shown`; `UninstallController` shows "Waiting for the Purge security
  prompt. Nothing has run yet." and then the code, and maps `consent_declined` to an info bar with Retry. The UI's own
  confirm dialog stays (quiet toggle, restore point).
- **Needs the VM:** the dialog drawn by the real TaskDialog with a real Inno/MSI uninstaller (wrapping of a long
  command, the escape legend, window to the front over the UI), the 1 s arming, and the code in the footer equal to
  the one the UI shows while it waits.
