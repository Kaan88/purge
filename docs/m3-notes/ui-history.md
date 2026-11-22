# M3-UI-HISTORY: History & undo page on real data

Branch `r3-history`, cut from `baseline` cbb7a8b. No Rust and no `purge-rpc` type changed (no gen-dto): every
method the page calls already existed. Broker consent path, purge-exec and undo semantics are untouched.

## Shape

| File | What |
|---|---|
| `ui/Purge.App/Views/HistoryModel.cs` | `HistoryViewModel` (no WinUI types, linked into the tests like `LeftoversModel.cs`): `LoadAsync` (`history.index`), `ShowItemsAsync` (`history.get`), `RestoreAsync` (`undo.run`, all or the ticked ops), `RecoverAsync` (`journal.resume` / `journal.rollback`). `HistorySessionModel` (time, app, count, size, days left, state chip), `HistoryEntryModel` (kind, outcome, the S5 alert line). |
| `ui/Purge.App/Views/HistoryView.xaml(.cs)` | The S4 page drawn from the view model: loading, empty and error states; board 13 timeline and the list (newest first, day headers); detail pane with "Show items", per-item alert mark, Restore selected / Restore all, recovery banner with Resume and Roll back. The sample rows, `Select(programName)` and the no-op "Export log (JSON)" and "Open System Restore" buttons are gone (no export in M3). |
| `ui/Purge.Client/Broker/HistoryBroker.cs` | `IHistoryBroker` + `HistoryBroker` over a launched `BrokerSession` (owns it; dispose ends the broker). `undo.progress` feeds the waiting bar. |
| `ui/Purge.Client/Rpc/ReconcileAlert.cs` | The one sentence for an `Alert`, now shared by Leftovers ("Put back" result) and History. |
| `IEngineClient` + `StdioEngineClient` | `GetHistoryIndexAsync` = `history.index` on the medium engine. `FakeEngineClient` answers an empty index (sample mode shows the empty state); the test `CliEngineClient` reads `sessions\index.json`. |

## Choices (DECISIONS candidates)

1. **Who serves what.** The list is `history.index` (table: `Read, Stdio`), so opening History never starts the broker
   or a UAC prompt. `history.get`, `undo.run` and `journal.*` are `Pipe` methods: "Show items", Restore, Resume and
   Roll back start the broker on the click (first-elevation explanation, then `BrokerLauncher`), as design 6.3 says.
   The page keeps the broker it started and launches a new one when the link has ended.
2. **Where the S5 alert shows.** `SessionSummary` carries no alert, so the mark appears per item once "Show items" has
   read `history.get` (`HistoryItem.alert`), with the Leftovers sentence; the session row then gets a "Check items"
   chip, kept across re-reads of the index. `UndoResult.alerts[]` and `OutcomeResult.alerts[]` are lines of the
   restore / recovery result bar.
3. **States.** "No cleanups yet." / "Couldn't read the history." (with the engine's message and "Try again").
   Chips: Undoable, Partly restored, Interrupted (caution), Restored, Rolled back, Nothing to restore (neutral).
   Restore is enabled only for a Committed or PartiallyUndone session that still holds bytes.
4. **After a change** (restore, recovery, or a broker that died mid-run) the index is read again, and the items too
   when they were shown.

## Tests

`ui/Purge.Client.Tests/HistoryPageTests.cs`: `LoadsEntriesNewestFirstWithoutStartingTheBroker`,
`AnEmptyIndexShowsTheEmptyState`, `AnIndexThatCannotBeReadShowsTheError`,
`ShowItemsStartsTheBrokerAndMarksTheReconcileAlert`, `AnItemWithoutAnAlertHasNoMark`,
`RestoreShowsTheUndoAlertsAndReadsTheListAgain`, `RestoreAllSendsNoItemIdsAndADeclinedPromptPutsNothingBack`,
`ACancelledAdminPromptStartsNothing`, `ABrokerThatDiesIsStartedAgainOnTheNextClick`,
`AnInterruptedSessionOffersRecoveryAndShowsItsAlerts`, `TheMediumEngineAnswersHistoryIndex` (stdio wire, fixture).

## Still needs the VM

- The page on a real store: sessions from Leftovers cleanups, "Show items" through a real UAC prompt, Restore and
  Restore selected through the broker's TaskDialog, a real reconcile alert (boot-time move with a foreign object).
- Resume / Roll back on a session interrupted by killing the broker mid-run.

## Open points

- **Two brokers.** The Leftovers page owns the broker S2 handed it; History launches its own. Whether a second broker
  can run while the first holds the store (store lock, `busy`) is not checked here; one shared broker per app would
  be the cleaner design.
- Interrupted sessions are those `Open` in the index; `journal.pending` (broker) is not asked, so an `Unindexed`
  session is not offered recovery from this page.
- The Quarantine vault page still uses `GetQuarantineAsync` / `UndoSessionAsync`, which the stdio client refuses; it
  could move onto `history.index` and `HistoryBroker` the same way.
