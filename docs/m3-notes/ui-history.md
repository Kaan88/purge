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

- **Two brokers.** The Leftovers page owns the broker S2 handed it; History and the Vault launch their own. Answered
  by R3 (branch `r3-single-writer`, DECISIONS 2026-11-22): the store has one writer at a time across brokers
  (`sessions\writer.lock` in purge-exec); a second writer is `busy`, which both pages show as "Another Purge window
  is changing the quarantine". One shared broker per app is still the cleaner design (one UAC prompt, no `busy`).
- Interrupted sessions: answered by R3 below.
- The Quarantine vault: answered by R3 below.

## R3 follow-ups (branch `r3-single-writer`)

1. **Threading.** No XAML binding reads the page models: the views post `Render`/`Refresh` through their
   `DispatcherQueue` on every `Changed` (as ProgramsView does), and the only `x:Bind` with change notification is on
   `LeftoversRow`, raised on the UI thread. The race was elsewhere: the models rewrote `Sessions` / `Items` on pool
   threads (after `ConfigureAwait(false)`) while a posted render enumerated them. The models now never leave the
   context that drives them (the UI thread), and `LeftoversViewModel` posts the broker's `consent.shown` and
   `baseline.changed` (reader thread) to the context it was made on. Tests: `UiThreadTests` (a single-thread
   synchronization context stands for the UI thread; the engine and broker answer on pool threads; every `Changed`
   must come on that thread; it fails with one `ConfigureAwait(false)` put back).
2. **Quarantine vault on real calls** (design 7a page table: `history.index`, `quarantine.expiring`,
   `quarantine.purge`). `ui/Purge.App/Views/VaultModel.cs` (`VaultViewModel`, `VaultBatchModel`, `VaultVolumeModel`,
   no WinUI types, linked into the tests): the cleanups that still hold something and the real use and cap per
   volume from `history.index` (no broker on page open); "Put back…" is `undo.run` for the whole session through the
   broker's dialog; "Review and delete expired…" is `quarantine.expiring`, then `quarantine.purge` with every expiry id
   (the broker's dialogs name every item, user data one per dialog); nothing expired is a note, not a dialog. No
   "Empty quarantine" and no export (design), no sample data. An interrupted session in the index shows a bar that
   opens History. `HistoryBroker` implements the new `IVaultBroker` too. `RecoveryBar` (CLI-only calls) is gone.
   Tests: `VaultPageTests` (10).
3. **Recovery of sessions the index does not show** (design 6.3: `journal.pending` is a broker `Read` method; the
   page never starts the broker on open). The index gets a run's entry only when the run ends, so `Open` in the
   index catches almost no interrupted run. History now asks `journal.pending` (a) on "Check for interrupted
   cleanups" (header button; starts the broker on the click) and (b) when a restore it started is refused with
   `needs_recovery` (the broker is up; no second prompt). A pending session the index lacks is listed from the
   journal ("N of M items done · found in the journals") with Resume and Roll back; one the index lists is marked
   Interrupted. A recovered session leaves the pending set. Tests: `OpeningThePageNeverAsksForInterruptedSessions`,
   `CheckForInterruptedListsASessionTheIndexDoesNotHaveAndOffersItsRecovery`,
   `CheckForInterruptedMarksAnIndexedSessionWhoseReportWasNeverWritten`,
   `CheckForInterruptedSaysSoWhenNothingWasInterrupted`,
   `ARestoreRefusedForRecoveryListsTheInterruptedSessionsWithoutAnotherPrompt`,
   `AnotherWriterOfTheStoreIsBusyNotAFailure`.

Still needs the VM: the Vault's "Put back…" and "Review and delete expired…" through a real UAC prompt and the
broker's dialogs; "Check for interrupted cleanups" on a session interrupted by killing the broker mid-run; two
brokers at once (Leftovers moving while History restores) answering `busy`.
