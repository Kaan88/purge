# M3-BROKER-FLOW: writer notes

Package: `bins/purge-broker/src/{uninstall,scan,plan}.rs` (and `flow_tests.rs`), branch
`m3-broker-flow`, cut from `baseline` 3d183bd and merged with `baseline` 8be6293 (M3-CONSENT,
M3-UI-S1). The binary now wires `uninstall::Flow` over `LiveMachine` instead of `serve::Unwired`;
every other method still answers `runtime`.

## Shape

| File | What |
|---|---|
| `uninstall.rs` | `Machine` (sources, the one scripted/live uninstaller, verify-gone, the fingerprint store, the quarantine/cap check), `LiveMachine`, `Session`, `Flow`/`FlowHandler`, `uninstall.prepare`, `.run`, `.observed`, `leftovers.stored` |
| `scan.rs` | `Scan` (scan document, mode, counts, warnings, trust, one live plan), `leftovers.scan`, `scan.candidates`, `candidate.explain`, `check_unique` |
| `plan.rs` | `plan.create`: the `ExecRequest` from the broker's scan and ids, confirm hash, `plan_in::bind`, the consent view's attention list, the frozen `Arc<BoundPlan>` |
| `flow_tests.rs` | the fixture machine, the recording handler, every refusal |

`Machine` is the seam for tests: the broker's own sources, the uninstaller (live: `pipeline::
uninstall_with_command` with the exact `QuietCommand`; tests: a scripted report), verify-gone, the
fingerprint under `<data root>\fp` (name = SHA-256 of the program id), and `unstorable` (the volume
checks and the cap). Nothing above it turns a client value into a path.

## Choices

1. **The command is frozen at `prepare`.** `uninstall.run` picks the interactive or quiet
   `QuietCommand` out of the session and passes it verbatim. It never resolves the Uninstall key
   again, so a key changed between the two requests cannot change what runs.
2. **Route is the broker's.** `prepare` computes `pipeline::route` (both routes are harvested);
   `run` refuses anything but `Route::Broker` with `wrong_route`. The medium engine never sees a
   broker route and the broker never runs a medium one.
3. **Modes.** A session scan is `post` only when the broker's uninstaller reported success **and**
   the broker's verify-gone passed; a failed, skipped or unverified uninstall is `forced`. The
   client may pass `forced`; there is no way to raise a mode. A stored fingerprint is scanned
   `external` (verify-gone re-checked; a still-installed program is never Safe).
4. **Candidate ids.** `leftovers.scan` refuses (never serves) a document in which an id is not
   `c-<16 hex>` or names two candidates (M3-R1 M2); `plan.create` checks again and only accepts
   top-level ids of *that* scan (an absorbed id is refused, not resolved to its parent).
5. **One live plan per scan.** `Scan::claim` is an atomic compare-exchange: a second `plan.create`
   of the same scan is refused until the plan is taken. `plan.execute` takes the plan (the id then
   works once) and calls `Plan::release` so a declined dialog can be followed by a new plan from the
   same scan. M3-EXEC must make that call.
6. **The view model is the sole attention list.** `plan.create` builds `consent::view::view` from the
   bound plan, calls `describes_plan`, and maps its attention entries to the RPC rows. The RPC
   `AttentionReason` gained `no_undo`, `inside` and `name` so the review page and the dialog say the
   same thing.
7. **Cap and quarantine checks at `plan.create`.** For selected path items: a volume that is not a
   fixed NTFS/ReFS drive root is a refusal with the item's id; planned bytes over the volume's cap are
   `cap_exceeded` with the numbers. The executor still checks both.
8. **Fingerprints.** Written atomically (temp + rename) under `<data root>\fp`, the name a SHA-256 of
   the program id; reading verifies the stored document names the same program. `prepare` fails if
   the store cannot be written; after a run or observation the update is best effort (the session in
   memory is what this broker scans with). Since 2026-11-22 ("fp checked" in DECISIONS) `fp` and
   `fp\msitables` are checked store directories and every read, write, rename and sweep in them goes
   through purge-exec's `FpDir`, relative to the checked handle, never by path; the broker's MSI table
   cache is `msitables::StoreTableCaches` over the same store.

## Tests to the review points

| Attack | Test |
|---|---|
| broker runs a medium-route program | `run_refuses_a_medium_route_session` |
| plan from another scan / another broker | `plan_create_refuses_ids_that_are_not_of_this_scan`, `ids_of_another_broker_are_gone` |
| plan created twice | `a_plan_cannot_be_created_twice_from_one_scan` |
| path/document from the client | `plan_create_takes_ids_only` (unknown member: `-32602`); the params types of `purge-rpc` |
| command shown = command run | `run_runs_the_command_prepare_showed` |
| consent shows = runs | `plan_create_holds_the_frozen_plan_the_response_describes` (stored hash, selection hash, code, attention = the view's) |
| forced after a failed verify / failed uninstaller | `a_failed_uninstaller_offers_a_forced_scan_with_nothing_preselected`, `a_failed_uninstaller_is_forced_even_when_the_program_is_gone` |
| forced never raised, lowering works | `a_successful_run_scans_post_and_forced_lowers_it` |
| M2 unique ids | `a_scan_with_a_shared_or_malformed_candidate_id_is_refused` |
| broker scan = CLI scan | `the_broker_scan_equals_the_cli_scan` |
| scan during a build offered again | `a_scan_made_during_the_build_is_offered_again` |
| refusal list with reasons | `plan_create_refuses_ids_that_are_not_of_this_scan`, `plan_create_refuses_a_blocked_item`, `plan_create_refuses_an_item_the_executor_cannot_quarantine`, `plan_create_refuses_a_plan_over_the_cap` |

`pipeline::Scanned` gained `baseline_trust`, the value the policy consumed, so `leftovers.scan` reports
the truth instead of the fingerprint's harvest trust (which is `None` for an exact shipped baseline,
because an Exact view records nothing).

## `plan_in::bind` cost

`bind` was quadratic (`check_order`, and `check_protected_descendants` over the whole document for
every selected whole-tree item). `any_nesting` sorts the document by folded place with the separator
below every other character, which makes a parent adjacent to its subtree: when nothing nests (the
shape `collapse` produces, and the 5,000-value stress plan) both checks are skipped entirely; a
document that does nest takes the old exact path. `a_large_plan_without_nesting_binds` (5,000 values)
and `nesting_is_detected_exactly` cover it. A crafted document with thousands of nested *selected*
items still takes the old path; only the executor's own act-time checks matter then.

## Still needs the VM / elevation

- A real elevated broker (UAC) preparing and running an admin-only uninstaller, then scanning it;
  compare the plan hash with the rig CLI's plan for VS Code (the package acceptance).
- A medium-route program prepared by the broker and run by the medium engine, then
  `uninstall.observed` from the broker (the two-process flow; the tests use one process).
- The fingerprint directory on a real data root (`StorageRoots`, admin-only), including a full
  volume and a removable/mounted-folder volume (the cap and quarantine refusals).
- The consent dialog drawn from `plan.create`'s frozen plan, and `describes_plan` before execution
  (M3-EXEC); only the view-model equality is tested here.
- The local baseline build started by the broker and a scan made during it (the test uses
  `FakeBuild`).

## Open points

- `plan.create` freezes `allow_irreversible: false`: a package item is listed as "Leave alone" and
  the dialog cannot acknowledge it. M3-EXEC needs a way to set the acknowledgement before
  `execute_bound` (an RPC field or a method on the plan); until then packages in a broker plan are
  skipped.
- `uninstall.observed` had no outcome from the medium engine, so a medium run that failed but left
  the program gone was scanned `post` (the broker only saw verify-gone). **Resolved:** `ObservedParams`
  carries the outcome (M3-EXEC), and M3-GLUE records the uninstall window in `observed` from `prepare`'s
  harvest to the observation, so the medium route's `post` scan works without a broker `uninstall.run`.
  Since M3-R2 (65347f2): `observed` answers `wrong_route` for a broker-route session, never raises a
  session that already ran, records the window at the first passing observation only, and records none
  more than 2 hours after `prepare` (rules and tests in `exec.md`, "`uninstall.observed` outcome").
- `plan_in::bind` is called once per refused item at `plan.create` (one clone of the scan document
  each; review M3-R2 N3). Bounded by the pipe limit and the scan size; collecting every
  `NotSelectable` in one pass needs a `purge-exec` API change and is left for later.
- The soft blockers (`BaselineInferred`, `InUse`, `ChangedSinceScan`) are not attention reasons in
  the view either; this package reports exactly what the view reports.
