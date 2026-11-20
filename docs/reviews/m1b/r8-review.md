# R8 review: 7e885aa..f000afd (M1b executor-gate fix round), branch m1b

**Verdict: fix B1, then build the ambient set and replay the two failed execdiffs on the host before the G5/G6 rerun.
1 blocker, 7 should-fix, 5 minor.** The engine fix is correct for the gate's case and the hand rules are narrow; the
weak part is the null window, which does not reproduce everything a gate window holds.

Checked: the full diff; `cargo test -p purge-exec --lib write_back` (2 pass, 1 ignored, unelevated); `cargo test
--release` in `vm/rigtool` (118 + 16 pass); a host replay of `rigtool execdiff` (the build of 15:14, with the new
rules) over the stored snapshot pairs of the failed runs `vm/runs/m1b-x-fidelity` and `vm/runs/m1b-x-traps`, with
`truth/m2-ambient.json`, output to a scratch directory. Not run: anything elevated, `rig-selftest.ps1`,
`-Mode m1b-x-selftest`, anything in a VM.

Replay result, used below: unexplained 13 -> 0 and 12 -> 0; collateral 31 -> 18 (fidelity) and 28 -> 14 (traps).
The hand rules cover what they were written for (`engine-rp` 253, `engine-fw` 4 / 2, `rig` 1). The 18 / 14 records
left are what the new ambient set has to supply.

## B (blockers)

**B1. The traps null window leaves out the rig's own `after-exec` phase, so two records of every traps gate run cannot
be in the ambient set.**
`vm/guest/m1b-exec.ps1:814` (null return) against `:821-838` (`after-exec`, before `snap-b` at `:840`) and `:351`
(`Get-ExScmState` = `Get-CimInstance Win32_Service`).

- In m1b-x-traps the gate window is snap A, deep A, exec, **after-exec**, snap B. after-exec reads the running trap
  service through CIM, which touches the WMI tracing keys of the providers it loads.
- The failed traps run shows it: `~K ...\Wbem\Tracing\Providers\CIMWin32 @ root/CIMV2` and `~K
  ...\Win32_WIN32_TERMINALSERVICE_Prov @ root/CIMV2`, LastWriteTime about 0.3 s after the engine exited, inside
  after-exec. The fidelity run (after-exec after snap B) has neither. Both are still collateral in the replay.
- `Invoke-ExNullWindow` (`:628`) only sleeps, so no traps null run makes these records. `m2-ambient.json` (12 M2 null
  runs) holds only `-K` / `-V` entries for CIMWin32, no `~K`. RIG.md 12.8 lists both keys as "Windows churn"; they are
  rig records.
- Scenario: the rerun's `execdiff-traps.json` has collateral 2, K10 fails, the campaign is spent again.
- Fix (one of): (a) move the traps `after-exec` phase after `snap-b` / `deep-b`, as fidelity mode has it, so the gate
  window holds no rig reads; (b) run the same reads (`Get-ExStateRecord` per trap and twin, `Get-ExScmState`) in the
  null window between the wait and snap B. (a) is cleaner. Extend the self-test `guest_null_window_replaces_exec` to
  compare what runs between `deep-a` and `snap-b` in both branches.

## S (should fix)

**S1. Several of the remaining records look caused by the exec itself, not by idle time; check with a replay before
the rerun.** `vm/RIG.md:1548-1551`, `vm/guest/m1b-exec.ps1:628-633`.

- In both failed runs, absent from all 12 M2 null runs: `~F ntuser.dat.LOG2` and `UsrClass.dat.LOG2` (size to 0 /
  8192), `~F ...\PowerShell\StartupProfileData-NonInteractive` and `~D ...\AppData\Local\Temp` (both about 0.4 s
  before the System Restore provider loads, so at engine start), `~V Windows Defender\Spynet|LastMAPSSuccessTime`.
  Traps only: `~D C:\WINDOWS\System32\config`, `-K ...\Component Based Servicing\TiRunning`, `-V hivelist|...
  \COMPONENTS`.
- The M2 exec runs (restore point `NotRequested`) passed with the M2 set, so these did not occur there either. What is
  new in M1b is the restore point (VSS flushes the hives, which would reset the `.LOG2` files) and the typed-object
  work. I could not prove the cause from code; the M1b flows also do more before snap A (plants, csc), which a null run
  does reproduce.
- A null run has no engine process and no restore point. If the records are exec-induced, the ambient set will lack
  them and K10 fails again, fail-closed.
- Fix: after `m1b-x-null`, replay before spending the campaign (seconds, host only):
  `rigtool execdiff --before <run>\snap-<run>-a.tsv.gz --after ...-b.tsv.gz --journal <run>\sess-<tag>-journal.jsonl
  --report <run>\report-<tag>.json --deep-before ... --deep-after ... --ambient truth\m1b-exec-ambient.json --sid <sid>`
  for the two failed runs. Expected: collateral 0 (the two B1 keys aside if fix (a) is taken). Whatever is left is
  exec-induced and needs a ruling: a conditional rule like `is_engine_rp_created`, or a null window in which the rig
  creates a restore point itself.

**S2. The ambient build does not check that its inputs are null runs.** `vm/rig-m1b-exec.ps1:491-507`
(`Invoke-XBuildAmbient`), `:421-425` (`Get-XRunName`), `vm/rigtool/src/ambient.rs:444`.

- The build takes any directory `<prefix><k>-<mode>` that holds a snapshot pair. It reads no `run.json`.
- Scenario 1: a gate run with `-RunPrefix xn1-` is named `xn1-m1b-x-fidelity`, the name of null round 1 (the comment
  at `:150` says a null name is never a gate run's; nothing enforces it). `m1b-x-ambient` then builds the set from a
  real exec window, and every removal and change the engine made becomes ambient.
- Scenario 2: `m1b-x-ambient` after a partly failed campaign uses a run that failed after snap B, or a stale one.
- A set built from a null run can also name a fixture object if Windows touches one in the window (a planted task
  firing, the running trap service). An exact `~` record on a `PurgeExec*` object would then excuse the same change
  by the engine; a random task GUID turns into a token pattern over every task.
- Fix: in `Invoke-XBuildAmbient` require each `run.json` to have `null_run.null = true`, the expected mode, a finished
  run and no failed phase; make `Get-XRunName` refuse a name that `Get-XNullRunName` can produce; fail the build (or
  the scorer) when a record or pattern contains `PurgeExec`, `C:\ProgramData\Purge` or the app's ARP key.

**S3. Open question: yes, BIND should verify the ambient set.** `vm/truth/m1b-exec.sh:156-186` (binding), `:196`
(`inputs.ambient` is only the guest path `C:\cr\bin\m2-ambient.json`).

- Today K10 passes with whatever file was pushed: `-AmbientFile <anything>`, a set from an older m2-base, the M2 set
  (`m1b-x-undo-traps` and `m1b-x-crash` fall back to it silently, `rig-m1b-exec.ps1:452`), or a set from S2's scenarios.
  The ambient set decides K10 as much as the cases file does, and the cases file is bound (R4 S4).
- Recommendation:
  1. Commit `vm/truth/m1b-exec-ambient.json` (and `-cleanpro`) after the null campaign, read by a reviewer like a truth
     file.
  2. The scorer hashes the committed file itself (as it does the cases file) and requires, for all four VM runs,
     `results.ambient.declared.sha256 == results.ambient.guest_sha256 == that hash`. A hash taken only from the run
     proves nothing.
  3. The scorer also checks the file: schema `purge.rig.m2ambient/1`, at least a constant number of runs per null mode
     (in the script, not the cases file), run ids of the null-run shape, and no fixture name (S2).
  4. `m1b-crash.ps1` records no `results.ambient` (`Get-ExAmbientRecord` is below the `-Library` return of
     m1b-exec.ps1); add it, and drop the silent M2 fallback for the gate modes.
- Not a blocker for starting the rerun: the runs already record both hashes (crash: the host's only), so the check can
  be added to the scorer afterwards, provided the file used is committed unchanged.

**S4. The prefetch rule covers every `PurgeExec*` program, including the service binaries the engine must never
start.** `vm/rigtool/src/items.rs:161`.

- Only `PurgeExecTrapSvcRun` is started by the rig (`m1b-exec.ps1:783`). The pattern also matches
  `PURGEEXECSVCA.EXE`, `PURGEEXECSVCB.EXE`, `PURGEEXECTRAPDEP.EXE`, `PURGEEXECIMPOSTOR.EXE`.
- Scenario: the engine (or the SCM on its behalf) starts a planted service during exec. The new prefetch file was the
  one record of that in the snapshot diff; it is now dropped as `rig`, for any op (`RigRules` has no op filter, so a
  removal is excused too).
- Fix: name the program, `PURGEEXECTRAPSVCRUN\.EXE-[0-9A-F]{8}\.pf`, and add the service binaries to the negative
  tests.

**S5. A key that already exists never gets its recorded descriptor, so an undo interrupted inside the write-back cannot
converge.** `crates/purge-exec/src/act_service.rs:1698-1742` (`write_back_ops`), `:2302-2304`, `:2780`.

- The descriptor is restored only in the `CreateKey` arm. `write_back_ops` emits `CreateKey` only for a missing key.
- Scenario: the process ends between `create_subkey` and `set_security` (or `restore_key_security` returns an error,
  now `VerifyFailed`). The next attempt has `own_attempt`, `own_partial_restore` holds, `create = None`; the key
  exists, so no write touches its descriptor; `tree_difference` reports "another security descriptor";
  `ValueDiffers`. After that `own_attempt` is false and every further undo is `ObjectExists`.
- The same holds for a subkey the SCM creates during create / config2 with a descriptor that differs from the backup.
- No K13 fault point lies inside the write-back, so the gate does not reach this. Before the fix the end state was
  the same on the first attempt, so it is not a regression.
- Fix: a `WriteBack::SetSecurity { path, sddl }` for each existing key below the root whose descriptor (owner aside)
  differs from the backup, applied with the same `restore_key_security` (needs a `WRITE_DAC | WRITE_OWNER` open). Add a
  resume test: create the subkey with a plain DACL first, then run the write-back.

**S6. The whole recorded descriptor is set while the recorded DACL is already in force.** `act_service.rs:2757-2780`,
`:2815`; `crates/purge-win/src/reg_write.rs:1151-1153`, `:1993-1997`.

- Both creation arms put the recorded DACL on the key at creation, then `restore_key_security` sets owner, group and
  DACL in one call. `set_security`'s own contract and the test at `reg_write.rs:1993` say the kernel checks an owner
  or group change against the DACL in force and answers `ACCESS_DENIED`.
- Scenario: a subkey whose recorded DACL gives the engine's token no `WRITE_OWNER` (for example
  `O:SYG:SYD:PAI(A;CI;KR;;;BA)(A;CI;KA;;;SY)`). The error is not 1307, so there is no fallback and the undo step fails
  with `VerifyFailed`. Before this commit the 1307 arm ignored that error and such a key (without `AI`) came back
  `Restored`, so for this shape it is a regression.
- I did not run this (it needs elevation); it follows from the documented behaviour.
- Fix: in the 1307 arm create the key with no descriptor (`None`), then set the whole recorded descriptor once, as
  `set_security` asks. In the other arm, when only the DACL differs, set the `D:` part alone (the owner holds
  `WRITE_DAC`). Add both shapes to the elevated test.

**S7. No gate step runs the elevated SYSTEM-owner test.** `act_service.rs:3542-3564`; `vm/truth/m1b-exec-cases.json:101-106`;
`vm/truth/m1b-exec.sh:92-99`.

- `elevated_write_back_restores_a_system_owned_auto_inherited_key` is `#[ignore]` in the lib tests, "run by hand". E1
  runs the `act_service` integration target with one required name only. The second new test asserts the full
  descriptor only when the process happens to be elevated.
- So the arm that matters most on real machines (owner SYSTEM, refused at creation, set with `SeRestorePrivilege`) is
  not exercised by CI or by the gate. K11 svc-full covers the other arm in the VM.
- Fix: move the test into `tests/act_service.rs` (or add a lib target to `elevated.targets`) and add its name to
  `require_names` in the cases file and in `ELEVATED` of m1b-exec.sh.

## M (minor)

**M1. The write-back stops at the first descriptor that cannot be set.** `act_service.rs:2780`. The values of that key
and all later keys are not written in this attempt, so the service is left with less than before the fix wrote (for
example without `Parameters|ServiceDll`). Fix: finish the remaining writes and return the first error at the end.

**M2. An owner that cannot be assigned is left without a word.** `act_service.rs:2817-2824`, `reg_write.rs:1161-1163`
(any failure of `with_restore_privilege` becomes 1307). The undo reports `Restored` although the owner differs. This
matches the stated contract of `tree_difference`; a note in the outcome detail would make it visible.

**M3. The conditional rules need `Created` / `Done`, but the side effects come from the attempt.**
`vm/rigtool/src/execdiff.rs:1464-1466`. A restore point that ends `Throttled` or `Failed`, or a firewall delete that
ends `Failed`, still loads the WMI provider and writes its tracing key; those records then fail K10. Fail-closed, costs
a rerun. If it happens, let the tracing-key part alone apply for any outcome but `NotRequested` / `Disabled`.

**M4. The NUL check sits in `ConvertTo-EngineArg`, not where the command line is started.** `vm/guest/riglib.ps1:1292`;
unquoted parts at `:1740` and `:1763` (`--sid`), `:1759` (`--group`); `Invoke-Native` `:90`, `Invoke-Engine` `:1324`.
Fix: refuse a NUL in `$Arguments` in those two functions as well. Also `m1b-crash.ps1:237`: `$` in `$XGuidRx` accepts
a trailing newline; use `\z`. I read every other registry string read in `vm/guest` (`Get-RegRaw`, `GetValue`,
`Get-ItemProperty`): none of them reaches a command line, they are compared, hashed or written to JSON. The task Id in
`m1b-crash.ps1:330` was the only one.

**M5. `$XAmbient` is resolved for every VM mode.** `vm/rig-m1b-exec.ps1:432`. `m1b-x-elevated` on a VM without an
ambient entry throws although it needs no set. With `-AmbientFile` naming a missing file on such a VM,
`$script:XPushAmbient` is `$null` (`:452`) and `Push-M2Ambient` fails in `Test-Path -LiteralPath $null`
(`rig.ps1:775`). Fix: resolve it inside `Invoke-XGuestMode` and pass `-None` when there is no file.

## N (notes)

**N1. Engine fix, both arms.** Creation with the recorded descriptor, read back, set once through the creating handle,
read back again and compared owner aside: correct for the K11 / K13 case (owner assignable, `D:AI`). The 1307 arm
creates without the owner and then sets the whole descriptor, which `set_security` retries with `SeRestorePrivilege`;
unelevated it falls back to group and DACL. `rest.is_empty() || rest == recorded` stops a pointless second call. The
first new test fails on the old code (creation drops `AI`), so it reproduces the bug, at the `write_back_below` level,
not through `run_undo` and the SCM. Crash recovery at the existing fault points is unchanged: `svcrestore.mid` lies
before the write-back and `undo.act.after` behind it.

**N2. Rules.** Every new predicate returns false for `-` first; `is_wmi_tracing` allows only `+K`, `~K` with LastWriteTime
/ value count, and `+V` with a numeric name. Paths are compared whole, per segment, with the control set checked. The
conditions come from the engine's own report (`restore_point.kind`) and the journal's effective outcome; they are the
engine's claims, but they unlock only OS diagnostics, never a file or key an item could target. The two integration
tests carry real negative controls (`NotRequested`, `Failed`, a skipped rule, no firewall op, removals).

**N3. Null timing.** The exec phases of the failed runs took 10.3 s and 8.7 s; `-NullWaitSec 10` fits. Same snapshot,
same flow up to deep A. `--added` entries match an added record only, never a subtree (unit test).

## Summary

| Class | Count |
|---|---|
| B | 1 |
| S | 7 |
| M | 5 |

The G5/G6 rerun can start after B1 is fixed and the S1 replay comes back clean; S3 (BIND) can follow in the scorer
without a new campaign, S2 and S4 should go in with B1 because they change what the ambient set and K10 mean.
