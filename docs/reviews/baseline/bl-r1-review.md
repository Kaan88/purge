# BL-R1 review: wave 5 (BL-FRAMEWORK, BL-CACHE) and the regpath change 59ae960

Date 2026-11-21. Reviewer: Fable. Branch `baseline`, HEAD e285d26 (BL-FRAMEWORK d530862, BL-CACHE e285d26).
Read-only review; no code changed, nothing built, no test and no xtask run (an unelevated CI run held the target
directory). One read-only `reg query HKU` on the host, for finding M3.

Inputs: `docs/HANDOFF-baseline.md`, `docs/BASELINE_LOCAL_DESIGN.md` (2, 4.1 to 4.6, 5, 8.3 to 8.5) and `.json`
(BL-R1, BL-FRAMEWORK, BL-CACHE), `docs/DECISIONS.md` (2026-11-21, presence-only), the diff ba920c8..e285d26, and in
full: `purge-index` `baseline_view.rs`, `baseline_view/fixture.rs`, `local_baseline/cache.rs` (production part);
`purge-scan` `framework/absence.rs`, the baseline sites of `framework.rs`, `skeleton.rs`, `cls_*`, `com_*`,
`reg_software.rs`, `ref_any.rs`, `framework/m1b.rs`; `purge-harvest` `refsnap.rs`, `harvest.rs`, `subtree.rs`,
`assoc.rs`, `anchors.rs`, `tokens.rs`, `msi.rs`, `sysobj.rs`, `coproducts.rs`; `purge-model` `fingerprint.rs`,
`evidence.rs`; `purge-policy` `band.rs`; `purge-win` `sid.rs`; `bins/purge-engine` `pipeline.rs`,
`pipeline/baseline.rs`, `main.rs`, `cli.rs`; `tools/xtask` `baseline_sites.rs`; `purge-scan/tests/shared/l5.rs` and
the per-scanner L5 tests; `purge-source` `live/regpath.rs`, `purge-guard` `canon.rs`.

Labels: B blocker, M must be fixed before BL-GATE, S should be fixed, N note.

## Verdict

- **No B finding.** No absence-dependent site reaches Safe, preselection or even a Tier A key form below Exact. No
  presence site is used negated beyond the three listed ones, and those three are presence uses. A standard user
  cannot plant or poison the cache or the shipped directory of an elevated engine, and what a poisoned cache could do
  is bounded by presence-only to "the scan of M1b without a baseline". A local file or a neighbour cannot become the
  Exact view.
- **Three M findings**: the rig's baseline directory fails the new directory rule (M1), invariant L5 is shown per
  scanner on a fixed fingerprint only and the replay that shows it end to end cannot run yet (M2), and the regpath
  change 59ae960 is half a fix (M3).
- Seven S findings, eleven notes.

## 1. An A site that reaches Safe or preselection below Exact

None found.

The view can answer `Inferred` (`baseline_view.rs:566-568`). Each crate hands it out as `Unknown` at one place:
`purge-scan` `framework/absence.rs:58-63` (`capped`, called from `key_absence`, `:75-77`) and `purge-harvest`
`refsnap.rs:192-197`. `key_absent` has no other caller in production code of any crate (checked over the workspace,
not only the two crates the xtask reads). Every gate is the trust test `== Exact` (`absence.rs:82-84`,
`refsnap.rs:169-175`).

Site by site, with the old line where the behaviour had to stay the same at Exact:

| Site | Code | Below Exact | At Exact, against ba920c8 |
|---|---|---|---|
| skeleton `check`, `prove`, listed subkeys | `skeleton.rs:120`, `:125`, `:255-259`, `:363` | `NotProven::NoBaseline` before any key is asked | `Proven` is `key_in_scope && !has_key`: same |
| Inno key record, tier | `framework.rs:2018-2021` | Tier B, `baseline=none` | same |
| delete-whole-key record vouching for a value | `framework.rs:1094-1102` | false | `!(in_scope && has_key)` in all four cases: same |
| `HarvestedToken` on a key | `framework.rs:2219` | no evidence | same |
| `classes::proven_not_windows`, `key_offerable`, COM key ownership | `cls_progid.rs:454-461`, `com_class.rs` (`proven_not_windows`) | false; `ComKeyOwnership` Tier B with `baseline=none` | same |
| shell handler value cap | `com_shellex.rs:864` | capped at Tier B | same |
| association skeleton standing | `cls_assoc/handler.rs:392-403` | no-baseline standing (X-SYSTIDY, `ChainedRef` Tier B) | `!in_scope \|\| has_key` is "not `Proven`": same |
| restore source of an `.ext` default | `cls_assoc.rs:207-209` | `None` (`exact_value`, `baseline_view.rs:574-579`) | same |
| REF-ANY record preselection | `ref_any/record.rs:184-186`, `:270` | not preselected | same |
| harvest: climb to ancestors | `subtree.rs:346` | ends at once | `known \|\| !in_scope` is "not `Proven`": same |
| harvest: `ext_in_baseline`, `openwith_in_baseline` | `assoc.rs:252-256` | `Some(true)` or `None`, never `Some(false)` | `has_key`: same. Report facts only: they are fields of `ExtRecord`, not of the fingerprint's `ExtJournalEntry`, and no scan reads them |

The no-baseline path does offer keys (REF-ANY `attributed_key`, `ref_any.rs:338-353`: an Inno key record at Tier B),
as it did at M1b; that is the design's "`Unknown` → Tier B, as today", not an offer on inferred absence.

The site table of `tools/xtask/src/baseline_sites.rs` (`SITES`, `:154-735`) agrees with the code in every row I
read: classes, counts and the "below Exact" text. No hand-written `!has_key` absence test is left. The carrier
(`absence.rs:162-195`) and the seal (`framework.rs:725-738`) have no production caller that hands them `Inferred`.

Findings S1, S2 and S6 are about what stands behind this result when somebody changes the code later.

## 2. A P site used negated

Three textual negations, all listed in the table, all presence uses in the sense that the path taken when the view
says "not present" is the path the engine takes without any baseline, so a larger union only removes:

- `framework.rs:1030`: a `Clients` name that carries a token Windows knows is not the app's registration.
- `anchors.rs:846`, `:883`: an AppID or CLSID key Windows has is no anchor.

The other P sites block or withhold on "present" (`framework.rs:1189-1197`, `:2213`; `framework/m1b.rs:1129`,
`:1146`, `:1199`; `com_class.rs:934`, `:1153`, `:1324`, `:1400`, `:1493`; `com_shellex.rs:785`, `:804`;
`com_interface.rs:465`; `reg_diag.rs:369`, `:569`; `ref_any/record.rs:255`; `reg_software.rs:536-539`;
`fs_vendorparent.rs:196`; harvest `anchors.rs:829`, `:1025`, `tokens.rs:240`, `msi.rs:730`, `sysobj.rs:157`,
`:220`, `:269`, `coproducts.rs:330`, `subtree.rs:486`, `:584`). No local variable holds a presence answer that is
negated later.

## 3. Planting or poisoning as a standard user

### 3a. `is_admin_only_writable` (`crates/purge-win/src/sid.rs:354-446`)

The rule holds against a standard user of the machine. Per point of the brief:

| Point | Result |
|---|---|
| Owner | Must be SYSTEM, Administrators or TrustedInstaller on the path and every ancestor (`:402-407`). A directory a standard user created first (squatting on `%ProgramData%\Purge`) is refused. An administrator's own account as owner is refused too: conservative |
| Inheritance | The effective DACL of every component is read, so an ACE inherited from above is seen on the component it reaches. Inherit-only ACEs are skipped on the object that carries them (`:97-99`), which is correct for that object |
| CREATOR OWNER | Skipped as a placeholder (`:47`, `:421`): it is in no token, so an effective ACE for it grants nothing. Its inherit-only form matters only where a user can create a child; on the leaf directory `FILE_ADD_FILE` and `FILE_ADD_SUBDIRECTORY` are in the mask (`:65-72`) |
| Deny ACEs | Ignored (`:92-94`), which can only err towards "writable" |
| NULL DACL | `false` (`:408-410`); an empty DACL passes, correctly (owner only) |
| Reparse points | Every ancestor is opened as the last component of its own path with `FILE_FLAG_OPEN_REPARSE_POINT`; a name surrogate anywhere answers `false` (`:364`, `:373-376`, `:437-440`). Other reparse tags pass; they do not redirect a name |
| TOCTOU | A component passes only when no standard user may delete, rename, re-ACL or take it (`ANCESTOR_WRITE_MASK`, `:75`). That property cannot be undone by a standard user, so there is no window between the check and the later open by path. `exact_file` and `Baseline::try_select` open the same joined path (`pipeline/baseline.rs:157`, `baseline.rs:334`) |
| Hard links | A hard link shares the file's descriptor, and a file moved in keeps its own. The directory rule does not see either; BL-CACHE therefore judges the exact file and `view.json` themselves (`pipeline/baseline.rs:140-165`, `:254-262`). Cache parts and neighbours are not judged per file: N4 |
| 8.3 names, case | No trust decision compares names; check and use take the same string. Cache file names are built from an edition restricted to letters, digits and `_` and a 16-hex id (`cache.rs:919-948`) |

Residue: S4 (where the path comes from, and volumes written elsewhere), N3.

### 3b. The cache and the pipeline

- **Plant, poison.** `LocalCache::open` (`cache.rs:347-363`) needs the rule on the directory and a plain directory;
  the directory is created only by an elevated engine under a data root that passes (`pipeline/baseline.rs:179-191`).
  Writes are `create_new` on a temporary name plus rename (`cache.rs:785-811`). A derived `.sets` file is taken only
  when bound to the SHA-256 of the text it stands for (`cache.rs:565-583`, `:668-676`).
- **What poisoning could buy.** Nothing beyond the no-baseline scan. Below Exact the cache and the neighbours feed
  presence only; a removed record removes a block, and the floor is the engine without a baseline. The only inputs an
  absence answer rests on are the exact shipped file (Exact) and nothing else; `view.json` decides areas, which no
  consumer reads while `Inferred` is capped.
- **Downgrade.** An elevated load asks for the part by the id of the machine as it is now (`cache.rs:509-517`); an
  older part has another name and another header id and is a miss (`part_matches`, `:976-989`). The stale S4 part an
  unelevated engine takes (`:519-537`) is marked incomplete, so the view has trust None.
- **Delay.** A standard user can change the S4 id by updating a Store app (a rebuild under a second). Where the
  cache directory is readable by Users, a user can hold a part open without sharing and so block the engine's read
  and its rename (N7); under the `install.ps1` data root Users cannot read it. Both cost presence only.

## 4. The view claiming Exact

Not possible from data. `BaselineView::exact` has one production caller (`pipeline/baseline.rs:238`), fed by
`load_baseline` → `Baseline::try_select` (`baseline.rs:321-348`): file name and header must both be the host's, and
the header tag is compared for equality (`baseline.rs:715`), so a `#purge-baseline-local` file under an exact name is
refused (L6). `rank_neighbours` drops the host's own file (`neighbours.rs:81`). A neighbour is loaded only when its
header names what its file name names (`cache.rs:898-912`).

`Fingerprint::harvest_trust` (`fingerprint.rs:542-554`) believes a recorded Exact only with the shipped baseline of
the fingerprint's own Windows in hand, and never raises a recorded Merged, Local or None. A crafted fingerprint can
only lower the policy trust. `for_policy` (`:380-386`) is inferred as soon as either side is. Under presence-only the
harvest side is inert: the harvest records `None` for every view below Exact (`harvest.rs:349-358`), and `for_policy`
gives `scan` whenever neither side is inferred. See N5 for the open point about unelevated harvests.

A fingerprint harvested under one view and scanned under another: every absence the harvest used is asked again by
the scan under its own view (the skeleton asks the key and every listed subkey, `skeleton.rs:255`, `:363`; COM and
ProgID keys through `proven_not_windows`; tokens through `has_token`, `framework.rs:2213`; system objects through
`framework/m1b.rs:1111-1199`). The one harvest fact that is wider under Exact, the climb to ancestors
(`subtree.rs:346`), only adds subtree records, and a record is no proof without the scan's own answer. Harvest under
Exact followed by a scan below Exact (a cumulative update between the two) is the M1b case "baseline gone at scan".

Finding S2 is the one soft spot: an Exact view of another Windows is representable.

## 5. Invariant L5

No counterexample found by reading; no test was run.

What `tests/shared/l5.rs` checks: (1) a view below Exact that holds nothing gives candidates equal to the
no-baseline scan, for a Merged, a Local and a None view with rules that would infer absence everywhere (`:137-146`).
This is the strong half: it shows that no A site sees inferred absence. (2) A view that holds every key, directory,
service and task the no-baseline candidates name preselects nothing new, and what was Blocked is Blocked or no longer
listed (`:148-170`), with the policy at trust None and at the view's own trust.

Is that "preselected subset, Blocked superset"? The first part yes, by candidate id. The second is weaker than the
design's wording on purpose (a scanner may withhold a Windows key), and weaker than what presence-only allows one to
state (S3, S7). Vacuous or thin tests: S3. The end-to-end property: M2.

## 6. Commit 59ae960 (regpath)

Correct as far as it goes: `.DEFAULT`, `S-1-5-18`, `S-1-5-19` and `S-1-5-20` have no `<SID>_Classes` hive. The
host's `HKU` lists exactly those four, the user's hive and the user's `_Classes` hive, and
`HKU\.DEFAULT\Software\Classes` is an ordinary key with a `Local Settings` child. The comparison is exact and
case-insensitive, and the test pins that `S-1-5-18-1` is still an ordinary user (`regpath.rs:310-311`). Before the
change a key below `Software\Classes` of these hives read as not found, a false absence.

It is half of the fix: M3. Other hives without a classes hive: N10.

## Findings

### M (must be fixed before BL-GATE)

**M1. The rig's shipped baseline directory fails the directory rule, so the elevated rig engine uses no shipped
baseline at all.** `main.rs:64` sets `check_shipped_dir` for every live engine; `shipped_dir_trusted`
(`pipeline/baseline.rs:127-133`) then refuses a directory with a non-administrative owner or an inherited grant, and
`load_with` goes on without the exact baseline and without neighbours (`:215-234`). The rig makes
`C:\cr\bin\kb\baselines` below the drive root by `guestcontrol mkdir` (`vm/rig.ps1:374`; `C:\cr` itself in
`vm/bootstrap-vm.ps1:24`), so it inherits the drive root's grant for Authenticated Users; `vm/win-unit.ps1:120`
even grants them Modify on its tree explicitly. Not checked on a VM; it follows from the code and the scripts. The effect is silent: one warning
line, exit code 0, and every "exact" run of R3 and R4 becomes a values-only run. L3 would then be judged on plans
that used no baseline. Fix, both parts: (a) the rig protects the engine tree before the first engine call
(owner Administrators; `icacls <tree> /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F
*S-1-5-32-545:(OI)(CI)RX`), and `install.ps1 -Check` style verification of it; (b) the rig reads `engine.hello`
(`baseline_trust`, `baseline_view`) and fails a run whose trust is not the one the run is for (Exact for the L3
runs, the hidden-baseline trust for R4). (b) is the part that keeps this from coming back. The same holds for any
user who unpacks the engine into a directory that is not admin-only: the elevated engine loses the exact baseline it
had at M1b. That is the design's intent (5, "The shipped directory"); say it in the release notes and in the UI's
"no verified clean-install list" line.

**M2. L5 is shown per scanner on a fixed fingerprint; the end-to-end property is unshown and the tool that shows it
does not run.** The pipeline harvests with the view (`pipeline.rs`, `harvest_report_with(…, &baseline.view, …)`), so
a view below Exact changes the fingerprint (fewer anchors, tokens, table anchors, recorded system objects and
co-products; shallower subtree records), and the plan stage merges candidates across scanners (containers offered
when empty after the plan). The L5 tests run one scanner on one hand-made fingerprint and band each candidate alone
(`l5.rs:64-92`, `:130-135`). Whether "less at harvest" can ever mean "more in the plan" is exactly what R3 is for
(8.3 S4), and `xtask replay --baseline-view merged|local` still bails (`tools/xtask/src/replay.rs:556-558`). Fix:
before BL-GATE the replay injects the view into harvest and scan alike (a `PipelineBaseline` built from `--local` and
`--neighbour`, no cache, `check_shipped_dir` off), and S4 is judged on the plans with the property of S7. Cheap
addition inside `purge-harvest`: a test that a whole fingerprint harvested under a view that knows the app's keys
is a subset (anchors, tokens, table anchors, system objects, co-products, attributed subtrees) of the no-baseline
fingerprint. Today `tests/refsnap/main.rs:1981-2081` has both halves for the journal and the subtree capture,
`tokens.rs` has presence at every trust, and `harvest.rs` compares whole fingerprints only for views that hold
nothing.

**M3. 59ae960 changes one of three places that apply the same lexical rule; two spellings of one key now disagree
in the Live source.** `regpath.rs:112-120` no longer rewrites `HKU\.DEFAULT\Software\Classes\x`. But

- `purge-guard` `canon.rs:658-672` (`user_key`) still canonicalises `HKU\<any sid>\Software\Classes\x` to
  `Hive::HkuClasses(sid)`, for `.DEFAULT` and the three service SIDs too;
- `purge-harvest` `refsnap.rs:244-250` (`source_key`) still rewrites it to `HKU\<sid>_Classes\x`;
- `regpath.rs:113` itself still takes `HKU\.DEFAULT_Classes\x` for a classes hive and opens a hive that does not
  exist.

So the in-place spelling now reads the key, and the canonical spelling, which is what a candidate target, a
reference-snapshot entry and the executor's address carry (`purge-guard` `live.rs:717`), reads "not found". Before
the change both spellings were consistently absent. The change makes these keys visible to a reference scan whose
scope is every loaded hive (`purge-index` `refscan.rs:250`; `loaded_user_sids` includes the service SIDs,
`purge-source` `registry.rs:27-28`): the walk below `HKU\S-1-5-18\Software\Classes` now reads the children it
used to list and fail on, and `source_key` turns a hit there into a target nobody can read or address. I found no path from this to a wrong delete (the executor cannot open the key either), but "not
found" from the Live source is evidence in several places, and the scan path now depends on which spelling a caller
happens to hold. Fix: one predicate "this hive has a classes hive" in one place (`purge-model`, beside
`target.rs:433`), used by `regpath`, `canon::user_key` and `source_key`; for the four hives the canonical form stays
`Hive::Hku(sid)` with the path `Software\Classes\x`, and `HKU\.DEFAULT_Classes\…` is refused as an invalid path.
Tests in all three crates, plus one Live test that both spellings of a `.DEFAULT` classes key agree. The baseline's
own fold (`baseline.rs:35-36`) is applied to both sides of a hash comparison and needs no change.

### S (should be fixed)

**S1. The policy backstop is off under a Merged or Local view; the cap has two live layers, not three.**
`pipeline.rs:1109-1116` hands the policy `for_policy(ctx.absence_trust(), …)`, and `absence_trust` is
`trust().presence_only()` (`absence.rs:107-109`): `None` for a Merged view. The fingerprint side records `None` as
well. So `is_capped` (`band.rs:172-175`) acts only on evidence that carries the carrier's own fact. A site wired to
inferred absence by mistake that does not call the carrier is stopped by the seal only, and the seal leaves out
key-scope `InstallerManifest(Msi | Burn)` and key-scope `ChainedRef` (`absence.rs:146-153`), with the comment "the
policy backstop P-BL-1 still caps them when it is handed an inferred trust" (`:135-137`). It never is. DECISIONS
2026-11-21 ("the cap stays as defence in depth, so a mistakenly wired A site still cannot reach Safe or
preselection") is therefore true for four evidence forms and not for those two. Handing the policy the view's own
trust would fix that, but would also cap the MSI and Burn key records that a no-baseline scan preselects today, a
recall loss with no safety gain. Recommended: keep the code, correct the three texts (DECISIONS, design 4.3 "As
built", `absence.rs:135-137`), and write into 8.5 that the first A site wired below Exact comes with
`baseline.view.trust()` as the scan side of `for_policy`. The pipeline test at `pipeline/baseline.rs:1352-1360`
already pins today's choice.

**S2. In the scan, "Exact" does not mean "of this Windows".** `ScanCtx::has_exact_baseline` and `key_absence`
(`absence.rs:75-84`) do not ask whether the Exact view matches the machine; the harvest's namesakes do
(`refsnap.rs:169-197`). `key_record_covers`, the Inno key record's tier and `HarvestedToken` on a key
(`framework.rs:1094-1102`, `:2018`, `:2219`) accept any Exact view, and `key_absence` answers `Proven` from it. This
is the M1b behaviour (`baseline.is_some()`), and no production path builds a mismatched Exact view (one constructor
call, after `try_select` for the same `os_info`). But the state is representable, the tests build it
(`baseline("EnterpriseS", …)`), and two methods of the same name in two crates mean different things. Fix: fold the
match into the capped path (`key_absence` answers `Unknown` and `has_exact_baseline` false unless
`is_exact_for(os_now())`), or make `BaselineView::exact` take the host and refuse another Windows. Either is
byte-identical at the gate.

**S3. The L5 harness proves less than its name.**
- Presence is all or nothing: the four views of the second half hold every key of every no-baseline candidate
  (`l5.rs:149-163`). No partial set (the parent and not the child, one neighbour key), which is where a scanner
  switches from a key to its values or from a container to its children.
- The fixture views hold keys and directories only (`fixture.rs:33-44`): no value, no file. `has_value`
  (`framework.rs:1194`, the firewall facts) is never true below Exact in any L5 test.
- Nothing asserts that the second half changed anything. A presence path that stopped working below Exact would
  pass.
- Nothing asserts "no new candidate" or "no band raised": a candidate that exists only under the view, or goes from
  Weak to Likely, passes as long as it is not preselected.
- Non-vacuity is an aggregate (`offered > 10` over worlds times scanners: `reg/main.rs:2712`, `assoc/main.rs:1222`,
  `fs/property.rs:161`; `> 7` in `msireg/main.rs:44`): a scanner that offers nothing in any world passes unseen. The
  second half is empty by construction for SYS-APPX (`keys_of` skips package targets) and for firewall rules (stated
  in the test).

Fix: per (world, scanner) either a non-empty no-baseline result or a named exemption; a seeded random subset of the
keys in place of the full set (some hundred draws; the worlds are small); value and file records in the fixtures;
assert `ids(below) ⊆ ids(none)` up to a named list of substitutions, `rank(band below) ≤ rank(band none)` per id,
and that the full-presence view removed or blocked at least one candidate wherever a P site exists.

**S4. The directory rule cannot tell a volume written elsewhere, and the engine takes its directories from the
environment.** The rule compares well-known SIDs, which are the same on every machine. An NTFS volume prepared on
another machine (removable disk) or a share whose server answers with an Administrators-owned, admin-only
descriptor passes every component, with content a standard user chose. That matters only when a user can point the
elevated engine there, and `main.rs:43-46` takes the baseline directory from `PURGE_KB_DIR` and `:53` the data root
from the `ProgramData` variable. A separate standard account cannot set the environment of another account's
elevated process. A medium-integrity process of the administrator's own account can, through the per-user
environment (to be confirmed on the rig with UAC on; it is the M3 case "UAC-on broker"). What it would buy: a
shipped "exact" file with lines removed, so absence proofs for Windows keys; the other conjuncts of each proof still
stand. Before this work `PURGE_KB_DIR` was honoured with no check at all, so BL-CACHE narrowed the gap. Fix: an
elevated engine ignores `PURGE_KB_DIR` unless built with the rig feature, takes the data root from the known-folder
API, and the callers that decide trust (`shipped_dir_trusted`, `LocalCache::open`, `table_cache`) require a fixed
local volume, as the scan already does for dangling references (`VolumeInfo::proves_absence`). Must be closed for
the M3 broker at the latest.

**S5. An elevated engine has no S1 presence after every servicing change until the rebuild ends (BL-CACHE open
point: stale part for presence).** A part of another id is a miss (`cache.rs:509-517`), the view then holds S2, S3,
S4 and the neighbours, and the build takes one to three minutes cold. Under presence-only the S1 part is most of
what the feature gives, and a cumulative update arrives monthly. A stale S1 part of the same edition and build is
still a list of keys Windows owned (L1: it can only add presence, at the cost of a few keys of removed components).
Recommended: yes, take it. On a miss, load the newest part of that source for the same edition and build with the
current builder version, mark its `#src` line incomplete with the reason "stale: id … of …" (as the unverified S4
part is marked, `:528-534`), so the local baseline is incomplete and the trust None by L2. `KEEP_PARTS` already
keeps the previous file. One test: a stale part never yields trust Merged or Local.

**S6. `baseline-sites` has blind spots that a later change can walk through.**
- It reads `purge-scan/src` and `purge-harvest/src` only (`baseline_sites.rs:877`). A helper in `purge-index`,
  `purge-plan` or the engine that takes a view and calls `key_absent` is not seen. Today there is none.
- `production_code` stops at the first `#[cfg(test)]` at the start of a line (`:779-789`). In
  `purge-harvest/src/inno.rs` that is line 57 of 1088 (`mod tests;`), in `inno_map.rs` 394 of 945, in `roots.rs` 932
  of 1506, in `purge-scan/src/catalog.rs` 146 of 334; what follows is not read. None of it mentions the baseline
  today.
- A line is cut at the first `//`, also inside a string literal.
- Negation is textual (`:799-831`): `== false`, an `else` branch or a `let` followed by `!name` is not seen. The
  count rule catches a new call; it does not catch an existing call whose use is turned round.
- The cap rule is "the file contains the arm" (`:982`).

Fix: read every crate of the workspace for `key_absent(` and `Absence::Inferred` (allow-list: `baseline_view.rs`
and the two capped files); skip only the item that follows a `#[cfg(test)]` instead of the rest of the file; a test
in `purge-index` that lists the public methods of `BaselineView`, so a new one has to be classified. The textual
negation rule is a tripwire and can stay one; the site table review is the real check.

**S7. The design states L5 and S4 as "Blocked sets are supersets"; the code checks "Blocked or no longer listed".**
(`BASELINE_LOCAL_DESIGN.md:69-70`, `:481-482` against `l5.rs:111-125`.) R3 judged by the design's words fails on the
first scanner that withholds a Windows key it used to list as Blocked. Decide the property before the gate and write
it once. Presence-only supports a tighter one than either: for every target, the band under a view below Exact is at
most the band without a baseline, where "not listed" is the lowest; and preselected implies preselected. Named
exceptions (a key replaced by its values) get their own rule instead of a hole in the property.

### N (notes)

- **N1.** Attack 1 and 2 results as in sections 1 and 2. I did not run `cargo xtask baseline-sites`; the counts in
  the rows I checked by hand match.
- **N2.** `BaselineView::exact` is public and takes any `Baseline` (`baseline_view.rs:151`). One production caller
  today. See S2 for the fix that also covers this.
- **N3.** `sid.rs` details that are not holes today: a compound allow ACE (type 4) is treated as "not an allow"
  (`:92-94`, `:170`) and so ignored; safer to treat every ACE type that is not a known deny or audit type as a
  grant. A handle a user opened for write before a file was protected survives the protection; an installer that
  copies and then tightens should create the directory protected first.
- **N4.** Before any area lets inferred absence count (8.5), these become safety items and are not today: cache
  parts and neighbour files are not judged per file (a moved-in or hard-linked file, an inherit-only grant on the
  directory), although a removed record there would then make a key absent; the policy gets `None` under a Merged
  view (S1); only the main fingerprint's `baseline_view` is read, the co-removed products' own fields are not
  (`pipeline.rs:1111`); the S1 id is count, total size and newest write time, not content.
- **N5. Open point "an unelevated harvest is believed at Exact when scanned elevated".** True as stated: an Exact
  view records nothing (`harvest.rs:349-352`), so the fingerprint reads as Exact with the shipped file in hand, and
  an unelevated engine loads the shipped file without the directory check (`pipeline/baseline.rs:127-129`). It has
  no consequence today: `for_policy` ignores a harvest side that is not inferred, and the scan asks every absence
  again under its own, checked view (section 4). The real question is wider and belongs to M3: a fingerprint or a
  plan made at medium integrity is a document its author can edit, baseline or not. The broker must harvest and
  scan itself, or treat such a document's key evidence as it treats `UserWritable` sources. Design 5 says so for
  the baseline ("the broker never takes a baseline computed at medium integrity"); extend the sentence to
  fingerprints and plans.
- **N6. Open point "the unelevated engine gets no local cache under the `install.ps1` data root".** Accept. Giving
  Users read access would buy presence for an engine that works values-only anyway and would open N7. Write into the
  M3 plan that scans whose result is shown to the user run in the broker.
- **N7.** Where Users can read the cache directory, a user can open a part without sharing and block the engine's
  read and the rename over it (`cache.rs:553`, `:805`): the local baseline is then missing, trust None. Not possible
  under the `install.ps1` root.
- **N8.** A failed build is not remembered: the next elevated run decides and builds again
  (`pipeline/baseline.rs:599-618`), and the CLI waits for the build before it exits (`cli.rs`,
  `finish_local_build`). If S1 can fail the same way every time (no delta base), every run pays the build. A marker
  with the id and the reason, or a retry limit per id, would bound it.
- **N9.** A crafted fingerprint with `baseline_view.trust = Merged` caps the key evidence of an Exact scan
  (`for_policy(Exact, Merged)`). It only lowers; fine.
- **N10.** 59ae960 lists four hives. Service accounts with a loaded profile (`S-1-5-80-…`, `S-1-5-82-…`) and a user
  whose `UsrClass.dat` is not loaded have no classes hive either and are still rewritten. Deciding by "is
  `HKU\<sid>_Classes` loaded" (once per SID) in the shared predicate of M3 covers them. The descriptor of
  `HKU\S-1-5-19\Software\Classes` could not be read unelevated on the host; check on the rig that it is a key and
  not a link.
- **N11.** The golden `cls_assoc_vscode_merged.txt` of design 4.6 was not made; with presence-only the merged view
  is held against the no-baseline golden, which is the stronger statement. Update 4.6.

## The BL-CACHE open points in one place

| Open point | Answer |
|---|---|
| Rig `…\kb\baselines` ACL before BL-GATE | M1: protect the tree and make the rig assert the trust it expects |
| Unelevated engine has no local cache under the `install.ps1` root | N6: accept, document for M3 |
| Elevated fallback to a stale part for presence | S5: yes, marked incomplete, trust None |
| Unelevated harvest believed at Exact when scanned elevated | N5: inert today; an M3 rule for documents made at medium integrity |
| `is_admin_only_writable` not re-reviewed by BL-CACHE | Section 3a: holds against a standard user; S4 and N3 |

## Recommendation

1. Before BL-GATE: M1 (rig ACL and the trust assertion), M2 (replay with an injected view in harvest and scan), M3
   (one classes-hive predicate in three places).
2. With them, cheaply: S7 (state L5 once), S3 (per-scanner non-vacuity, partial presence), S1 (correct the three
   texts), S2 (match inside the capped path).
3. Before M3's broker: S4, N5.
4. Any time: S5, S6, N8.
5. Carry N4 into 8.5 as the list of what the cap lift has to redo.

## Disposition

Added 2026-11-21 by the BL-R1 fixes (branch `bl-r1-fixes`, from `baseline` at e285d26). One line per finding:
fixed in a commit, deferred to a milestone, or accepted. The text above is the review as written.

| Finding | Disposition |
|---|---|
| M1 | Fixed in d645393: `rig.ps1 Push-Tools` protects `C:\cr\bin\kb` (and takes delete and re-ACL rights on `C:\cr`, `C:\cr\bin` from standard users) through an elevated guest job that checks the result against the directory rule; new CLI verb `hello` prints `engine.hello`; `run-app.ps1` phase `engine-hello` fails a run whose `baseline_trust` is not the one the run is for (`-ExpectTrust`, default Exact when the pushed baselines hold the guest's own). **Not run on a VM**: the rig self-test covers the host logic and the descriptors only. `win-unit.ps1` and `rig-baseline-local.ps1` were not changed (the first grants Modify on its own tree and runs unit tests, not the engine tree; the second pushes with `-NoBaselines`, which is now protected like any push) |
| M2 | Fixed in 7c114e1 and ba949a1 (and the frozen-run test's comparison in the commit that adds this section): `xtask replay --baseline-view merged\|local\|none` injects the view into harvest and scan through `purge-engine`'s feature `inject-view` (xtask only; a test pins that no CLI source names the doors); `l5_violations` and `--l5-against` check L5 over two plans; a test replays a case with injected Merged, Local and None views. The purge-harvest test "a whole fingerprint harvested under a view is a subset" was not added: deferred to BL-GATE (R3 shows it end to end; the replay test compares fingerprints only for views that hold nothing) |
| M3 | Fixed in 957c1be: `purge_model::has_classes_hive` used by `regpath`, `canon::user_key` and `source_key`; one table of spellings tested in all three crates, a deny-list test, and a Live test. `HKU\.DEFAULT_Classes\…` is not refused as an invalid path: it is read as the hive it names, which does not exist, so it is absent in every spelling (accepted: refusing it would change what `regpath` and the guard accept for every caller) |
| S1 | Fixed in 2c415f4 (texts only, as recommended): DECISIONS row, design 4.3, 4.4 heading and 8.5, the comment on `claims_absence` |
| S2 | Fixed in 2a8a917: `ScanCtx::has_exact_baseline`, `key_absence` and `absence_trust` require the exact baseline of the Windows the scan runs on |
| S3 | Fixed in ba07878: values and files in the fixture views, seeded partial presence, "no new candidate" and "no band raised", per-scanner non-vacuity with named exemptions, and a self-check that the comparison bites |
| S4 | Deferred to M3 (the broker): an elevated engine still takes `PURGE_KB_DIR` and the data root from the environment, and the directory rule cannot tell a volume written elsewhere |
| S5 | Fixed in f094230: on a miss the newest part of the same edition and build answers presence, marked incomplete (trust None), and still counts as missing for the build |
| S6 | Fixed in c588741: only the `#[cfg(test)]` item is skipped, every crate of the workspace is read for the absence side, the view's public methods must be classified. Textual negation and "the file contains the cap arm" stay as they are (accepted: a tripwire; the module documentation says so) |
| S7 | Fixed in ba07878: L5 is stated once in design section 2; 4.6 and 8.3 S4 refer to it; the scanner tests and `l5_violations` check that statement |
| N1 | Accepted: `cargo xtask baseline-sites` was run for these fixes and passes |
| N2 | Accepted for now, narrowed by 2a8a917 (the scan refuses an Exact view of another Windows) and c588741 (`BaselineView::exact` outside the listed maker fails `baseline-sites`); making the constructor take the host is deferred to M3 |
| N3 | Deferred to M3: compound allow ACEs treated as grants, and "create the directory protected first" for an installer that copies and then tightens |
| N4 | Deferred to the cap lift (design 8.5): the list of what becomes a safety item when an area lets inferred absence count; S1's condition is written into 8.5 |
| N5 | Deferred to M3: a fingerprint or plan made at medium integrity is a document its author can edit; the broker harvests and scans itself |
| N6 | Accepted: the unelevated engine gets no local cache under the `install.ps1` data root; M3 runs user-facing scans in the broker |
| N7 | Accepted: only where Users can read the cache directory, which the `install.ps1` root does not allow; costs presence only |
| N8 | Deferred to M3: a failed build is not remembered, so every elevated run builds again |
| N9 | Accepted: a crafted fingerprint can only lower the policy trust |
| N10 | Deferred to M3: `has_classes_hive` is lexical and lists four hives; service accounts with a loaded profile and a user whose classes hive is not loaded are still rewritten. The one predicate of 957c1be is where "is `HKU\<sid>_Classes` loaded" would go. The check that `HKU\S-1-5-19\Software\Classes` is a key and not a link is still open (rig) |
| N11 | Fixed in ba07878: design 4.6 says the merged golden was not made and why |
