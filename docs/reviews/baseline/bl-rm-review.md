# BL-RM review: gate M round 2 (local baseline measurement)

Date 2026-11-21. Reviewer: Fable. Branch `baseline`, HEAD ba4782d. Read-only review; no code changed, no VM run.

Inputs: `docs/BASELINE_LOCAL_DESIGN.md` (3.4, 4, 5, 8), `docs/BASELINE_LOCAL_DESIGN.json` (BL-RM), `docs/DECISIONS.md`
(Post-M1b), `kb/baselines/view.json`, `vm/rigtool/src/baseline_diff.rs`, `crates/purge-index/src/baseline.rs`,
`crates/purge-index/src/local_baseline/build.rs`, `vm/RIG.md` 8a, the reports `vm/truth/baseline-local/bl-r1-cleanpro.json`
and `bl-r2-inbound.json` (+ `-build.json`), the run folders, `E:\purge-build\gate-evidence\bl-gate-m\round2\r1.log`.

How it was checked: the reports were read in full for the S2-passing areas (every merged false-absent key), the
`shared_shape_false_absent` lists were grouped and read, and the whole diff was recomputed from the four `.tsv.gz` files
with an independent normaliser written for this review (Python, no twin rule). The false-absent COM registrations were
looked up on the host registry (read-only `reg query`).

## Verdict

- **No B finding. Wave 4 (BL-VIEW, BL-POLICY) may start.**
- **First `view.json`:** `merged: true` for seven areas: `classes-wow6432node`, `classes-clsid`, `classes-interface`,
  `classes-appid`, `software-clients`, `software-wow6432node`, `software-vendor`. `local: true` for none (Local is
  presence-only, an outcome 8.3 S3 accepts). `system` and `hku-default` pass the numbers but should stay unmarked
  (S1, S2 below). `classes-typelib` stays unmarked (passes on R2 only).
- Seven S findings to settle before or inside wave 4 / before BL-GATE, nine M findings.

## The numbers hold

Independent recomputation (no twin rule) against the reports:

| | truth in scope | local covered | merged covered | report local / merged |
|---|---|---|---|---|
| R1 | 309,929 | 218,658 | 274,522 | 218,708 / 274,523 |
| R2 | 275,869 | 208,056 | 263,935 | 208,105 / 263,935 |

The differences (50 and 49 local, 1 merged) are the 64-bit twin rule, all in `software-wow6432node`; every per-area
truth count is identical. No key is unmatched, no truth key is out of scope. `shared_shape_false_absent` has 520 and
409 entries, equal to `shared_shape_false_absent_local`, so that list is complete. The first-200 lists are truncated
only in failing areas; in every S2-passing area the merged list is whole (at most 48 keys).

## Question 1: the three attack questions

### 1a. Are the false-absent lists complete and honestly classified?

Complete: yes, for the shapes the design names. Classified: the counts are right, the labels are not.

Every merged false-absent key in the S2-passing areas is a whole registration, never a subkey under a covered root:

| Area | R1 roots (of) | R2 roots (of) | What they are |
|---|---|---|---|
| `classes-clsid` | 5 (6,944) | 5 (6,852) | R1: Microsoft Copilot `notification_helper.exe`, `notification_click_helper.exe`, its elevation service; two not on the host. R2: Windows Defender platform `MPUXAGENT.DLL` (MpUx agent, PSFactoryBuffer); three not on the host |
| `classes-interface` | 2 (26,254) | 4 (25,303) | R1: the Copilot elevation service's two interfaces. R2: `IMpUxUserSessionAgent`, `2`, `3` (Defender), one unknown |
| `classes-typelib` | 2 (257) | 0 (254) | R1: the same two Copilot interfaces' type libraries (10 keys, 0.646 %: the R1 fail) |
| `classes-appid` | 2 (569) | 2 (550) | R1: Copilot notification helper, `MicrosoftCopilotElevationService`. R2: `MpUx Agent Host`, one unknown |
| `classes-wow6432node` | 4 | 2 | the 32-bit copies of the same registrations |
| `software-wow6432node` | 29 keys | 48 keys | `.NETFramework\Fusion\References`, `NGenService\Roots`, `EdgeUpdate\Clients` and `ClientState`, `Uninstall\Microsoft Copilot`, `ClickNote`, `Lighting\Inbox` |

So the residue in the passing areas is not "a component manifest S1 missed, or OOBE". It is **Microsoft products that
are serviced apart from the Windows build** (Copilot and Edge through EdgeUpdate, the Defender platform, .NET's NGen
and Fusion state). The report's `expected_source` says "S1 (component manifests), else OOBE / first start: a
neighbour" for all of them; that label comes from the root and misnames the class that matters most for a real host
(finding S3).

Some truth keys counted as false absent are not Windows keys (M1), all in the Inbound truth: `HKU\<sid>\Software\
Google\Chrome\NativeMessagingHosts\com.<user>.downloadmanager` for certain, and most likely the three keys of the
per-user `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` chain (what a 32-bit per-user installer
leaves). `HKU\<sid>\Software\ChangeTracker` (R1) is a real Windows key
(`AppModel\RegistryWriteVirtualization\ExcludedKeys` names it; it exists on the host), so that miss is real.

### 1b. Is any area marked that should not be?

Nothing is marked yet. Of the ten areas the numbers would mark, two should not be:

- **`hku-default`** (the only S3 pass, and an S2 pass): the 100 % is true by construction, finding S1.
- **`system`**: 22 keys, 13 of them known only from the neighbour, no A consumer, finding S2.

`classes-typelib` must stay unmarked under the "both VMs" rule; that is the rule working as written, although the
fail is two registrations (M5).

### 1c. Do the leave-one-out pairs say anything about the host's case?

Less than 8.2 claims. Three limits:

1. **It is one pair measured in two directions**, not two pairs (M9). For keys every Windows 11 has, each file covers
   the other trivially. The informative part is only the two set differences.
2. **Both truths were captured on the same day** (2026-11-11T15:51Z and T21:45Z) with nearly the same Edge and
   Defender versions. The residual class (S3) grows with calendar time and product versions, not with build
   distance. A host scanned months after the newest shipped baseline is a harder case than Δ240 builds on the same
   day, and neither run measures it. "Harder than the host's case" in 8.2 is not shown.
3. **The neighbour rule does not give most real hosts the host's case** (S6). A retail 26100.x host matches rule 1
   (same build) and gets only `EnterpriseSEval-26100.1742`: R1's direction (rich edition, LTSC neighbour), where merged
   coverage is 88.6 %.

What the pairs do say: in the seven recommended areas the union is stable in both directions (pooled 99.966 % and
99.953 %, 56 and 77 false-absent keys of 167,162 and 163,209), with zero shared-container misses. For this host
(26300.9974, both neighbours qualify, one the same edition at Δ40) the expectation is at least as good; it is an
expectation, and R5 has no truth to test it against. S3 proposes a proxy.

## Question 2: the flags

Strict 8.3 on both VMs gives merged = {classes-wow6432node, classes-clsid, classes-interface, classes-appid,
software-clients, software-wow6432node, software-vendor, system, hku-default}, local = {hku-default}.

**W1's 99.8 % does not decide marking.** 8.4 ends with "the first `view.json` marks exactly the areas that pass S2
(merged) and S3 (local)"; W1 is a worth-it criterion judged in BL-GATE. Read per area, `classes-appid` (99.65 /
99.64) and `software-wow6432node` (99.78 / 99.63) miss 99.8 %; read pooled over the marked areas it holds on both
VMs. The design should say which reading is meant; pooled is the sensible one (S4). The two areas' misses are two
COM registrations of 570 and run-time .NET / EdgeUpdate state; neither is a reason to leave them unmarked.

Recommended flags and why they differ from the strict list:

| Area | merged | local | Note |
|---|---|---|---|
| `classes-wow6432node` | true | false | 10 / 4 keys, all 32-bit copies of the registrations above |
| `classes-clsid` | true | false | 0.07 % of roots on both VMs |
| `classes-interface` | true | false | |
| `classes-appid` | true | false | 2 registrations each; passes |
| `software-clients` | true | false | 89 keys; 10 (`StartMenuInternet\Microsoft Edge`) known only from the neighbour |
| `software-wow6432node` | true | false | 99.7 % of the area is `WOW6432Node\Microsoft`; vendor containers: 0 merged misses |
| `software-vendor` | true | false | 109 / 106 keys; 40 known only from the neighbour (mostly `Policies\Microsoft\…`) |
| `system` | **false** | false | S2 |
| `hku-default` | **false** | **false** | S1 |
| all others | false | false | fail S2 / S3 |

Risk despite the numbers:

- **Small areas cannot show 0.5 %.** Zero misses in 109 keys bounds the miss rate at about 2.7 % (95 %), in 89 keys
  at 3.3 %, in 22 keys at 12.7 %; about 600 keys with zero misses are needed to support 0.5 %. `software-vendor` and
  `software-clients` are still worth marking: they are where vendor skeletons and client registrations live, the
  zero-tolerance shared-shape rule did hold, and the cap keeps a miss at one unticked Likely item. They must never
  be candidates for the cap lift of 8.5 on evidence of this size; write that into 8.5 (a minimum truth count).
- **`software-vendor` passes only with a neighbour.** Local alone misses `SOFTWARE\Mozilla` and
  `SOFTWARE\Mozilla\NativeMessagingHosts` (Defender's browser-extension host writes them). S3 correctly fails there,
  which is the gate working. It also means trust Local must stay presence-only in this area for good.
- Nothing in the seven areas makes absence usable for something worse than the capped offer: the misses are whole
  registrations whose server paths lie in Copilot's or Defender's own directories, which the other conjuncts of the
  COM proofs look at.

## Findings

### S (serious: settle before wave 4 ends or before BL-GATE)

**S1. `hku-default` passes by construction; do not mark it.** S3 reads the live `HKU\.DEFAULT`; the truth is that same
hive of that same snapshot (S3 keys 628 / 618, truth 625 / 618, coverage 100.0000 %). The run cannot produce a false
absent there, so it is no evidence. The neighbour alone covers 454 of 625 (72.6 %) and 454 of 618 (73.5 %), which is
the honest size of the uncertainty. On a host the question is "which keys does Windows add to `HKU\.DEFAULT` after
the cached build"; the source id (`SourceStamp::id`, `build.rs:154`: manifests, default hive, S4 package names) does
not cover S3, so the cached S3 part never refreshes within one id and its age is unbounded. Decide in BL-VIEW /
BL-CACHE: either S3 is read live when the view loads (cheap, about 3,000 records; then an existing key under
`HKU\.DEFAULT` is always present and the area can never give absence, so the flags are moot), or S3 stays cached and
the area stays unmarked. Either way: `hku-default` false / false, and 8.3 should say that an area whose local source
is the truth's own hive cannot pass S3 by a same-snapshot run.

**S2. `system` should not be marked.** 22 truth keys (`CurrentControlSet`, `Hardware Profiles\…`, `Policies\…`,
`ServiceState`); local knows 9, the other 13 come from the neighbour. Design 3.1 says the A consumers do not ask
about `HKLM\SYSTEM`. Marking buys nothing and puts inferred absence into the hive where a wrong delete costs most, on
a sample that cannot support the threshold. Add to 8.4: an area is marked only if it passes S2 **and** an A consumer
asks there.

**S3. The residual class is time-dependent and unmeasured; the promised drift run is missing.** See 1a and 1c. On a
host the false-absent set in the COM areas will be the registrations of Copilot, Edge, WebView, the Defender
platform, OneDrive and Store-delivered COM servers that are newer than every shipped baseline. DECISIONS 2026-11-17
item (4) puts "a Windows Update drift run inside BL-MEASURE"; round 2 has none. Before BL-GATE, one of:
(a) the drift run (a rig VM after Windows, Defender and Edge updates, diffed against its own older truth plus the
neighbour); (b) in the elevated R5, for the marked areas, list the live host keys the merged view calls absent whose
server path or name is Microsoft's (`%windir%`, `ProgramData\Microsoft\Windows Defender\Platform`,
`Program Files (x86)\Microsoft\…`): a proxy false-absent list where no truth exists. Also give `expected_source` a
value for this class so the next report does not call it OOBE.

**S4. W1 over the scope cannot be met and should be restated now; wave 4 starts anyway.** 73 % (R1) and 66 % (R2) of
the merged misses lie under `CurrentVersion\{AppModel, Component Based Servicing, SideBySide, Appx}`; about half of
all merged misses carry a version, hash, package family or SID in the key name (17,021 of 35,407; 6,479 of 11,934).
No neighbour of another build can hold those names. Even without those four subtrees the scope is at 96.1 % / 98.3 %.
The 99 % was an estimate in 8.2 ("to be confirmed or refuted"); it is refuted for a structural reason, not because
the union is weak where it is used. Restate W1 as: pooled merged coverage of the marked areas at least 99.8 % on
both VMs (holds: 99.966 / 99.953), scope coverage reported, not gated. No design change is needed for safety.
Presence-only is not indicated: that switch belongs to W2 (below 50 %), which is not measured yet. Because the
strict flags leave ProgIDs, `.ext`, shell / shellex, TypeLib, `CurrentVersion` and every `HKU\<sid>` area unmarked,
W2 is the criterion at risk. Do a cheap pre-estimate at the start of wave 4, outside the engine: take the key
candidates the exact view offers in the frozen M1b replay plans and count how many lie in a marked area and are
absent from local ∪ neighbour. If that is far under 80 %, S5 becomes urgent before wave 5's critical packages.

**S5. The area table is too coarse exactly where the A consumers are.** `classes-progid` is "ProgIDs and the rest of
Classes" and fails at 24.6 % / 12.9 % because of AppModel state, not ProgIDs: `Classes\Extensions` (1,763 / 1,166
misses), `Classes\Local Settings` (1,419 / 122), `PackagedCom`, `CID`, `CID.Local`, `SvcId`. What-if computed for this
review (not a result to mark from):

| Sub-area | R1 truth / misses / shared | R2 truth / misses / shared | S2 |
|---|---|---|---|
| AppModel state under Classes | 5,152 / 3,367 / 0 | 2,096 / 1,380 / 0 | fail |
| `AppX<hash>` ProgIDs | 102 / 27 / 9 | 78 / 3 / 1 | fail |
| the remaining ProgIDs | 8,514 / 5 / 0 | 8,527 / 1 / 0 | pass on both |
| `classes-shell` without `AppX<hash>` | 2,522 / 0 / 0 | 2,564 / 12 / 8 | R2 fails (`.appx`, `.msix` … `\ShellEx`) |
| `CurrentVersion\{Uninstall, Run, RunOnce, Shell Extensions, Explorer}` | 0 misses | 2 misses (Explorer) | pass, but 1 to 18 keys each except Explorer |

A round 3 that needs no VM (edit `view.json`, rerun `rigtool baseline-diff` on the kept files) could split
`classes-progid` into AppModel state, `AppX<hash>` ProgIDs and the rest. The split is structural (rigtool's own
`STRUCTURAL` list already treats `Local Settings` as not a ProgID), but cutting areas after seeing the data invites
fitting: state the rule before the rerun, and treat a newly cut area as provisional until a third baseline confirms
it. Not needed for wave 4 to start; needed if the W2 pre-estimate is low.

**S6. Neighbour rule 1 starves same-build hosts.** 4.1: "same build, other ubr: all of them qualify; otherwise the
nearest below and above". A 26100.x Home or Pro host gets only the LTSC file and never `Professional-26340.9882`
(Δ240, inside the limit). A neighbour only adds presence (L1), so the fix is safe: take the same-build files first,
then fill up to `max_count` with the nearest others inside `max_build_distance`. Fix in BL-VIEW and its tests.

**S7. W4: the cold miss is acceptable as a number, but two things around it are not settled.**
- *The settled pass is the third read in one boot.* The standby list is emptied, but Defender has already scanned
  all 31,647 manifests in the cold and warm passes, so 34 s / 14 s is not shown to be a first read on a quiet
  system. Add a pass that is the first build of a boot after the settle (restore, boot, settle, build once).
- *The cache will be rebuilt far more often than "once per (edition, build, ubr)".* The source id holds the sorted S4
  package full names, so every update of an inbox Store app gives a new id and throws away the S1 part too. Round 1
  saw exactly that within minutes of network access (S4 not-inbox 14 → 18). On a real host that is weekly, and each
  time the first scan may run at trust None. In BL-CACHE key the parts apart: S1 by the manifest directory stamp, S2
  by the hive stamp, S4 by the package names (91 manifests, fast), S3 live (S1 above).

  With that, the budget question answers itself. The cold read is I/O yielding at background priority (R1 cold:
  649 s of thread time in `read`, 32 s in `expand` + `parse`; settled: 77 s; warm: 10 s), not the builder's cost.
  Keep the design (build when the broker starts, never block a scan), restate the budget as "settled first build at
  most 60 s on the rig VM, cold after boot reported", and when a scan is waiting for the view raise the build to
  normal I/O priority and let the UI offer a rescan when it completes. A build at every logon is not warranted: it
  puts a resident task on the machine for a cost paid once per servicing change, and that is a user decision for the
  M3 broker, not something gate M shows a need for.

### M (minor)

- **M1. The shipped truths are not clean.** Both hold VirtualBox Guest Additions keys (`HKLM\SOFTWARE\Oracle\VirtualBox
  Guest Additions`, its `Uninstall` key, `WOW6432Node\Oracle`, driver entries); the Inbound truth also holds
  `com.<user>.downloadmanager` under Chrome's and Edge's `NativeMessagingHosts` and a per-user `Wow6432Node\…\Uninstall`
  chain. Because each VM is the other's neighbour, the VirtualBox keys count as "covered by merged"; in
  `software-vendor` two of the four local shared-shape misses (`Oracle`, `Oracle\VirtualBox Guest Additions`) are
  covered only that way. Without them the area still passes, so the conclusion stands. One of R2's four
  `hku-software` misses is certainly such a key and the other three probably are. Give `baseline-diff` an exclusion list for known rig keys, and
  consider scrubbing them from the shipped files (today they also block `SOFTWARE\Oracle` on Exact hosts).
- **M2. The normaliser mirror is faithful but only by inspection.** `baseline_diff.rs` `fold`, `normalise_folded`,
  `twin`, `in_scope` match `baseline.rs` `normalise_key`, `key_forms`, `key_in_scope` line for line, and this review's
  independent recomputation agrees. The equality with the engine was checked once by hand (RIG.md 8a). Add a test
  that runs both over one corpus. The diff uses the twin rule of `has_key`; `has_key_exact_view` (no twin for
  `WOW6432Node\<vendor>`) is stricter, but merged coverage through a twin is 1 key in R1 and 0 in R2, so it changes
  nothing here.
- **M3. S1 floor 15,000.** Honest and documented; Inbound has 18,489. A listing that ends early without an error is
  caught only by this absolute floor (the 99.9 % rule is over the files listed), and on a 35,842-manifest host 15,000
  is 42 %. A relative check would scale: the manifest count against the count of `SideBySide\Winners` keys.
- **M4. S3 allow-list.** One exact path, confirmed by round 2's `unreadable-keys=` on both VMs; the key itself is
  recorded as a `K` record. The DACL evidence is from the host's `HKCU` twin, not from the VMs' `HKU\.DEFAULT` key.
  The truth cannot read below it either, so nothing below `ProtectedRoots` is measured. The view should answer
  `Unknown` at or below any key named in `unreadable-keys`. Moot while `hku-default` is unmarked.
- **M5. Keys are counted, not registrations.** `classes-typelib` fails R1 on two registrations (10 keys of 1,547)
  while `classes-appid` passes on two (2 keys of 570). Report roots beside keys in the COM areas.
- **M6. The budget machine.** Design 5 says "120 s on a 2-vCPU VM"; both runs report `cpus: 4` and the log prints
  "budget 120 s on 4 CPUs". Align the text or the VM.
- **M7. 45 % of the local file's `K` records are outside the capture scope** (189,876 of 423,030 on R1, almost all
  `HKLM\SYSTEM\DriverDatabase`). Absence is never answered there. If no P site asks there either, dropping them
  roughly halves the key set the view loads (3.1 s against 1.5 s).
- **M8. Shape noise.** `shell` matches `Local Settings\…\Shell\Bags\N\Shell` (a shell bag, not a verb container). It
  errs to the strict side.
- **M9. Wording of 8.2.** "R1 and R2 are each a leave-one-out test" should say it is one pair in two directions, and
  the S3 by-construction case (S1) should be named.

## Question 5 in short: is the tooling wrong or overclaiming?

Wrong: nothing found; the numbers reproduce. Overclaiming: (1) `hku-default` at 100 % (S1); (2) "harder than the
host's case" (1c, S3); (3) the settled pass as the builder's own cost (S7); (4) `expected_source` for the
separately serviced products (S3); (5) clean truths (M1). The S3 allow-list, the S1 floor and the scope are sound.
The source id not covering S3 does no harm to the rig check (a change in `HKU\.DEFAULT` between passes would show
as a determinism failure, the strict side; none occurred) but matters for the cache (S1).

## Recommendation

1. Write `view.json` with the seven `merged: true` flags above and no `local: true`. Record in DECISIONS why `system`
   and `hku-default` are left out although they pass.
2. Start wave 4. In BL-VIEW: neighbour fill rule (S6), `Unknown` below unreadable keys (M4), S3 live or unmarked
   (S1). In BL-CACHE: per-source keys (S7).
3. At the start of wave 4, outside the engine: the W2 pre-estimate from the frozen replay plans (S4). If low, round 3
   with the finer Classes areas (S5).
4. Restate W1 (S4) and the W4 budget (S7) in the design; add the minimum-count and "a consumer asks there" rules
   (S2, Question 2).
5. Before BL-GATE: the drift run or the R5 proxy list (S3), a first-read settled pass (S7), the elevated R5.
