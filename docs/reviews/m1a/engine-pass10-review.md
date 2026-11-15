# Review 10: the value-content rule at the choke point (`ScanCtx::seal`)

**Verdict: ACCEPT WITH REQUIRED CHANGES**

Tree reviewed: uncommitted `m1a`, hash over crates+bins `24226d69…` (unchanged at the end of the review; the repo was not touched).

The architecture holds. I found no path from a scanner, from `purge-plan` or from `band.rs` to a Safe value that does not pass through `seal`, and no way Tier A comes back after sealing. What I did find is in the rule itself and in the driver:

- one decidable case of foreign text beside the app's path that still comes out Safe (must-fix 1);
- a defect in `ScanCtx::run` that wrongly demotes every value of a co-removed product in the engine, invisible to the scanner-level tests (must-fix 2);
- three narrower gaps and some test-honesty points (should-fix).

All probes ran on a pristine copy of the tree first (`/home/kaan/purge-target/rev10/probe1.log`). The two trial fixes were applied to the scratch copy only afterwards.

## 1. Can the invariant be broken?

### What I checked and found sound

- **Only one entry into the plan.** `purge_plan::emit::build` is called only from `bins/purge-engine/src/pipeline.rs:884`, with candidates that all came through `ctx.run` at `pipeline.rs:857`. No signature, agent or manual origin feeds the plan in M1a.
- **`seal` is kind-agnostic.** It lowers every positive Tier A evidence whatever its kind, so no evidence constructor (manifest, snapshot, token, chained, dangling) escapes it.
- **`band.rs` cannot raise a tier.** `effective_tier` only applies `at_most`, and `effective_weight` clamps to the table. Safe needs stored Tier A with matching scope.
- **Merge cannot bring Tier A back.** `decide.rs:359` unions evidence of candidates on one canonical target and one owner. Each copy was sealed by a function of (target, registry) only. The only spelling a scanner emits that differs from what it read is REG-ENV's `CurrentControlSet`, and both the fixture and the live source resolve it. A link on the path gives an error, not `NotFound`, so it caps.
- **`purge-plan` adds evidence only to containers.** `EmptyAfterPlan` is pushed at `decide.rs:121`, is dropped from scanner input at `decide.rs:349`, and supports only `RemoveDirIfEmpty`, which fits no value (`band.rs:206`, `action_fits`). `collapse.rs` adds blockers only.
- **Key-level deletes.** `ProvenOwnedSkeleton` requires the key to be value-free. An Inno whole-key record is what the uninstaller would do itself. The table's `touches` also fails any Safe key at or above a planted value.
- **The three exemptions.**
  - Whole-key record: exactly the key, needs a baseline that lacks the key, never a value container. No abuse found.
  - A list entry that is exactly the app's folder: the edit removes only that text; `offer_value` caps entries outside the own place anyway.
  - `<app>\x.exe user text` in command places: behaves as documented, including `<exe>"C:\Users\tester\my tool.exe"` with no blank. `/../` tricks are not even offered.

### MUST-FIX 1: characters no file name can hold are accepted after the app's path

- **Where:** `crates/purge-guard/src/prefix.rs:181` (`is_one_path`), used by `ListEntry::read` and so by `entry_standing` (`framework.rs:568`).
- **Input:** `HKLM\SOFTWARE\Other Vendor\Tool | SearchPath` with an Inno `RegDeleteValue` record and a snapshot entry, holding any of:
  - `C:\Program Files\Mozilla Firefox\browser\x.exe|user text`
  - `C:\Program Files\Mozilla Firefox\browser|user text`
  - `…\x.exe?a=b`, `…\x.exe*user`, `…\x.exe<user>`
  - `C:\Program Files\Mozilla Firefox\firefox.exe|Users\tester\tool.exe`
- **Result:** REF-ANY `DeleteValue`, **Safe, ticked**, all four evidence rows Tier A. The same data in machine `Environment | FX_HOME` is Safe through REG-ENV.
- **Reproduced:** yes (`rev10_probe_text_after_path`).
- **Why it matters:** this is the same class as the five earlier findings. Unlike the folder-plus-text limit it is decidable: `< > | ? *` cannot occur in a path, and the matcher's own `path_from` already cuts at them.
- **Fix tried in scratch:** add `'<', '>', '|', '?', '*'` to the refused characters in `is_one_path`. All probe rows drop to Likely with Tier B. The purge-guard, purge-scan, purge-harvest, purge-plan and purge-engine suites pass; the one failure is `every_target_of_the_rig_deny_file_is_denied`, which needs `vm/truth/deny.json` that I did not copy. I did not re-run the 74-capture replay.
- Add these rows to `hostile()`.

### MUST-FIX 2: `ScanCtx::run` seals a co-removed product's candidates against the main app's fingerprint

- **Where:** `crates/purge-scan/src/framework.rs:647-653`. `common::for_each_app` (`reg_software.rs:987`) scans a co-removed product with a sub-context carrying that product's fingerprint, so `build()` seals correctly. `run` then seals again with the outer context, where the product's path "is not a path of the app".
- **Input:** Firefox with the Maintenance Service co-removed. `HKLM\SOFTWARE\Other Vendor\Tool | Updater = C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`, with a value record and snapshot entry in the product's fingerprint.
- **Result:** `scanner.scan` gives 4 Tier A rows; `ctx.run` gives 0, all marked `unproven: the entry is not a path of the app`.
- **Reproduced:** yes (`rev10_probe_co_removed_through_run`).
- **Direction:** recall only, never unsafe. But "applying it twice changes nothing" is false, and the engine disagrees with every scanner-level test, because `World::scan` calls `scanner.scan`, not `run` (`tests/reg/world.rs:363`). The 74 captures do not show it because no co-removed product there has a Tier A value outside the main app's places.
- **Fix tried in scratch:** in `run`, seal with the fingerprint of `candidate.owner` (the matching `co_removed` fingerprint, else `self.fp`). The probe then gives 4 and 4, and the suites pass. Add a test asserting `run(x) == scan(x)` over all scanners on a world with a co-removed product.

### SHOULD-FIX 3: the rule is skipped by data type

- **Where:** `framework.rs:700-707`. `REG_BINARY` and `REG_NONE` return `None` ("no text"), although the scanners read UTF-16 runs from the same data (`reg_software.rs:1134`).
- **Input:** `Other Vendor\Tool | firefox.exe`, type `REG_BINARY` or `REG_NONE`, bytes the UTF-16 of `"C:\Users\tester\my tool.exe" --with "…\browser\x.exe"`, value record plus snapshot.
- **Result:** Safe, ticked. The same bytes as `REG_SZ` give Likely.
- **Reproduced:** yes (`rev10_probe_nul_and_binary`).
- **Reach:** narrow. A binary value is offered only when its name refers to the app, and it needs the installer's record on exactly that value.
- **Suggestion:** when the UTF-16 runs hold something shaped like a path that is not the app's, cap. Do not cap on any run at all, or `StartupApproved` and similar would lose Tier A.

### SHOULD-FIX 4: text after the first NUL of a `REG_SZ` is not judged

- **Where:** `crates/purge-source/src/types.rs:244` (`text()` stops at the first NUL) with `framework.rs:700`.
- **Input:** `REG_SZ` bytes `C:\…\browser` NUL `C:\Users\tester\tools` NUL, with a value record.
- **Result:** Safe, ticked.
- **Reproduced:** yes.
- **Suggestion:** treat non-NUL data after the first NUL as "not read in full". String readers do not see that text, so the weight is low.

### SHOULD-FIX 5: "a value named after the app passes by its name" is looser than documented

- **Where:** `framework.rs:794-810`.
- **5a, trailing text in the name.** The doc says the name "must be that and nothing else", but a `Below` root match passes with more text after it.
  - Input: names `…\firefox.exe user text` and `…\firefox.exe;C:\Users\tester\tools`, data `"C:\Users\tester\my tool.exe" --with "…\x.exe"`, value record.
  - Result: Safe in a foreign key and in `Run`. Reproduced.
- **5b, a token anywhere in the name, with no record at all.** Id kinds pass on any match (`_ => true`).
  - Input: `Run | my 308046B0AF4A39CB thing` or `Run | C:\Users\tester\tools\308046B0AF4A39CB\notes.txt`, holding somebody else's command line, no installer record, no snapshot.
  - Result: REF-ANY Safe, ticked, on `HarvestedToken:A` plus two Tier B rows. Reproduced. I did not check whether the pre-pass tree behaves the same.
- **Judgement:** defensible as the meaning of `HarvestedToken`, since tokens are GUIDs or long hex. In a command place, though, the value starts a program.
- **Suggestion:** in command places let the program rule decide and do not apply the name exemption. That costs no recall, because the app's own entries pass the program rule. For root and exe names require the whole name, with the MUI suffix allowed.

### Not a finding

- Own place 3 (`App Paths\<leaf>`, `Applications\<leaf>`) matches by file name only (`framework.rs:829-838`), so `Applications\python.exe` of another product counts as own when the app ships a `python.exe`. This predates the pass. I could not construct foreign text reaching Safe through it that is not itself a reference to the app.

## 2. Is the table test honest?

Partly.

- **The enumeration check is real.** A new catalog scanner fails `every_scanner_of_the_catalog_is_in_the_table`.
- **Places are not tied to scanners.** Listing a new scanner in `REGISTRY_SCANNERS` satisfies the test without planting anything where it reads. Measured (`rev10_probe_who_offers`): only 7 of the 13 registry scanners ever produce a candidate in the table. CLS-PROGID, CLS-ASSOC, CLS-FILEEXTS, CLS-TOASTS, CLS-AUMID and CLS-PROTOCOL offer nothing, because the `firefox()` fingerprint has no ProgID, CLSID or AUMID anchors. For those six the table proves nothing; they are protected by the choke point alone.
  - Suggestion: derive coverage from `captured_roots()` (every registry root spec needs at least one place), and assert that every listed registry scanner offers at least once.
- **It tests `scan`, not `run`, and not the plan.** That is stricter for hand-built candidates, but it is why must-fix 2 was invisible. Run the rows through `ctx.run` as well.
- **Data shapes missing:** the must-fix 1 characters, binary and none types, embedded NUL, and any variation of the value name.
- **Exemptions:** `own_entry` is exact. `own_by_record` skips whole rows, key candidates included, for 15 places. That is acceptable given the design, and I would not narrow it.
- The 32 mutations are well chosen. None covers "run uses the wrong fingerprint".

## 3. Token anchors in the snapshot: apply it now

- After sealing, a Token-anchored snapshot row keeps Tier A outside the own place only when the data is exactly the token or the value is named after the app.
- The first case is the one the ProgID/CLSID/AUMID rule exists for: another product's value holding exactly the app's id shows a mention, not who wrote the value. A CLSID is a GUID and gets Tier B; a GUID token should not be treated better.
- In post mode `InPreUninstallRefSnapshot` A/8 alone is enough for Safe, so this is the last "Safe by mention" path.
- I checked the author's measurement: `diffk-on.txt` and `diffk-live.txt` show tier moves only, with "BAND UP / NEW SAFE: 0". The affected rows (`FeatureUsage\AppBadgeUpdated | <hash>`, `Search\JumplistData | <hash>`) stay Safe on `HarvestedToken` for the name.
- Do it as its own commit with a policy version bump, so the golden diffs are attributable.

## 4. Text after a folder outside command places: acceptable documented limit

It is a limit, not a hole, once must-fix 1 is in.

- It needs Tier A, which outside the own place means the installer's record on that exact value.
- What can be lost is plain words after a blank. Anything shaped like a second path is already refused (drive colon, `\\`, a blank before `\`, `/` or `%`, a comma, text after a program file).
- The removal is reversible.
- The same family is also Safe and should be named in the documentation: `…\readme.txt user text`, `…\x.exe=user`, and a no-break space instead of a blank (all reproduced).
- The real fix belongs to the harvest: while the app is installed the entry can be measured against the file system, and `RefSnapEntry.data_hash` can show the data is unchanged since. That is a later milestone.

## 5. Regressions

- **Co-removed products:** must-fix 2.
- **GitForWindows `InstallPath` / `LibexecPath`:** correct, not a regression. In `x0-git-toolsdir` and `x0-git-upgrade` the fingerprint's only root is an `InferredRoot`, and the reason recorded is "the entry is not a path of the app". The installer's value record no longer outweighs an unvalidated root, in live modes only. Post-mode plans are identical in all 74 captures (`difft-on.txt`).
- **`UFH\ARP`:** correct; the record holds entries that are not the app's.
- **Recall cost not in the captures** (reproduced in `rev10_probe_recall`; all have the installer's value record and are now Likely; I did not check whether they were Safe before this pass):
  - `"<app>\firefox.exe" /setup` in a value that is not a command place (the shape of `StubPath`, `ddeexec`, `ShellNew\Command`, an `EDITOR` variable);
  - `rundll32.exe "<app>\x.dll",Start` and `cmd.exe /c start "" "<app>\firefox.exe"` in `Run`.
  - Consider accepting a quoted program of the app followed by arguments in any recorded string value, and deciding deliberately about Windows launchers in front of the app's file.

## Files

- Scratch workspace: `/home/kaan/purge-target/rev10/ws` (currently holds the two trial fixes and the probes)
- Probe tests added to the scratch `hostile.rs`: `/home/kaan/purge-target/rev10/probes.diff`
- Trial fixes for must-fix 1 and 2: `/home/kaan/purge-target/rev10/trial-fixes.diff`
- Probe output on the pristine copy: `/home/kaan/purge-target/rev10/probe1.log`
- Suite run with both trial fixes: `/home/kaan/purge-target/rev10/fixtry.log`
