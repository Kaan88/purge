# M1b review R5b: check of the R5 fix round (`a954d90..5a6fd2b`)

Reviewer changed no repo file, built nothing, ran no VM.

## Verdict

**No blocking finding. The campaign can start.** B1-B3, S1-S4, N1 and N3 are fixed as asked, the scorer still
fails closed, and nothing found would make the next campaign fail for a scripting reason or be unscorable.

One should-fix (S1): the notice exemption is wider than "scored only by K8", because K8 looks at notices only for
`python` on clean and cp. It is a scorer-only change (about ten lines in `m1b.sh`), needs no VM rerun, and can land
before or after the campaign runs as long as it is in before `collect`.

The three interpretations the fixer flagged are all accepted (section 3).

## Should fix

### S1. A notice in any app other than clean/cp `python` is scored by nothing

`vm/truth/m1b.sh:1194-1250` (K8 loop), `vm/rigtool/src/score.rs:49-54`, `:974`.

rigtool takes every `ReportOnly` + `suggest_uninstall` item out of K1-K6 for every app. K8 reads `notices` only for
`clean/python` and `cp/python`. It checks the scan for suggestions on `dirty/python` and `python312-with-313`, and
nothing at all for `python313-with-312`, 7zip, node, vcredist, powershell, temurin.

Failure scenario: an engine regression makes `family_left` false on `m1b-python313-with-312` (the 3.13.17 Launcher
is linked, CPython-3.12 is still registered). The engine suggests uninstalling the Launcher that Python 3.12 still
uses. Before R5 this failed K1/K5/K6 (the key is `kept_owner`); now it is a notice, and no row fails. Wrong advice
passes the gate.

Also in the same loop: on clean/cp K8 accepts any suggestion (`>= 1`, names compared with the score only). It does
not check that the notice sits on the Launcher's Uninstall key or that there is exactly one.

Fix: one K8 row per set, "notices elsewhere: 0": every app score other than clean/cp `python` must have
`notices == []` (a missing list fails), and a scan with a suggestion fails. For clean/cp python, require the
notice target to carry one of `LAUNCHER_CODES`.

## Notes

- **N1** `m1b.sh:1005-1010`, `:1014-1028` (S3 folding). `norm_target` folds every `HKU\S-1-5-21-*` to `HKCU` and
  `scan_blockers` merges the blockers of all scan items under the folded key, then asks for any `DenyListed`.
  Two scan items on the same key path in two users' hives, one DenyListed and one Blocked by `TooLarge`, would
  both pass. Not reachable on the rig (one `tester` profile; the only kept item is the bam value under HKLM, whose
  SID is inside the path and is not folded). Tighter: match the exact target first, fold only as a fallback, and
  require DenyListed on every scan item under the key. The other folds (`HKCR`, `<sid>_Classes`,
  `CurrentControlSet`) name the same key, so they cannot hide anything.
- **N2** `m1b.sh:1645-1667` (`plan_actions`). Action and suggestion are paired with plan items by target, in order.
  Two scan items on one target with different actions could hand the notice to the wrong plan item. All 22
  archived sidecars have no duplicate target (experiment) and the engine merges same-target candidates, so this is
  theoretical. Pre-existing for `action`; it now also decides the exemption.
- **N3** `on_launcher` (`m1b.sh:1183-1189`) matches the three brace GUIDs and three files. A packed-GUID key
  (`Installer\Products\<packed>`) or the Launcher's Package Cache folder of another version is not matched. It is
  a new check, so nothing is loosened; K5 still catches those items through the label file.
- **N4** Not verified here: the cargo tests (no `ci-5a6fd2b.log` yet in the evidence folder), `rig-selftest.ps1`
  (read only), the engine on a VM.

## 1. Findings of R5, one by one

| Finding | Result |
|---|---|
| B1 notice | `is_notice` needs `ReportOnly`, a non-empty `suggest_uninstall`, not preselected, not Safe. The field reaches the plan only through `plan_actions`, which deletes any value the plan brought and copies the scan item's evidence fact. The engine writes that fact in one place (`sys_burndeps.rs:467-489`, always `ReportOnly`). A deleting action, a Safe band or a preselected item is scored as before (rigtool test covers each). Remaining width: S1. |
| B2 dirty python | K8 G3 expects 0 suggestions and no Launcher item outside Blocked with a deleting action. On the archived `m1bd-python` sidecar: 0 and 0, PASS (experiment). |
| B3 cold scan | Cache moved before each cold M1b step; `budgets/3` with `cold_cache_steps`; K14 fails a step that is not `moved`/`absent`, so a `budgets/2` record fails (experiment on the archived budgets: "cache state None" for both steps). |
| S1 rigtool binding | `rigtool_check` before collect and replay; BIND needs both hashes equal. See section 2. |
| S2 | `main_is_pre` is `None` without a pre record; the check at `m1b.sh:752` is applied to trap runs only, so app runs without `pre` are not affected. |
| S3 | A Blocked danger item needs a `DenyListed` blocker in the scan sidecar; no sidecar, no item or another blocker fails. See N1. |
| S4 | Three tests compare the shared-index harvest with a target harvest and with the entries-only index (read, not run). |
| N1, N3 | Done as asked. |

## 2. Campaign risks checked

- **rigtool binding** (experiment): `vm/rigtool/target/release/rigtool.exe` (built 11:55, after the commit at 11:54)
  reports `source-sha256 391c9dc8...447c91`; the same hash computed over the tree with the `rigtoolsrc` algorithm
  is identical; `git status --porcelain -- vm/rigtool` is empty (`target/` is ignored). `sha2` was already in
  `Cargo.lock`, so the new build dependency does not dirty the lock file. The campaign's rigtool build
  (`rigtool-5a6fd2b.log`) goes to the default target dir in the main checkout, which is where `m1b.sh` looks.
  `core.autocrlf=true` is handled by the CRLF normalisation on both sides.
- **Selftest**: `bash truth/m1b.sh --selftest`: 0 failures; tree clean after.
- **Archived gate3 evidence under the new scorer** (experiment, output in the scratchpad): the K1 and K8 vcredist
  rows find the bam value's blocker as `DenyListed reg.hklm.system` on clean and dirty, so the S3 match works on
  real target spellings. K8 clean/cp python fail with "no notices list", as they should for an old score.
- **Budgets**: the archived run was cold in every round (memory cache): added scan time 2.19 s and added harvest
  time 4.80 s, both under the 6.5 s cold limit, so a truly cold scan step is not expected to fail on time.
  `Write-RigLog` writes to the host, so `Move-M1bCacheAside` returns the hashtable alone. Aside names carry the
  step and milliseconds, so the two moves cannot collide.
- **K8 on G8**: `cp/python` rows are produced; the scan sidecar is collected for cp like the other sets. R5 found
  the Launcher records on `m1bcp-python` equal to rig-base, so the suggestion is expected there.
- **Evidence shape**: scan sidecar `evidence[].detail` is an object of string facts in all archived sidecars, which
  is what `suggest_of` reads.

## 3. The fixer's interpretations

- **B2 allows Blocked Launcher items on dirty**: accepted. Blocked is the design's "stays Protected"; an item
  listed lower still fails K5 through the label file.
- **B1 excludes Safe and preselected ReportOnly from notices**: accepted, it is the stricter reading. The engine's
  policy never gives `ReportOnly` Safe, so the real suggestion is not affected.
- **K8 also runs on G8 python**: accepted. Without it the cp notice would be scored by nothing (the S1 pattern).
