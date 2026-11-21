# W2 pre-estimate (wave 4 start, outside the engine)

2026-11-21, on `baseline` at 5e480c5. Asked for by review BL-RM S4 / section 3 item 3 and the DECISIONS 2026-11-21
coordinator row "Wave 4 ... starts". Read-only: no engine run, no VM. Scripts and raw output (not committed):
`%TEMP%\claude\…\scratchpad\w2\` (`w2.py`, `report.py`, `cross.py`, `report-current.txt`, `report-m1a.txt`).

**Result: W2 ≈ 1.4 % (2 of 140) on the current-engine plans, 0 % (0 of 291) on the M1a-era plans. That is far
below the 50 % drop line, not just below 80 %.** Every loss comes from an unmarked area. No candidate is lost to extra
presence: none of them, and none of their remaining subkeys, is in local ∪ neighbour on its own VM. Re-cutting
`classes-progid` (S5) does not move the figure. Only marking `classes-ext` does, and `hku-classes` for per-user
installs. S2 currently forbids both.

## 1. Method

**Plans.** These are the exact-view scan sidecars, in two samples:

- *Current engine* (the gate's plans):
  - the five G1 replays, `vm/runs/m1b-replay/<id>/replay.scan.json` (vscode, git, firefox, npp, 7zip; all Inbound,
    EnterpriseSEval 26100.1742; this checkout's engine at replay time, 2026-11-19);
  - the M1b gate runs `m1b-*` (Inbound clean), `m1bd-*` (Inbound dirty) and `m1bcp-*` (Clean-Pro, Professional
    26340.9882), `plan-purge.scan.json`.

  Trap runs are counted separately, because they are synthetic.
- *M1a-era*: `f0-*`, `f0d-*`, `f1d-*`, `f2d-*`, `lx*-*` `plan-purge.scan.json`. These were made by the engine of that
  time, not this checkout, so they are a second opinion only.

`vm/truth/frozen/<id>/plans/` holds only `bcu` / `clone` / `ut` plans and no Purge plan, so the Purge plans above were
used instead.

**Candidate selection (the stand-in for "exact offers, none does not").** A candidate is a `RegKey` item that meets
all of these:

- it is offered (band Safe or Likely);
- it carries evidence of an absence-dependent kind from the seal list in design 4.4: `ProvenOwnedSkeleton`,
  `ComKeyOwnership`, `HarvestedToken`, key-scope `InstallerManifest` or key-scope `ChainedRef`;
- it has no other Tier A/B evidence ("pure").

Items with other Tier A/B support were left out, because the none view offers them too. That excludes
`HKLM\SOFTWARE\Mozilla\Firefox` in every firefox run and `…_Classes\Applications\notepad++.exe` in `lx*`.

**Kept by the merged view.** The target key and every subkey that still exists after uninstall must all meet both
tests below. The subkeys come from `snap-<run>-2.tsv.gz`, because the skeleton proof needs "neither the key nor any
remaining subkey" (`skeleton.rs`). Checking the target key alone gives the same numbers.

- (a) The key lies in an area with `merged: true` in `kb/baselines/view.json`. The area is the first one that matches,
  with the ext / shell shape rule.
- (b) The key, or its 64-bit twin, is in neither set:
  - Inbound plans: `vm/runs/bl-r2-inbound/local-cold.tsv.gz` ∪ `Professional-26340.9882`.
  - Clean-Pro plans: `vm/runs/bl-r1-cleanpro/local-cold.tsv.gz` ∪ `EnterpriseSEval-26100.1742`.

Keys are normalised by a Python mirror of `vm/rigtool/src/baseline_diff.rs`: fold, roots, control sets, `<sid>`,
`_Classes`, `.DEFAULT`, `WOW6432Node\Classes`, the twin rule and `in_scope`. Only `K` records are read.

**Positive control.** None of the 464 selected candidates, and none of their subkeys, is in the exact baseline of its
own VM. That matches the engine's exact proofs and shows that the normalisation lines up. Spot check: `Classes\.txt`
is in all four files, and `Classes\.bash` is in none.

## 2. Results, current engine

| Plan | Exact-view key candidates | Kept by merged | Lost: area unmarked | Lost: in local ∪ neighbour |
|---|---|---|---|---|
| vscode (replay, Inbound) | 136 | 0 | classes-ext 135 (105 `.ext`, 30 `.ext\OpenWithProgids`), hku-classes 1 (`_Classes\vscode`) | 0 |
| git (replay, Inbound) | 2 | 0 | classes-shell 1 (`LibraryFolder\background\shell`), classes-progid 1 (`sh_auto_file`) | 0 |
| m1b-python (Inbound) | 1 | 1 (`WOW6432Node\…\Uninstall\{73831AC2-…}`, software-wow6432node) | 0 | 0 |
| m1bcp-python (Clean-Pro) | 1 | 1 (same key) | 0 | 0 |
| firefox, npp, 7zip, and every other gate run | 0 | – | – | – |
| **Total** | **140** | **2 (1.4 %)** | **138**: classes-ext 135, hku-classes 1, classes-shell 1, classes-progid 1 | **0** |
| Trap runs (3 × 8, synthetic) | 24 | 6 (25 %): CLSID and Interface traps | classes-typelib 6, software-microsoft 6 (`Tracing\7zFM_*`), classes-shell 3, system-services 3 | 0 |

## 3. Results, M1a-era plans

| Plan | Candidates | Kept | Lost: area unmarked | Lost: present |
|---|---|---|---|---|
| f0-vscode (Clean-Pro) | 137 | 0 | classes-ext 136, hku-classes 1 | 0 (the area already fails) |
| f0-vscode-user (Clean-Pro) | 137 | 0 | hku-classes 137 | 0 |
| f0/f0d/f1d/f2d-git | 4 × 2 | 0 | classes-shell 4, classes-progid 4 (`sh_auto_file`) | 0 |
| f0d/f1d/f2d-vscode-user (Inbound) | 3 × 3 | 0 | hku-classes 6, classes-progid 3 (`Applications\code.exe`) | 0 |
| **Total** | **291** | **0 (0 %)** | classes-hku 144, classes-ext 136, classes-progid 7, classes-shell 4 | 0 |

## 4. What-ifs (marking areas; not a result to mark from)

| Also marked | Current engine (140) | M1a-era (291) | Lost to presence once marked |
|---|---|---|---|
| none (`view.json` as committed) | 1.4 % | 0 % | – |
| S5: plain ProgIDs (`classes-progid` without AppModel / `AppX<hash>`) | 1.4 % | 0 % | 0 |
| `classes-shell` | 2.1 % | 1.4 % | 0 |
| `hku-classes` | 2.1 % | 49.5 % | 0 |
| `classes-ext` | **97.9 %** | 44.3 % | M1a: 7 on Clean-Pro (below) |
| `classes-ext` + `classes-shell` + S5 ProgIDs + `hku-classes` | 100 % | 97.6 % | M1a: 7 |

- **S5 does not move W2.** The only plain-ProgID candidates are `sh_auto_file` (git) and `Applications\code.exe`
  (vscode-user). After uninstall, their remaining subkeys `shell`, `shell\open` and `shellex` fall into
  `classes-shell`, which is unmarked. So the whole proof still fails, and they stay lost even if only the ProgID area
  is marked. S5 is still worth doing for W1 and S2, but it is not the W2 lever.
- **`classes-ext` is the lever.** It decides 135 of 140 candidates. It is unmarked because S2's shared-shape rule
  (= 0) fails with 5 merged false-absent keys on each VM:
  - R1: `.cpio`, `.mtree`, `.nupkg`, `.uu`, `.xar` `\OpenWithProgids`;
  - R2: `.appx`, `.appxbundle`, `.msix`, `.msixbundle` and `.xml\OpenWithProgids`

  (from `vm/truth/baseline-local/bl-r{1,2}-*.json`). These have the same shapes as the vscode candidates (`.ext` and
  `.ext\OpenWithProgids`). Marking it is a safety decision about exactly the keys W2 counts, not a cosmetic re-cut.
- **Extra presence shows up only once `classes-ext` is marked.** It costs the M1a f0-vscode plan (Clean-Pro) 7
  candidates:
  - local only: `.ini\OpenWithProgids`, `.txt\OpenWithProgids`;
  - neighbour only: `.xml\OpenWithProgids`;
  - both: `.log`, `.ps1`, `.psd1`, `.psm1`, all four whose `OpenWithProgids` is in local.

  In other words, the 26340 manifests and the 26100 neighbour call these Windows' own, while the Clean-Pro snapshot
  baseline did not have them. As a cross-check, the 136 Inbound vscode candidates judged against the Clean-Pro sets
  (r1 ∪ EnterpriseSEval) lose 6, all in r1 local: `.ini`, `.log`, `.ps1`, `.psd1`, `.psm1`, `.txt` `\OpenWithProgids`.
  That is ~5 %, which belongs to W3 and does not threaten W2.

## 5. Approximations (all of them)

1. **The "none view does not offer" set is guessed from evidence kinds, not computed.** A none-view replay (R3)
   decides it. Two directions are uncertain:
   - Design 4.3 gives the key-record site "`Unknown` → Tier B, as today", and `ComKeyOwnership` an X-SYSTIDY Tier B
     path. So the python Uninstall key (key-scope `InstallerManifest`) and the CLSID / Interface traps may also be
     offered by the none view. If they are, they leave the denominator, and the current-engine figure becomes 0 of
     138.
   - Mixed items were excluded. If the none view in fact drops some of them, they would enter the denominator. The
     only real one is `Mozilla\Firefox`, which is software-vendor and would be kept.
2. Every candidate gets the subtree (skeleton) proof, although only `ProvenOwnedSkeleton` needs it. Checking the target
   key alone gives identical totals.
3. "Remaining subkeys" are read from the run's own post-uninstall snapshot (snap 2). The engine sees the live
   registry at scan time, which is the same moment in the rig.
4. The local baseline is the `local-cold` build. Warm and settled builds were not used: they are the determinism pair,
   with the same keys expected.
5. The Python fold handles non-ASCII letters with Python's case mapping minus the Windows keep-apart ranges. Every
   candidate key is ASCII, so it has no effect.
6. The S5 what-if marks all of `classes-progid`. That is equivalent here, because no candidate lies in AppModel state
   or under `AppX<hash>`.
7. Counts are per plan, not per unique key. The python key appears in two plans, one per VM. The dirty-base and
   repeat M1a runs repeat the git and vscode-user keys.
8. **The sample is tiny and lopsided.** VS Code contributes 136 of 140 (current) and 274 of 291 (M1a); only four apps
   have any candidate at all. The figure says "W2 is decided by `.ext` and per-user Classes". It is not a stable
   percentage.
9. The M1a-era plans come from an older engine, and its absence sites may differ from today's.
10. The trap runs are planted objects, not app leftovers. They are shown only to illustrate which COM areas the
    marking reaches.

## 6. Reading for the coordinator

- As committed, the merged view would offer almost nothing that only absence proves: about 1 % now, and 0 % on the
  M1a corpus. By 8.4 that is the presence-only outcome unless the area table changes. Part of the gain is real,
  because the python Uninstall key in `software-wow6432node` is kept. But that site may not even need absence (item 1
  above).
- S5 (re-cutting `classes-progid`) is not enough on its own. The W2 decision is about `classes-ext`, together with
  `classes-shell` for the subkeys of a ProgID proof and `hku-classes` for per-user installs. All three fail S2 today:
  - `classes-ext`: 5 shared-shape false-absent keys per VM;
  - `classes-shell`: 9 per VM;
  - `hku-classes`: 115 and 3 shared-shape, with coverage of 28 % and 55 %.

  So W2 at 80 % is not reachable without either relaxing the shared-shape rule for these areas, or a source that
  covers the newest Windows-owned extension keys (archive formats, AppX / MSIX, `.xml`). The second option is the
  drift problem of S3.
- A minor point found on the way: the 32-bit `WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\…` falls into the
  marked `software-wow6432node`, while its 64-bit twin falls into the unmarked `software-ms-currentversion`. The area
  order treats the two views of the same key differently.
