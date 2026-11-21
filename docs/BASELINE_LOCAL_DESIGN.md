# Local baseline and nearest-build trust cap (design)

Status: design only, 2026-11-17. Implementation starts after the M1b gate. Package list:
`docs/BASELINE_LOCAL_DESIGN.json`. User decision: `docs/DECISIONS.md`, section "Post-M1b".

## 0. Summary

Today the engine proves "this registry key is not Windows' own" only with a shipped clean-Windows baseline
of exactly the host's (edition, build, ubr). Any other host works values-only. Windows builds change every
week or month, so most hosts never match.

This design adds:

1. A **local baseline**: the engine reads, once per (edition, build, ubr) and read-only, what this
   Windows installation says about itself (component manifests, the default user hive, inbox package
   manifests) and caches the result in an admin-only directory.
2. A **baseline view** that merges the local baseline with the nearest shipped baselines and answers two
   different questions with different trust: "is this Windows' own?" (presence, any source may say yes)
   and "is this proven not Windows' own?" (absence, with a trust level).
3. A **trust cap**: absence that is not from an exact shipped baseline never makes an item Safe or
   preselected. It is carried by a soft blocker, checked again in the policy and again when a scan is
   sealed.
4. An **advisory interface** for the residue (keys neither proven Windows' own nor proven the app's), for
   a later AI model. Advice can only lower a band.

What the cap means for the result, stated plainly: on a host without an exact baseline the set of
**preselected** items does not grow. The gains are (a) more protection: Windows' own keys, values and
paths are Blocked on every host, and harvest stops taking them as anchors or tokens; (b) key leftovers
that today are not offered at all (token keys, COM keys, ProgID keys) or go out as X-SYSTIDY are offered
as Likely with a real explanation; (c) a measured path to lifting the cap per registry area later (§8.5).

## 1. What exists today (read before implementing)

| Fact | Where |
|---|---|
| Exact-match selection, hashed sets, normalisation, capture scope, safe-direction collisions | `crates/purge-index/src/baseline.rs` |
| File format `#purge-baseline 1`, `K`/`V`/`D`/`F` | `kb/baselines/README.md`, `vm/RIG.md` §2, §8, `vm/rigtool/src/baseline.rs` |
| Shipped: `Professional-26340.9882` (309,932 K), `EnterpriseSEval-26100.1742` (275,872 K) | `kb/baselines/` |
| Engine loads the baseline: `load_baseline`, `baseline_for`; test `baselines_are_only_used_for_an_exact_match` | `bins/purge-engine/src/pipeline.rs` |
| Baseline directory: `%PURGE_KB_DIR%\baselines` or `<exe dir>\kb\baselines`; **not checked for admin-only write** | `bins/purge-engine/src/main.rs` |
| `ScanCtx::baseline: Option<&Baseline>`, `in_baseline`, `baseline_blocker`, key record Tier B without a baseline, no token evidence on a key without a baseline | `crates/purge-scan/src/framework.rs` |
| `ProvenOwnedSkeleton` needs `is_for` | `crates/purge-scan/src/skeleton.rs` |
| `matching_baseline` users | `cls_progid.rs`, `cls_assoc/handler.rs`, `com_class.rs`, `com_shellex.rs` |
| Blocking only | `reg_software.rs` (`has_key_exact_view`), `fs_vendorparent.rs`, `framework/m1b.rs` (`in_baseline` facts) |
| Harvest uses | `crates/purge-harvest/src/` `anchors.rs`, `tokens.rs`, `subtree.rs`, `assoc.rs`, `msi.rs`, `sysobj.rs`, `coproducts.rs`, `refsnap.rs` (`matching_baseline`) |
| Bands, soft blockers, Ai rule | `crates/purge-policy/src/band.rs` (rules 3, 4, 7), `crates/purge-model/src/blocker.rs` |
| Admin-only cache precedent | `crates/purge-index/src/ownership/cache.rs` (`DiskTableCache::open`), `pipeline::table_cache`, `docs/reviews/m1b/r4-review.md` "MSI table cache" |
| Plan text | `docs/ENGINE_PLAN.md` §5.3, §5.5, §5.7.1 step 3, §5.8, §8.1, review rows S12 and F6 |

Two directions of use, which the whole design rests on:

- **P (presence blocks).** "The baseline has it" removes an anchor, a token, a candidate, or adds the
  `WindowsBaseline` hard blocker. A wrong "present" costs a missed leftover.
- **A (absence enables).** "The baseline does not have it" is one conjunct of a proof that lets a key be
  deleted (`ProvenOwnedSkeleton`, `HarvestedToken` on a key, `ComKeyOwnership`, a key-scope installer
  record, the ProgID and `.ext` skeleton rules, the subtree record at harvest). A wrong "absent" can
  offer a Windows key.

## 2. Invariants

- **L1 Additive sources.** Every source of the local baseline and every shipped neighbour can only add
  to the set "Windows' own". Nothing is ever subtracted at hash level. A contaminated source (an
  installer that wrote into the default user hive) costs recall, never safety.
- **L2 Complete or unused.** A source that failed, or a build below its floors (§3.4), makes the local
  baseline *incomplete*. An incomplete local baseline is used for presence only, never for absence.
- **L3 Exact is untouched.** On a host with an exact shipped baseline the engine behaves byte-for-byte as
  at the M1b gate: the local baseline is not built, not read and not merged.
- **L4 The cap.** Absence at a trust below Exact never yields Safe and never preselects (§4.4).
- **L5 Monotone.** A view below Exact only takes away: what a scan or a plan offers with a view below Exact,
  the same scan or plan without a baseline offers at least as strongly. For every item offered below Exact
  there is an item of the no-baseline result that (1) has the same target or, when the no-baseline result has
  no item of that target, a key or directory that contains it; (2) has a band at least as high, with
  not listed < Blocked < Weak < Likely < Safe; (3) is preselected if the item below Exact is. So nothing new is
  offered (not even as Blocked), no band is raised, the preselected set is a subset, and what was Blocked is
  Blocked or no longer listed. The Blocked set is *not* a superset: a scanner may withhold a Windows key it
  listed as Blocked without a baseline. The containing case in (1) is the one named exception to "the same
  target": a scanner told that a key is Windows' own may offer the app's values in it instead of the key.
  This is the one statement of L5 (restated after review BL-R1 S7; the first wording, "Blocked sets are
  supersets", was not what presence-only gives). It is checked per scanner (`purge-scan`
  `tests/shared/l5.rs`) and per plan (`xtask replay`, `l5_violations`).
- **L6 A local file is never an exact baseline.** Different header tag, directory and file name; the
  exact loader rejects it (§3.5).
- **L7 Advice only lowers** (§7).

## 3. The local baseline

### 3.1 Sources

Checked on the host (Windows 11 Pro Insider 26300, 2026-11-17, read-only): 35,842 files in
`C:\Windows\WinSxS\Manifests` (35.5 MB); 97% start with `DCM\x01` + `PA30`, the rest are plain XML. A
`DCM` file expands with `msdelta.dll` `ApplyDeltaB(0, base, file[4..])`, where `base` is resource type
`0x266`, id `1` of `wcp.dll` in the newest `WinSxS\amd64_microsoft-windows-servicingstack_*` directory
(9,066 bytes here). 2,100 random files expanded without one failure; 600 took 1.2 s on one thread in
PowerShell and gave 15.7 MB of XML. About one manifest in three has registry keys; 1,500 random
manifests held 35,380 `registryKey` elements (4,019 of them spelled `asm:registryKey`), with roots
`HKEY_LOCAL_MACHINE` 64%, `HKEY_CLASSES_ROOT` 36%, `HKEY_CURRENT_USER` 0.1%. Scaled: about 850,000 key
elements before de-duplication. `offreg.dll` and `msdelta.dll` are in `System32`.
`C:\Users\Default\NTUSER.DAT` is 256 KB. 47 directories in `C:\Windows\SystemApps`.

| # | Source | Read how | Covers | Misses |
|---|---|---|---|---|
| S1 | Component manifests `WinSxS\Manifests\*.manifest`, all versions and architectures, staged features included | directory listing, `ApplyDeltaB`, streaming XML | `registryKey` names and `registryValue` names under HKLM\SOFTWARE, HKLM\SYSTEM, HKCR (CLSID, Interface, TypeLib, AppID, ProgIDs, `.ext`, shell verbs), a few HKCU; `file` and `directory` destinations | keys made at run time; keys of drivers installed from INF; anything Edge, OneDrive or a Store app writes itself; value **data** (macros, so no usable hash) |
| S2 | Default user hive `C:\Users\Default\NTUSER.DAT` | `offreg.dll` `OROpenHive` on the file (the hive is not loaded into the registry) | the template of every new profile: `HKU\<sid>\…` as a profile starts | keys made at first logon and later (Explorer, shell, per-user AppX state, OneDrive); `UsrClass.dat` content (there is no template for it) |
| S3 | `HKU\.DEFAULT` | the live key through the existing `RegistrySource` (it is the loaded `config\DEFAULT`) | `HKU\.DEFAULT\…`, `HKU\S-1-5-18\…` | nothing in its scope; it can hold keys written by installers running as SYSTEM (additive, L1) |
| S4 | Inbox package manifests: `AppxManifest.xml` of packages whose signature kind is System, plus Microsoft-published provisioned packages | package list through `purge-win` `appx`; files read from the package directory | declared file types, protocols, COM classes and interfaces, ProgIDs; with the package repository keys under `HKLM\SOFTWARE\Classes\Local Settings\…\AppModel\PackageRepository` also the generated `AppX…` ProgIDs of these packages | per-user AppModel state; packages installed only for one user; **to confirm in the spike**: which repository values name the generated ProgIDs |
| S5 | INF files `%windir%\INF\*.inf` without `oem*.inf` | text parse of `AddService` and `AddReg` lines with `HKLM`/`HKCR` roots | `Services\<name>` of inbox drivers, class keys | device-instance keys (`HKR`), anything the capture scope excludes anyway (`Enum`) |

Not used, with the reason: the `COMPONENTS` hive and `servicing\Packages\*.mum` (they say which
component versions are installed; taking every manifest already errs to the safe side, L1); the live
`HKLM\SOFTWARE` (it is what is being judged); the `System32` file listing (path uses are P only, and
S1 gives the file destinations); WinRE's image (another OS).

S5 is built only if the measurement shows a need (§8): the A consumers do not ask about
`HKLM\SYSTEM`, so missing driver services cost nothing there.

What no local source can know, and why the union is needed: keys created by OOBE, by first logon and by
services at their first start. They exist in a shipped baseline of a neighbouring build, because the rig
captures a machine after OOBE and logon, and they change little between builds.

### 3.2 Mapping rules (S1)

- Elements are matched by local name (`registryKey`, `asm:registryKey`, …).
- `HKEY_CLASSES_ROOT\X` is recorded as `HKLM\SOFTWARE\Classes\X`. `HKEY_CURRENT_USER\X` is recorded as
  `HKU\S-1-5-21-0-0-0-1000\X` (the existing normaliser turns it into `<sid>`) and as `HKU\.DEFAULT\X`.
  `HKEY_USERS\.DEFAULT` and `HKEY_LOCAL_MACHINE` are taken as written.
- Every ancestor of a recorded key is recorded.
- A manifest whose `processorArchitecture` is `wow64` or `x86` records each key under `HKLM\SOFTWARE`
  twice: as written and under the 32-bit view (`HKLM\SOFTWARE\WOW6432Node\…`, for Classes
  `HKLM\SOFTWARE\Classes\WOW6432Node\…`). This over-states the 32-bit view; that is the safe side.
- A key name holding a `$(…)` macro that is not in the macro table is skipped and counted.
- Values: one `V` record per `registryValue`, with the type mapped from `valueType` and the hash
  `0000000000000000`. Only the name is ever used (§4.3).
- `file` and `directory` destinations: the macros `runtime.windows`, `runtime.system32`,
  `runtime.drivers`, `runtime.fonts`, `runtime.inf`, `runtime.wbem`, `runtime.programFiles`,
  `runtime.programFilesX86`, `runtime.commonFiles`, `runtime.commonFilesX86`, `runtime.programData`,
  `runtime.bootDrive`, `runtime.systemRoot`, `runtime.help`, `runtime.userProfile`, `runtime.public`,
  `runtime.startMenu`, `runtime.documentsSettings` are expanded for drive `C:` (the baseline's
  convention); for `wow64`/`x86` manifests `system32` is `SysWOW64` and `programFiles` is
  `Program Files (x86)`. The spike lists every macro found and extends the table.
- Manifests of any `publicKeyToken` are taken (L1). The token is recorded per source line for the
  measurement only.

S2: every key of the hive as `HKU\S-1-5-21-0-0-0-1000\<path>`; `Software\Classes` is folded by the
existing normaliser. Transaction logs are not replayed; the hive of the default profile changes only
with servicing.

### 3.3 What the local baseline is not

It is not a clean-install snapshot. It has no value hashes, so it never restores a value (§4.3). It is
never written into `kb/baselines` and never shipped.

### 3.4 Completeness seal (L2)

The build is *complete* only when all of these hold; the numbers are first guesses, fixed by the spike:

- the `wcp.dll` base resource was found, and at least 99.9% of the manifests expanded and parsed;
- at least 15,000 manifests were read and at least 150,000 distinct keys came from S1 (gate M round 1: Windows 11
  LTSC 26100.1742 has 18,489 manifests, all expanded and parsed, Clean-Pro 26340.9882 31,647, the host 35,842; a
  partial read is caught by the per-file counts above, the listing floor only rejects a directory that is far too
  small);
- key names skipped for an unknown macro: at most 50;
- S2 opened and gave at least 500 keys; S3 was readable: every key unreadable to the builder is on the short list of
  keys Windows denies to Administrators by design (below), any other one keeps S3 incomplete;
- S4: the package list was read (elevated) and at least 20 manifests parsed.

The file records, per source, status, counts and the reason of an incomplete build. The S2 and S3 lines name the
first 16 unreadable and the first 16 vanished keys (`unreadable-keys=`, `vanished-keys=`, full paths, `, `-separated)
so a seal reason can be looked at; S3 also counts `unreadable-by-design=`.

**Keys denied by design (S3).** Exact paths, compared folded (`purge_index::local_baseline::S3_DENIED_BY_DESIGN`):

| Key | Why an elevated Administrator cannot read it |
|---|---|
| `HKU\.DEFAULT\Software\Microsoft\SystemCertificates\Root\ProtectedRoots` | The protected root list of the account's certificate store. Its DACL is protected (not inherited) and grants only the account itself (`HKU\.DEFAULT`: SYSTEM), `NT SERVICE\CryptSvc` and one capability SID; Administrators get nothing. Checked on the host (2026-11-21): its own `HKCU` copy has `D:PAI(A;CI;KR;;;<user>)(A;CI;KA;;;<CryptSvc>)(A;CI;KR;;;S-1-15-3-9)`; of the 7 `HKU\.DEFAULT` keys an unelevated walk cannot open, it is the only one whose `HKCU` twin grants Administrators nothing (the other 6 grant `BA` full control). So it is taken to be the one unreadable key of S3 on both rig VMs in gate M round 1; the `unreadable-keys=` detail of round 2 confirms or refutes it |

A listed key costs nothing: what the elevated builder cannot read, the elevated scanner cannot read either, so no
candidate is judged against what the baseline misses there. A key is added only with the same kind of evidence (its
DACL, and that Windows sets it so), never because a run met it.

### 3.5 File

`local-<EditionID>-<build>.<ubr>-<id>.tsv.gz`, the baseline record format, with a header that the exact
loader refuses:

```
#purge-baseline-local 1\t<iso time>\t<computer>\t<edition>\t<build.ubr>\t<builder version>\t<source id>
#src\t<S1|S2|S3|S4|S5>\t<status>\t<items read>\t<records>\t<skipped>\t<detail>
K\t… V\t… D\t… F\t…
#end\t<record count>\t<sha-256 of everything before this line>
```

`Baseline::from_bytes` keeps rejecting this header (`BadHeader`); a second entry point
`LocalBaseline::from_bytes` reads it, checks `#end`, and returns the same hashed sets. A file without a
correct `#end` line is a miss, never partial data.

## 4. Trust levels and the union

### 4.1 Levels

| Level | When | Presence (P) answered from | Absence (A) |
|---|---|---|---|
| **Exact** | a shipped baseline matches (edition, build, ubr) in name and header | that baseline only | proof, as today |
| **Merged** | no exact match; the local baseline is complete; at least one shipped neighbour qualifies | local ∪ neighbours | *inferred*, inside the areas marked `merged` (§4.2); capped (L4) |
| **Local** | no exact match; the local baseline is complete; no neighbour qualifies | local | *inferred*, inside the areas marked `local`; capped. If no area is marked, Local is presence-only |
| **None** | anything else (no local baseline, or incomplete) | whatever exists: neighbours, an incomplete local baseline | never; values-only as today (§5.7.1 step 3) |

Neighbour selection, among the shipped baselines of any edition:

1. same build, other ubr: all of them qualify;
2. otherwise the nearest build below and the nearest build above the host's, each only if
   `|Δbuild| ≤ 1000`;
3. at most three neighbours; ties go to the host's edition, then to the smaller `|Δubr|`.

The edition does not have to match: a neighbour only adds presence (L1). The limit of 1000 keeps a
Windows 10 baseline from standing in for Windows 11; it is data (`kb/baselines/view.json`).

For this host today (26300.9974): `Professional-26340.9882` (Δ40) and `EnterpriseSEval-26100.1742`
(Δ200) both qualify, so the view is Merged.

### 4.2 Areas

`kb/baselines/view.json` (shipped, admin-only like the baselines) lists registry areas as key prefixes
with two flags, `merged` and `local`: whether inferred absence is accepted there at that level. The
first version is written from the measurement (§8.4). Outside the capture scope
(`Baseline::key_in_scope`) absence is never answered, as today.

### 4.3 API (`purge-index`, new `baseline_view.rs`)

```
pub enum BaselineTrust { Exact, Merged, Local, None }

pub struct BaselineView { /* exact | (local?, neighbours, areas) */ }

impl BaselineView {
    pub fn trust(&self) -> BaselineTrust;
    pub fn name(&self) -> String;             // "Professional-26340.9882" or "local-…+2"
    // P: any trust. Union of every set the view holds.
    pub fn has_key(&self, key) -> bool;        pub fn has_key_exact_view(&self, key) -> bool;
    pub fn has_value(&self, key, name) -> bool; pub fn has_path(&self, path) -> bool;
    pub fn has_token(&self, token) -> bool;     pub fn has_segment(&self, name) -> bool;
    // A: the only way to learn absence.
    pub fn key_absent(&self, key) -> Absence;
    // Restore source for an .ext default: Exact only.
    pub fn exact_value(&self, key, name) -> Option<BaselineValue>;
}

pub enum Absence {
    Present,                 // some set has it
    Proven,                  // Exact, in scope, not there
    Inferred(BaselineTrust), // Merged or Local, in scope, in an accepted area, in no set
    Unknown,                 // out of scope, area not accepted, or trust None
}
```

`ScanCtx::baseline` and the harvest contexts change type from `Option<&Baseline>` to `&BaselineView`.
That makes every one of today's uses a compile error, and each is rewritten as P or A:

| Site | Class | With a non-exact view |
|---|---|---|
| `framework.rs` `in_baseline`, `baseline_blocker`; `reg_software.rs`; `fs_vendorparent.rs`; `framework/m1b.rs` facts; `com_class.rs` and `com_shellex.rs` `in_baseline` calls | P | union; more `WindowsBaseline` blocks |
| `framework.rs` anchor filter (`has_token`), `harvested_token` "baseline knows the token" | P | union |
| harvest `anchors.rs`, `tokens.rs`, `msi.rs`, `sysobj.rs`, `coproducts.rs` | P | union |
| `skeleton.rs` `prove` | A | `Inferred` → evidence plus cap; `Unknown` → `NotProven::NoBaseline` |
| `framework.rs` key record (`installer_manifest`, the MSI and Burn forms, the delete-whole-key rule at line 1053) | A | `Inferred` → Tier A plus cap; `Unknown` → Tier B, as today |
| `framework.rs` `harvested_token` on a `RegKey` target | A | `Inferred` → evidence plus cap; `Unknown` → none |
| `cls_progid.rs`, `com_class.rs` (`:470`), `com_shellex.rs` (`:864`), `cls_assoc/handler.rs` standing | A | `Inferred` → as with a baseline, plus cap; `Unknown` → today's no-baseline path (X-SYSTIDY, Tier B cap) |
| `cls_assoc.rs` `restore_source` | exact value | `exact_value`; `None` below Exact, so the default stays report-only |
| harvest `subtree.rs` (`known \|\| baseline.is_none()`), `assoc.rs` (`ext_in_baseline`) | A | the fingerprint records the trust beside the fact (§4.5) |

An xtask check `baseline-sites` (in the style of `no-new-walks`) fails when `key_absent` is called
outside the listed files, or when a scanner calls a P method and negates it.

**As built (BL-FRAMEWORK, presence-only; DECISIONS 2026-11-21).** The "with a non-exact view" column of the A
rows above is the design; what ships is its `Unknown` half only. Each crate has one *capped path* that asks
the view for absence and hands `Inferred` out as `Unknown`: `purge-scan` `framework/absence.rs`
(`ScanCtx::key_absence`, `has_exact_baseline`, `has_matching_exact_baseline`) and `purge-harvest` `refsnap.rs`
(`HarvestCtx::key_absence`, `has_exact_baseline`, `presence`). Below Exact every A site therefore takes the path it
took without a baseline, and every P site asks the union. The carrier (`CandidateBuilder::absence`) and the seal
(`ScanCtx::baseline_cap_missing`, in `ScanCtx::run`) exist and are tested, with no production caller that hands
them an inferred answer. The seal acts on evidence that *claims* baseline absence (`framework::claims_absence`:
`ProvenOwnedSkeleton`, `HarvestedToken`, and `ComKeyOwnership` or a key-scope Inno record without `baseline=none`),
not on every absence-dependent kind: key-scope MSI and Burn records and key-scope `ChainedRef` never ask the
baseline, and the no-baseline paths emit them. The fingerprint records a view below Exact with the trust of the
absence facts made with it, which is `None` (`BaselineTrust::presence_only`); an Exact view and an empty one record
nothing, so those fingerprints are byte-identical to the M1b gate's. `cargo xtask baseline-sites` holds the site
table (every call, its class, what it does below Exact) and fails on an unlisted call, on `key_absent` outside the
two capped files, on a capped file without the `Inferred => Unknown` arm, and on a negated presence call.

**The cap as built has two live layers, not three (review BL-R1 S1; DECISIONS 2026-11-21).** Of the three layers
of §4.4 the carrier and the seal act below Exact. The policy backstop P-BL-1 is inert in production under a Merged
or Local view: the scan hands the policy `ScanCtx::absence_trust()`, which is `trust().presence_only()`, so None
below Exact, and the fingerprint records None too; `is_capped` then acts only on evidence that carries the
carrier's own fact. A site wired to inferred absence by mistake is therefore stopped by the capped path itself
(it never sees `Inferred`), by `baseline-sites`, and by the seal for the evidence forms the seal knows; key-scope
MSI and Burn records and key-scope `ChainedRef` are outside the seal and would not be stopped by the policy either.
Handing the policy the view's own trust would close that, and would cap the MSI and Burn key records a no-baseline
scan preselects today: a recall loss with no safety gain while no site consumes inferred absence. So the code
stays, and §8.5 carries the condition.

### 4.4 Where the cap is applied (three layers; two of them live while presence-only, see §4.3 "as built")

1. **Scanner layer, the carrier.** `CandidateBuilder` gets `absence(&mut self, a: Absence)`. For
   `Inferred(t)` it adds the detail facts `baseline=<view name>`, `baseline_trust=merged|local` to the
   evidence and the new **soft** blocker `Blocker::BaselineInferred` to the candidate. The evidence keeps
   the tier its kind has. By band rule 3 ("no soft blocker") the item cannot be Safe; by rule 4 (Tier A
   with a soft blocker) it is Likely.
2. **Seal.** `ctx.run` already seals candidates. With a view below Exact it refuses (drops, with a
   warning, and fails in debug builds) a `RegKey` candidate that has evidence of an absence-dependent
   kind and no `BaselineInferred`. Absence-dependent kinds: `ProvenOwnedSkeleton`, `ComKeyOwnership`,
   `HarvestedToken`, key-scope `InstallerManifest`, key-scope `ChainedRef`.
3. **Policy backstop (P-BL-1).** `PolicyCtx` gets `baseline_trust`. In `decide`, when it is Merged or
   Local and the target is a `RegKey`, evidence of an absence-dependent kind does not *support* Safe,
   whether or not the blocker is there; the note `BaselineInferred` is added. `POLICY_VERSION` becomes
   `bl.1` (or the next free name); the golden tests get new rows, the old rows stay.

`BaselineInferred` is soft: the user may tick the item. What then protects a Windows key is unchanged:
the other conjuncts of each proof (every value attributed to the app at harvest, empty now, no
TrustedInstaller owner or ACE, no other referrer), the Guard, the backup and undo.

Explanation templates (`purge-policy` `explain.rs`): the evidence line reads "not in this PC's Windows
component list, nor in clean Windows <neighbour names>" in place of "not on clean Windows <name>"; the
blocker line reads "Not preselected: there is no verified clean-install list for Windows build
<build.ubr>".

### 4.5 Fingerprint

`OsInfo` (or a new field beside it) records `baseline_view: {name, trust, local_id}` at harvest.
Absence facts stored in the fingerprint (`ext_in_baseline`, `openwith_in_baseline`, the subtree record)
count at scan time with `min(harvest trust, scan trust)`. Old fingerprints have no field; they read as
Exact when their `os` matches a shipped baseline and as None otherwise, which is what they were.

### 4.6 Existing tests and invariants

- Unchanged and still required: `baselines_are_only_used_for_an_exact_match` (the exact loader),
  `no_matching_baseline_is_not_proven` and `harvested_token_on_a_key_needs_a_baseline` (now stated for
  trust None), `a_key_record_without_a_baseline_is_tier_b`, the golden
  `cls_assoc_vscode_no_baseline.txt`, every test that builds an exact baseline with
  `testkit::baseline` (the helper wraps it in an Exact view).
- New: one test per A site for `Inferred` (evidence present, blocker present, band Likely, not
  preselected) and for `Unknown`; a golden `cls_assoc_vscode_merged.txt`; property tests for L5 over the
  replay corpus; the seal test; `P-BL-1` golden rows; a test that a `#purge-baseline-local` file placed
  in `kb/baselines` under an exact name is refused (L6); a test that an incomplete local baseline gives
  trust None and still blocks.
- Replay gate: with exact baselines the plans are byte-identical to the M1b gate plans (L3).
- As built for L5 (presence-only; reviews BL-R1 S3, S7, M2). Per scanner, `tests/shared/l5.rs` runs each
  scanner world without a baseline, with views below Exact that hold nothing (the candidates must be equal),
  and with views that hold what the no-baseline candidates name: all of it, then seeded random parts of it
  (keys, values, directories, files, the keys of services and tasks, the values of firewall rules). Each pair
  must hold L5 as §2 states it, with the policy at trust None and at the view's own trust. A test fails when
  a scanner offers nothing in any of its worlds or when no presence view changes what it offers, unless the
  scanner is named exempt with the reason (SYS-APPX: a package is nothing a baseline holds); and the
  comparison is shown to bite on the candidates of each scan. Per plan, `xtask replay --baseline-view
  merged|local|none` with `--local` and `--neighbour` injects the view into the harvest **and** the scan
  (`purge-engine` feature `inject-view`, enabled by xtask only; no CLI or RPC path reaches it), and
  `l5_violations` compares the plan with the no-baseline plan. With presence-only the merged view is held
  against the no-baseline golden, so the golden `cls_assoc_vscode_merged.txt` listed above was not made
  (review BL-R1 N11).

## 5. Cache

- **Where.** `%ProgramData%\Purge\baseline\`. Accepted only when the directory and every ancestor pass
  the check `DiskTableCache::open` uses (`is_admin_only_writable`: owner SYSTEM, Administrators or
  TrustedInstaller; no write, delete, DACL or owner right for anyone else; no reparse point). Created
  only when elevated and only under a data root that already passes (`install/install.ps1`). As built, the
  directory must also be a plain directory on the engine's own file system: a link or junction in its place
  is refused whatever the file system source says about the path.
- **Who builds.** Only an elevated engine (the broker). An unelevated engine reads an accepted cache and
  never writes; without a cache it has trust None and says so in a warning. The broker never takes a
  baseline computed at medium integrity. As built: the data root of `install.ps1` grants Users traverse
  only, so an engine that is not elevated cannot read the directory's protection there and gets no cache
  (seen on the host 2026-11-21); it then has the shipped neighbours only. That is the safe side, and nothing
  a standard user can read can be held open against the elevated engine's writes.
- **Why a standard user cannot plant or poison it.** A removed line could make a Windows key look
  absent, so the file must not be writable below admin. The directory rule gives that; the `#end` line
  only detects truncation. Writes go to a temporary name in the same directory and are renamed.
- **Key and invalidation** (as built in BL-CACHE, `purge_index::local_baseline::cache`; DECISIONS 2026-11-21,
  review BL-RM S1 and S7). The cache holds one text file **per source**, each in the format of §3.5 with that
  source's one `#src` line: `local-<EditionID>-<build>.<ubr>-s1-<id>.tsv.gz` (S1; id over the count, total size
  and newest write time of `WinSxS\Manifests`), `…-s2-<id>.tsv.gz` (S2; size and write time of the default hive)
  and `…-s4-<id>.tsv.gz` (S4; the sorted full names of the inbox packages of every user). Every id also covers
  the builder version. A part is used only when its name, header and `#src` line agree with the host and the id
  asked for and its `#end` holds. A new UBR, a servicing change, an inbox package update or a new builder
  version is a miss for the parts it touches and only for those: an inbox Store app update rebuilds S4 in under
  a second and keeps S1. After a store the two newest files of that source are kept. The loaded local baseline
  is the union of the parts; its source id (the fingerprint's `local_id`) is made from the ids of the parts
  used. The one-file form of §3.5 is still what `baseline build --out` writes for the rig.
- **A stale part answers presence** (review BL-R1 S5). After a servicing change the rebuild of S1 takes minutes,
  and until it has ended the engine would have no component manifests at all. On a miss a load therefore takes
  the newest part of that source of the same edition and build that this builder wrote (any id, any UBR; the
  two newest files are kept) and marks its `#src` line incomplete with the reason `stale: …`. It is a list of
  keys Windows owned on this machine before the change, so it only adds presence (L1), at the cost of a few
  keys of removed components. The local baseline is incomplete with it, so the trust is None (L2) and nothing is
  inferred; the part still counts as missing for the build, and the local baseline's source id says `stale:`
  for it, so it is never the id of a complete one.
- **S3 is never cached.** Nothing an id could be made from says that the live `HKU\.DEFAULT` changed, so
  every load of the view reads it again through the registry source (about 0.3 s) and judges its seal then.
  An engine that is not elevated cannot read all of it and cannot list every user's packages (it takes the
  newest S4 part unchecked), so its local baseline is always incomplete: trust None, presence from all it has.
- **Derived form.** Parsing the S1 text takes about 3 s. Beside it the cache keeps `…-s1-<id>.sets`: the hashed
  sets as binary, with `HashedSets::scheme()`, the SHA-256 of the text file's bytes and its own SHA-256. A load
  hashes the text file and takes the sets only when the scheme and both hashes match; header and `#src` line
  are always read from the text. Anything else: the text is parsed and (elevated) the derived file is written
  again. The shipped neighbours get the same form (`shipped-<EditionID>-<build>.<ubr>.sets`, bound to the
  shipped file's bytes). The text files stay the source of truth.
- **Build.** `pipeline::start_local_build` runs once per engine start (the CLI: `harvest`, `uninstall`, `scan`;
  the broker in M3), never at logon. It returns at once; a thread builds the missing parts at background
  priority, the cheap ones first. A scan never waits: it runs with what exists, tells the build that it is
  waiting (the build's threads leave background priority) and warns that a later scan uses the result. The
  state (`none`, `checking`, `building`, `done` with `rescan`, `failed`) is in `engine.hello`
  (`baseline_build`, beside `baseline_trust` and `baseline_view`). The CLI process stays until the build it
  started has ended.
- **The shipped directory.** When the engine is elevated, `kb\baselines` (also when it comes from
  `PURGE_KB_DIR`) must pass the same admin-only check, or no shipped baseline is used at all. This closes
  a gap that exists today and that this feature would widen. The live engine sets
  `Settings::check_shipped_dir`; fixtures and replays do not, because their file system source describes
  another machine than the one the baseline directory is on. As built, the exact baseline's file and
  `view.json` are judged themselves too (a file moved into the directory keeps its old owner and grants; a
  hard link shares them); one that fails is not used and the view is built without it. The rig (review BL-R1
  M1; scripts changed, **not yet run on a VM**): its `C:\cr\bin\kb\baselines` is made by `mkdir` below the
  drive root and so inherits its grant for Authenticated Users, which made its elevated engine drop every
  shipped baseline. `rig.ps1` `Push-Tools` now protects `C:\cr\bin\kb` after the copies (owner Administrators;
  protected DACL: SYSTEM and Administrators full, Users read and execute) and takes delete and re-ACL rights
  on `C:\cr` and `C:\cr\bin` from standard users, and every engine run asks `purge-engine hello` (the result
  of `engine.hello`) and fails when `baseline_trust` is not the trust the run is for (`vm/RIG.md` §4a). The
  first rig run confirms it, or shows what the directory rule still objects to (the run's `engine-hello`
  phase logs it).
- **Budget** (`PURGE_TIMING` phases `baseline.local.*`; `read` is the workers' time taking the next manifest and
  reading it, outside the listing lock since gate M round 2): cold build at background I/O and CPU priority,
  in parallel over the manifests: at most 30 s on the 591-program host, at most 120 s on a 2-vCPU VM;
  peak memory at most 300 MB; file at most 15 MB; source-id check at most 0.3 s; warm load of the view
  (local plus two neighbours) at most 1.5 s and at most 80 MB resident. The build starts when the broker
  starts and overlaps the uninstall dialog; a scan that starts before it ends runs with trust None and a
  warning, and is not blocked.

## 6. Hash collisions

The rule in `baseline.rs` stays and is extended to the union: only membership is asked, a collision can
only make an item look present, and present is the safe side. Three consequences for the
implementation: the union is "any set has the hash" and is never computed as a difference; nothing is
removed from a set after hashing (rig items and `oem*.inf` are filtered on text, before hashing); no
cache of "known absent" answers is kept. With 64-bit FNV-1a and about 10^6 entries a query collides
with probability about 5·10^-14.

## 7. Advisory interface for the residue (interface only, model later)

The **residue** of a scan is every item that carries `BaselineInferred`, plus every key an A site
answered `Unknown` for and therefore did not offer or offered as X-SYSTIDY.

Output, part of the scan result, schema `purge.residue/1`:

```
{ "scan_id": "…", "baseline_view": {"name": "…", "trust": "Merged"},
  "items": [ { "id": "<candidate id or residue id>", "item_fp": "…",
               "key": "HKLM\\SOFTWARE\\Classes\\…", "area": "<area id of view.json>",
               "why": "inferred_absent | area_not_accepted | out_of_scope | no_view",
               "site": "<scanner id>",
               "shape": { "values": 0, "subkeys": 0, "owner": "admins|system|ti|user|other",
                          "written": "before_install|in_window|after_uninstall|unknown",
                          "parent_in_view": true, "siblings_in_view": 12, "siblings": 14,
                          "in_local": false, "in_neighbours": [false, false] } } ] }
```

No value data and no file content leave the engine (ENGINE_PLAN §8.4).

Input, schema `purge.advice/1`, read as untrusted (from `%LOCALAPPDATA%\Purge\agent\` or the MCP tool
`annotate_candidates`):

```
{ "scan_id": "…", "model": "…", "items": [ { "id": "…", "item_fp": "…",
    "verdict": "windows | app | unknown", "confidence": 0.0, "reason": "<enum>", "note": "<≤200 chars>" } ] }
```

Effect, enforced in the engine: advice becomes `Ai` evidence bound to (`scan_id`, `id`, `item_fp`);
stale or unknown ids are dropped. `windows` has a negative weight and moves the item down one band
(band rule 7). `app` and `unknown` add a collapsed note and change nothing: they never remove
`BaselineInferred`, never raise a band, never preselect, never create a candidate. Hard blockers and the
Guard are out of reach (§8.1 invariants 4 and 5).

## 8. Measurement plan (before any engine change beyond the builder)

### 8.1 Tools

- `purge-engine baseline build --out <file>`: builds the local baseline, read-only apart from the
  output, prints the `#src` lines and the timing.
- `rigtool baseline-diff --truth <shipped> --local <file> [--neighbour <shipped>…] --areas <view.json>
  --out <report.json>`: per area and in total: truth keys; covered by local; covered by local ∪
  neighbours; **false absent** local-only and merged (in truth, in no set); extra (in a set, not in
  truth); the share of covered keys per source; the first 200 false-absent keys per area; the count of
  false-absent keys of a **shared-container shape** (`.ext`, `.ext\OpenWithProgids`, `…\shell`,
  `…\shellex\*`, a top-level ProgID, `SOFTWARE\<name>` and `SOFTWARE\WOW6432Node\<name>` at depth 1 and
  2). Only keys inside the capture scope are compared.
- `xtask replay --baseline-view merged|local|none --local <file> --neighbour <file>…`: the frozen snaps
  with an injected view.

Areas of the first table: `Classes\CLSID`, `Classes\Interface`, `Classes\TypeLib`, `Classes\AppID`,
`Classes\.ext`, `Classes\<ProgID>`, `Classes\*\shell and shellex`, `Classes\WOW6432Node`,
`SOFTWARE\Microsoft\Windows\CurrentVersion`, `SOFTWARE\Microsoft` (rest), `SOFTWARE\<vendor>`,
`SOFTWARE\WOW6432Node`, `SOFTWARE\Clients and RegisteredApplications`, `SYSTEM\…\Services`,
`SYSTEM\…\Control`, `SYSTEM` (rest), `HKU\<sid>\Software\Microsoft`, `HKU\<sid>\Software` (rest),
`HKU\<sid>_Classes`, `HKU\.DEFAULT`.

### 8.2 Runs (rig rules of `vm/RIG.md` apply; clean snapshots only, nothing installed)

| Run | Machine | What | Truth |
|---|---|---|---|
| R1 | Clean-Pro VM, Professional 26340.9882, `rig-base` | build (cold, then warm); `baseline-diff` local-only, and merged with the neighbour `EnterpriseSEval-26100.1742` (leave-one-out: the exact file is hidden) | `Professional-26340.9882` |
| R2 | Inbound VM, EnterpriseSEval 26100.1742 | the same, with the neighbour `Professional-26340.9882` | `EnterpriseSEval-26100.1742` |
| R3 | none (replay) | every frozen M1a and M1b snap of each VM with the view of R1 or R2 injected: exact, merged, local, none | the exact plans |
| R4 | both VMs | the M1b campaign (`truth/m1b.sh`, apps and traps) with the exact baseline hidden | the campaign's truth and trap expectations |
| R5 | the host, 26300.9974, read-only | build time and size; scan plans of ten programs in merged mode against none mode | none (counts and timing only) |

R1 and R2 are each a leave-one-out test across edition and across 240 builds, which is harder than the
host's case (Δ40 and Δ200, one of them the same edition).

Expected, to be confirmed or refuted (estimates, not measurements): local-only coverage about 85 to 95%
in the COM areas of HKLM Classes, 60 to 80% in `SOFTWARE\Microsoft`, 50 to 70% in `HKU\<sid>`, under
40% in `HKU\<sid>_Classes`; merged coverage above 99% overall.

### 8.3 Acceptance: the cap is safe

- **S1** R3: zero *flips*. A flip is a candidate offered with inferred absence whose key is in the truth
  baseline. R4: `danger_listed = 0` and every trap expectation met, in merged and in local mode, on both
  VMs.
- **S2** Merged, in every area marked `merged`: false-absent keys of a shared-container shape = 0;
  other false-absent keys at most 0.5% of the area's truth keys, each listed in the report.
- **S3** Local, in every area marked `local`: the same two numbers with local-only sets. An area that
  fails is not marked; "no area marked" is an accepted outcome (Local is then presence-only).
- **S4** L3 and L5 hold over R3: exact plans byte-identical; every plan made with an injected view below
  Exact holds L5, as §2 states it, against the no-baseline plan of the same run (`l5_violations` is empty).
- **S5** The completeness seal passes on both VMs and on the host, and fails when one source is made
  unreadable (fault injection in a unit test).

### 8.4 Acceptance: the feature is worth it

- **W1** Merged coverage of truth keys, pooled over the areas marked `merged`, at least 99.8% on every
  leave-one-out run; coverage over the whole scope is reported, not judged (restated after gate M, coordinator
  2026-11-21, review BL-RM S4: the scope figure is dominated by versioned servicing state under `CurrentVersion`).
- **W2** R3 and R4: of the key candidates that the exact view offers and the none view does not, the
  merged view offers at least 80% (as Likely). Below 50% the A side is dropped and the feature ships as
  presence-only.
- **W3** Recall cost: items the exact view offers and the merged view blocks (extra presence) are at
  most 1% of the exact view's offered items.
- **W4** The budgets of §5 on R1, R2 and R5, judged on a first-read build on a settled machine; the cold build
  right after boot is reported, not judged (restated after gate M, coordinator 2026-11-21). The rig job builds three times (gate M round 2, coordinator): *cold*
  right after boot (what a broker started at logon would see), *warm* (the determinism pair of cold), and *settled*:
  after the boot settle of the exec runs (ReadyBoot trace stopped, uptime at least 300 s), the CPU under 10 % over
  30 s, and the standby list emptied so the files are read from disk again. Background mode stays in every pass; the
  settled pass separates the builder's own cost from the boot-time I/O it yields to. R1 and R2 build with the VM's NAT
  cable disconnected; passes whose bodies differ are a determinism failure only with the same header source id
  (another id: the source changed, the run is invalid).
- **W5** R5: the merged view adds at least one `WindowsBaseline` block or Likely key per program on
  average over the ten programs; otherwise the report says the host gains nothing and why.

The first `view.json` marks exactly the areas that pass S2 (merged) and S3 (local) on every leave-one-out run and
that an A consumer asks about (gate M round 2: `merged` in seven areas, `local` in none; DECISIONS 2026-11-21).

### 8.5 Lifting the cap later (not part of this work)

An area may let inferred absence support Safe only after a user decision and only when S2 holds with
**zero** false-absent keys of any shape in that area on at least three leave-one-out pairs, two of them
with a build distance at least as large as the one trusted. That needs more shipped baselines, which is
what automated release-build baseline packs would provide.

The first A site wired below Exact, capped or not, comes in the same change with `baseline.view.trust()` as the
scan side of `BaselineTrust::for_policy` in the pipeline, so that the policy backstop P-BL-1 is live again
(review BL-R1 S1: while presence-only the policy is handed None below Exact, §4.3 "as built"), and with the
seal's list of evidence forms reviewed for the kinds that site can emit.

## 9. Packages

Details, files and tests: `docs/BASELINE_LOCAL_DESIGN.json`. Importance follows the model-routing rule;
critical packages get a Fable review.

| Wave | Id | Importance | What |
|---|---|---|---|
| 1 | BL-WIN-SXS | medium | `purge-win`: manifest expansion (`wcp.dll` base, `ApplyDeltaB`), read feature |
| 1 | BL-WIN-OFFREG | medium | `purge-win`: read-only offline hive walk through `offreg.dll` |
| 1 | BL-MANIFEST | high | pure parser: manifest XML to records, macro table, view mapping |
| 1 | BL-SOURCES | medium | default hive, `HKU\.DEFAULT`, inbox package manifests to records; `LocalSources` trait, live and fixture |
| 2 | BL-BUILD | high | orchestration, seal, file format, `LocalBaseline` reader, CLI `baseline build` and `baseline info` |
| 2 | BL-RIG-DIFF | medium | `rigtool baseline-diff`, area table, replay `--baseline-view`, `vm/RIG.md` §8a |
| 3 | BL-MEASURE | gate M | runs R1, R2, R5 and the report; decides `view.json` and whether wave 4 starts |
| 4 | BL-VIEW | critical | `BaselineView`, trust levels, neighbour selection, areas |
| 4 | BL-POLICY | critical | `Blocker::BaselineInferred`, `PolicyCtx::baseline_trust`, P-BL-1, notes, templates, fingerprint field |
| 5 | BL-FRAMEWORK | critical | `ScanCtx` and harvest type change, every site classified, seal check, xtask `baseline-sites` |
| 5 | BL-CACHE | critical | cache directory, source id, invalidation, admin-only check of `kb\baselines`, pipeline and `engine.hello` |
| 6 | BL-RESIDUE | medium | `purge.residue/1` output, `purge.advice/1` types and validation (no model, no consumer) |
| 6 | BL-GATE | gate | runs R3, R4; S1 to S5, W1 to W5 |

## 10. Not now

- Automated release-build baseline packs (a VM per Windows release build, captured and published): future
  maintenance. It raises the share of Exact hosts and supplies the pairs §8.5 needs.
- The AI model for the residue (§7 is the interface only).
- S5 (INF) unless gate M asks for it.

## 11. Open questions for the user

1. **Unelevated runs without a cache**: trust None with a warning (this design), or allow an in-memory
   build on every run (slow, about the cold-build time)?
2. **Local-only level**: accept "presence-only unless an area passes S3", or drop inferred absence at
   the Local level for good?
3. **Blocking from neighbours when nothing else exists** (trust None still uses neighbours for presence):
   it changes today's no-baseline plans (more Blocked, never more offered). Accept?
4. **R4 on the rig** needs the exact baseline hidden on the VM, which is a new rig mode. And a real drift
   test (Clean-Pro after a cumulative update) would need a Windows Update on a rig VM: wanted?
5. **`PURGE_KB_DIR`**: the admin-only check of the shipped directory when elevated will reject a
   user-writable rig directory. Keep the override for unelevated runs only?
6. **Cap lift** (§8.5): keep it as a stated future option, or rule it out?

## 12. Assumptions not yet verified

- `ApplyDeltaB` is safe to call from several threads (the budget assumes it).
- The `wcp.dll` base resource (`0x266`/`1`) has the same place on 26100 LTSC and on Windows 10.
- `offreg.dll` opens `C:\Users\Default\NTUSER.DAT` unelevated with shared read.
- Which package repository values name the generated `AppX…` ProgIDs (S4).
- Real Microsoft manifests are not committed as test fixtures; fixtures are hand-written in the same
  shape, and the real ones are read only on Windows test machines.
