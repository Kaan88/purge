# rigtool

The Purge VM rig's command-line tool. The contract it implements is `vm\RIG.md` (sections 2, 5, 6, 7, 8);
this file only covers usage.

Standalone Cargo project (own empty `[workspace]`), not part of the product workspace.

## Build

```
cargo build --release      # target\release\rigtool.exe, static CRT (no vcruntime140 needed)
cargo test
```

`.cargo\config.toml` sets `+crt-static` for `x86_64-pc-windows-msvc`.

`build.rs` records the SHA-256 of the sources (`Cargo.toml`, `Cargo.lock`, `build.rs`, `src\**`, CRLF read as LF);
`rigtool version` prints it. `vm\truth\m1b.sh` refuses to collect with a binary built from other sources (review R5 S1).

## Commands

### snap

```
rigtool snap [--root SPEC]... [--no-values] [--threads N] -o snap-<run>-<phase>.tsv.gz
```

- No `--root`: the default roots of RIG.md §2 (HKLM\SOFTWARE, HKLM\SYSTEM\CurrentControlSet minus `Enum` and
  `Control\DeviceClasses`, every loaded HKU hive, the file system roots).
- `SPEC` is a registry key (`HKLM\...`, `HKEY_LOCAL_MACHINE\...`, `HKCU\...` = the current user's
  `HKU\<SID>`, `HKCR\...` = `HKLM\SOFTWARE\Classes`) or a path (`%VAR%` is expanded). Suffix `@1` = the root
  and the entries directly inside it only.
- Run elevated in the VM. Unelevated it works and counts access errors (stderr shows them by Win32 code).
- Besides the RIG.md records, the file carries `#roots` and `#exclude` lines (what was captured); `score`
  uses them to tell "absent" from "not captured". A `K` record with empty `n_values`/`n_subkeys` is a key that
  was enumerated but could not be opened (its error is counted). A `#denied<TAB>path` line marks a key or
  directory whose listing (subkeys, values or entries) failed or is incomplete; `score` treats anything below
  it (or below a `K` record without counts) as unknown, never `gone`.
- Registry links are recorded (`K` + `V SymbolicLinkValue`) and never followed. A root that is itself a
  link onto another captured root (`HKU\S-1-5-18` -> `HKU\.DEFAULT`) is written as that link record only; a
  link root whose target is not captured otherwise (`HKLM\SYSTEM\CurrentControlSet`) is followed.

### Canonical registry names

Every key in a plan, label file, deny file or `--root` goes through the same canonicalisation, which folds
the Windows registry links onto the name the capture holds the data under:
`HKU\<user SID>\Software\Classes` -> `HKU\<user SID>_Classes` (user SIDs `S-1-5-21-…`, `S-1-12-1-…` and the
run's SID only; `HKU\.DEFAULT\Software\Classes` is a real key), `HKU\S-1-5-18` -> `HKU\.DEFAULT`,
`HKLM\SOFTWARE\WOW6432Node\Classes` -> `HKLM\SOFTWARE\Classes\Wow6432Node`, and
`HKLM\SOFTWARE\WOW6432Node\{Clients,Policies,RegisteredApplications}` -> `HKLM\SOFTWARE\…`. `score` also
resolves any other link key recorded in snap-0/snap-2 to its target. Snaps from before this rule that
followed `HKU\S-1-5-18` are read without the duplicate records below it.

### diff

```
rigtool diff A.tsv.gz B.tsv.gz [--json]
```

Text output: `op TAB rec TAB path [TAB value-name] [TAB changes]` with `op` = `+` added, `-` removed, `~` changed,
fields escaped like the snap format. `--json` prints `{summary, added, removed, changed}`.

### truth

```
rigtool truth --s0 snap-0 --s1 snap-1 --s2 snap-2 --lists0 lists-0.json --lists2 lists-2.json --run run.json
              [--ambient vm\truth\ambient.json] [--labels vm\truth\labels\<id>.json] [--deny vm\truth\deny.json]
              [--sid S-1-5-21-...] -o vm\runs\<id>\truth.json
```

- `--s0`, `--s2`, `--lists0`, `--lists2`, `--run` and `-o` are required (`--s1` is optional).
- The user SID (for `HKCU` in label and deny files) comes from `--sid`, else `run.json.sid`, else the snap.
- `kept_owner` anchors come from `run.json.entries_left` (strings or uninstall-entry objects) and from ARP
  entries present in `lists-2` but not in `lists-0`: the ARP key, its InstallLocation (unless it is a broad
  folder), its DisplayIcon / uninstaller exe, and its MSI product keys.
- New subtrees are collapsed to their top-most key or dir. When such a subtree also holds something a
  still-installed product owns (an anchor above, or a `kept_owner` rule match), the collapsed item is split:
  the kept subtree becomes its own `kept_owner` item, every other child on the way becomes its own item,
  the container keys' values become `RegValue` items, and the container itself is no item (offering it
  covers a `kept_owner` item, so it scores `danger`).
- Each item also carries `in_s1` (present after install) and, for paths, `dir` and the total `size`.
- `deny_hits` lists leftover/user_data items that match the deny file (a hint that a label rule is missing).

Label file (`vm\truth\labels\<id>.json`):

```json
{ "id": "python", "rules": [ { "label": "kept_owner", "match": "^K:HKLM\\\\SOFTWARE\\\\Python\\\\PyLauncher", "why": "Python Launcher MSI still installed" } ] }
```

`match` is a case-insensitive regex on the canonical target string (`P:`, `K:`, `V:<key>|<name>`,
`C:<key>|<name>`). An optional `"include": ["_os.json"]` loads other label files (relative to this one)
first. Precedence: rig, `first` rules, the built-in list rule (a `;`-list value whose segments are
unchanged is ambient), ambient set, `ambient` rules, `kept_owner` rules, entries_left, `user_data` rules,
`leftover` rules, default `leftover`. A rule may carry `"first": true` (checked before every ambient
source: an attributable exception such as the app's own Prefetch file) or, on an ambient rule,
`"split": true` (the rule labels a Windows container only; its new children are emitted as items and
labelled again). See vm/RIG.md §5. `vm\truth\mk_labels.py` generates `_os.json` and the per-app `gen` rules.

### ambient

```
rigtool ambient --null vm\runs\null1 vm\runs\null2 vm\runs\null3 -o vm\truth\ambient.json
```

Each directory needs `snap-0.tsv.gz` and `snap-2.tsv.gz` (or `snap-<run>-0/2.tsv.gz`). Output:
`{ runs: [{id, dir, exact, patterns}], exact, patterns }`; patterns are anchored regexes where GUIDs, hex
runs of 16+ and numbers of 6+ digits are wildcards (path/key patterns also match descendants).

### score

```
rigtool score --set vm\runs\firefox vm\runs\git ... [--deny vm\truth\deny.json] [--sid S] --json score.json --md score.md
rigtool score --plan a.json [--plan b.json] --truth truth.json --s0 snap-0 --s2 snap-2 [--deny ...] --json ... --md ...
```

- `--set`: each APPDIR holds `truth.json`, `snap-0.tsv.gz`, `snap-2.tsv.gz` and `plans\*.json` (one plan per
  tool). Without `--deny`, `APPDIR\..\..\truth\deny.json` is used if it exists.
- Per offered item: an item absent from snap2 is `gone` (a no-op) first, then `danger` > `hit` > `ambient` >
  `other`. `danger` also covers an item inside a `kept_owner` item. Items whose existence is unknown
  (outside the captured area, a value under a depth-1 root, a segment of a cut preview) are never `gone`.
- An `AppxPackage` offer skips the deny check (it goes through the package API) and covers the truth items
  that name its full or family name, its `AppContainer\Mappings` key (by `Moniker`) and its
  `PackagedCom\ClassIndex\{CLSID}` keys (by the package child key). RIG.md §7.
- Metrics per (app, tool) and the macro mean per tool; `partial_n` = truth items not covered but partially
  matched. Without `--md` the Markdown goes to stdout.
- `recall_listed/visible/safe` follow RIG.md §7 (covered by any offered item, `danger` ones included).
  `recall_listed_nd/visible_nd/safe_nd` count only coverage by offered items whose outcome is not `danger`,
  so a tool that offers a broad pre-existing folder or key does not earn recall for what lies below it.
- Notices (ruling 2026-11-18, review R5 B1): an item with action `ReportOnly` and a `suggest_uninstall` field
  (not preselected, not Safe) suggests uninstalling a related product. It is not scored (no danger, precision,
  recall, `protected_correct`, `offered_n`) and is listed under `notices` with what it would have scored.

Deny file: an array (or `{ "deny": [...] }`) of regex strings on the canonical target string, or objects
`{ "match": "<regex>", "why": "..." }` or `{ "target": {"type": "Path", "path": "..."}, "why": "..." }`
(an offered item equal to or containing that target is danger).

### convert

```
rigtool convert --clone vm\results\firefox-clone-uninstall.json --app firefox -o plans\clone.json
rigtool convert --removed vm\results\firefox-ut-removed.json --tool ut --app firefox -o plans\ut.json
rigtool convert --removed vm\results\firefox-bcu-removed.json --tool bcu --app firefox -o plans\bcu.json
```

Clone leftovers: `checked` -> band Safe + preselected, unchecked -> band Likely. UT/BCU removed lists: band
Safe, preselected. Inputs may have a UTF-8 BOM.

### baseline

```
rigtool baseline --snap vm\runs\null1\snap-0.tsv.gz -o kb\baselines\
```

With a directory (or a trailing `\`) as `-o`, the file is named `<EditionID>-<build>.<ubr>.tsv.gz`.

### invdiff

```
rigtool invdiff --inv inventory.json --lists lists-<run>-<phase>.json [--explain vm\truth\inventory-explain.json]
                [--sid S-1-5-21-...] [--json out.json] [--md out.md]
```

The M1a inventory exit check (ENGINE_PLAN §11.1, §4.1): the engine's inventory (`purge-engine inventory --json`,
`purge.inventory/0`, read through rigtool's own serde structs) against the rig's raw enumeration. Exit code 1
when any difference has no explanation rule (0 otherwise); without `--md` the Markdown goes to stdout.

- Reference set: the `uninstall[]` rows of the lists file (riglib `UninstallEntries`: HKLM 64-bit view,
  `WOW6432Node`, `HKU\<sid>` of the loaded `S-1-5-21-…` hives) by canonical key, plus the `msi[]` product codes.
  riglib `MsiProducts` is a **registry enumeration** of `Installer\UserData\<SID>\Products`, while the engine
  calls `MsiEnumProductsExW`; an MSI difference can therefore come from the two methods themselves (advertised
  products, a context the registry walk does not see) and is itself something to explain.
- Engine set: `entries[]` by canonical `key_path`; MSI codes = `msi_only[]` plus the `product_code` of every
  entry with `msi` set (merged with a Windows Installer product). Codes are compared as sets.
- Keys on both sides are canonicalised like everything else (see "Canonical registry names");
  `HKEY_CURRENT_USER` maps to `HKU\<sid>` with `--sid`, else the lists file's `user_sid`.
- Reported: `only_in_engine`, `only_in_reference` (subject `key` or `msi`) and `mismatches` on keys present on
  both sides for `name`, `version`, `uninstall`, `quiet`, `sys` (SystemComponent), `parent` (ParentKeyName,
  case-insensitive) and `product_code` (case-insensitive). Values are compared trimmed with blank = absent (the
  engine trims and drops blank values); a missing reference name stands for the key name (the engine's
  `display_name` fallback). riglib reads values with .NET `GetValue`, which expands `REG_EXPAND_SZ`, while the
  engine keeps them as written, so a `%VAR%` in the engine's value matches any text (`counts.expanded`).
- `--lists` also accepts the legacy array `vm\results\lists-registry.json` (rows
  `{key,name,version,sys,parent,uninstall,quiet,size,loc}`); it has no MSI list and no product code column, so
  those are not compared (`msi_compared: false`).

Explanation file (`vm\truth\inventory-explain.json`), `{ "rules": [...] }` or a bare array:

```json
{ "rules": [ { "match": "^HKU\\S-1-5-(19|20)\\\\", "side": "engine", "why": "service hives: riglib reads S-1-5-21-* only" } ] }
```

`match` is a case-insensitive regex on the canonical key path or the MSI code; `side` is `engine`,
`reference`, `mismatch` or `any` (default); an optional `field` limits a rule to mismatches of that field. The
first matching rule wins. The report lists `unused_rules` so stale rules can be removed.
