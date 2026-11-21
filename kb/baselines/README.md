# kb/baselines

What a clean Windows install contains, per (edition, build), for the engine's "present on clean Windows"
check (ENGINE_PLAN.md §5.5, §10.2). Written by `rigtool baseline` from the `snap-0` of a clean snapshot that
never had a test app installed, minus rig-owned items. vm/RIG.md §2 and §8 are the authoritative format.

## Baselines

| File | Machine | Source snap-0 | Records (K / V / D / F) |
|---|---|---|---|
| `EnterpriseSEval-26100.1742.tsv.gz` | corpus VM `Inbound-Win11-Test`, Enterprise LTSC eval | `vm/runs/null1/snap-null1-0.tsv.gz` | 275,872 / 460,215 / 2,158 / 15,050 |
| `Professional-26340.9882.tsv.gz` | Clean-Pro VM `Purge-CleanPro`, Pro Insider | `vm/runs/cleanpro-null1/snap-null1-0.tsv.gz` | 309,932 / 528,901 / 6,001 / 37,410 |

The Professional baseline matches a host only on build 26340.9882. A host on another build has no matching
baseline and gets values-only + X-SYSTIDY (ENGINE_PLAN §5.7.1).

`view.json` (`purge.baseline-view/1`) is not a baseline: it lists the registry areas of the local-baseline view and
the neighbour rule (docs/BASELINE_LOCAL_DESIGN.md §4.1, §4.2; `vm/RIG.md` §8a). Its `merged` / `local` flags are set
only by gate M from the measurement reports.

## File name

`<EditionID>-<build>.<ubr>.tsv.gz`, e.g. `EnterpriseSEval-26100.1742.tsv.gz`.

## Encoding

- gzip, UTF-8, LF line endings.
- First line: the header, `#purge-baseline 1\t<iso time>\t<computer>\t<edition>\t<build.ubr>`.
- Second line: `#source\t<snap file>`, the snap-0 it was built from (e.g. `vm/runs/null1/snap-null1-0.tsv.gz`).
- Then one record per line, fields separated by TAB. In text fields `\`, TAB, LF and CR are escaped as
  `\\`, `\t`, `\n`, `\r`, and NUL as `\0`.
- Registry keys use canonical roots (`HKLM\SOFTWARE\…`, `HKLM\SYSTEM\CurrentControlSet\…`, `HKU\<SID>\…`,
  `HKU\<SID>_Classes\…`, `HKU\.DEFAULT\…`); paths are absolute without a `\\?\` prefix.

## Records

Only these four record types; no sizes, times or previews.

| Rec | Fields | Meaning |
|---|---|---|
| `K` | key | registry key |
| `V` | key, name, type (u32), hash | registry value; `name` empty for the default value; `hash` = first 16 hex chars of SHA-256 of the data |
| `D` | path | directory |
| `F` | path | file |

`*.tsv.gz` files are ignored by git everywhere except in this directory.
