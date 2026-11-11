# kb/baselines

What a clean Windows install contains, per (edition, build), for the engine's "present on clean Windows"
check (ENGINE_PLAN.md §5.5, §10.2). Written by `rigtool baseline` from the `snap-0` of a clean snapshot that
never had a test app installed, minus rig-owned items. vm/RIG.md §2 and §8 are the authoritative format.

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
