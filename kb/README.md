# kb: Purge knowledge base

Static data the engine loads (ENGINE_PLAN.md §3.2, §5.9). Loaded by `purge-kb` and `purge-index`; every
file is code-reviewed and shipped as a snapshot per release, with no network fetch.

JSON has no comment syntax, so each data file starts as an empty array and is described here.

| Path | Contents | Used by | Lands in |
|---|---|---|---|
| `packs/` | Per-app knowledge packs (declarative JSON, §5.9) | `purge-kb`, `purge-scan` | M4 |
| `baselines/` | Clean-Windows key/value/path sets per (edition, build); format in `baselines/README.md` | `purge-index` | M0 (built by the rig) |
| `generic-tokens.json` | Name tokens too generic to count as identity evidence on their own (e.g. "update", "helper") | `purge-identity` | M1a |
| `mega-vendors.json` | Publishers with many unrelated products, whose name alone never proves ownership | `purge-identity` | M1a |
| `shared-components.json` | Paths and keys shared between products (runtimes, common files) that are never offered as one app's leftover | `purge-guard`, `purge-index` | M1a |
| `shared-iids.json` | COM interface ids registered by many products (proxy/stub, type-library marshalling) | `purge-scan` (COM scanners) | M1b |
| `deny.json` | Deny-list data beyond the built-in rules of `purge-guard` (§5.10), seeded from BCU's (Apache-2.0, attributed) | `purge-guard` | M1a |

Licence-clean seed sources only (§5.9): our VM truth runs, winget-pkgs (MIT), Scoop Main (Unlicense),
`chocolatey-community/chocolatey-packages` (Apache-2.0), BCU deny data (Apache-2.0). Winapp2 and BleachBit
are reference reading only.
