# Purge

Purge is a Windows uninstaller and leftover cleaner. It runs an app's own uninstaller, then finds what the
app left behind by proving ownership from what the app registered *before* it was removed, and moves the
leftovers to a quarantine it can undo. Nothing is deleted outright, and only the user approves a removal.

Status: **M0** (repo hygiene and the VM rig). The engine crates are skeletons; `purge-model` holds the
first real types. The plan is `docs/ENGINE_PLAN.md`; milestones are in its §11.1.

## Layout

| Path | What |
|---|---|
| `crates/` | Engine libraries (Rust): `purge-model` (shared types), `purge-win` (Win32; feature `write` for the executor only), `purge-source`, `purge-inventory`, `purge-identity`, `purge-harvest`, `purge-index`, `purge-scan`, `purge-guard`, `purge-policy`, `purge-plan`, `purge-exec`, `purge-kb`, `purge-rpc`. Each `lib.rs` states its job and milestone. |
| `bins/purge-engine` | The medium engine: `--stdio` server and CLI verbs (ENGINE_PLAN.md §3.4) |
| `bins/purge-broker` | The elevated broker: harvest, uninstall, scan, consent, execute and undo (M3) |
| `bins/purge-mcp` | AI-agent MCP server (M6). Never links the executor. |
| `tools/xtask` | `cargo xtask ui-strings \| check-deps \| ci` |
| `kb/` | Knowledge base: packs, clean-Windows baselines, vendor and shared-component data |
| `ui/` | WinUI 3 app (M3; placeholder) |
| `install/` | `install.ps1` (M2; placeholder) |
| `vm/` | VM rig that measures real leftovers and scores plans; contract in `vm/RIG.md`. `vm/rigtool` and `vm/harness` are separate Cargo projects, outside the workspace. |
| `docs/` | `ENGINE_PLAN.md` (the plan), `PARITY.md` (feature parity), `COMPARISON.md`, `ENGINE_RESEARCH.md` |

## Build

Needs Rust 1.99.1 (pinned in `rust-toolchain.toml`) on x86_64 Windows. Binaries link the static CRT
(`.cargo/config.toml`).

```
cargo build --workspace
cargo run -p purge-engine -- --version
cargo xtask ci          # fmt check, clippy -D warnings, tests, purge-mcp alone, check-deps, ui-strings
```

`ui-strings` compares our string literals with a local copy of the reference product's English language
file, given by the `PURGE_UT_STRINGS` environment variable. That file is never committed or copied into
the repo. Without the variable the check is skipped.

## Licence

Purge is licensed under the MIT License (`LICENSE`). Code ported from Bulk Crap Uninstaller stays under
the Apache License 2.0; its attribution is in `NOTICE` and `THIRD_PARTY.md`.
