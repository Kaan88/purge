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

## Hub

This app is installed and updated by Hub (`Kaan88/mdhub`). What a release, the installer and the exe
must do for that is in https://github.com/Kaan88/mdhub/blob/main/docs/COMPLIANCE.md. Before changing
the release workflow, the installer, the exe's version resource or `tools/write-hub-txt.ps1`, read it.

In this repository: the one version is `[workspace.package] version` in `Cargo.toml` (the exes'
version resources, the UI assemblies and the setup take it from there; `install/inno/check-version.ps1`
fails the build on a difference), the setup is `install/inno/purge.iss`, the release is
`.github/workflows/release.yml` (tag `v<version>`), and `tools/write-hub-txt.ps1` is a copy of Hub's
script: re-sync it, do not edit it. Purge has no updater of its own, so COMPLIANCE section 6 does not
apply.

**v0.1.0 and Hub.** The published v0.1.0 was built before this, from d1393e7, whose `Purge.exe` has no
version of Purge in it: the .NET default, `FILEVERSION` 1.0.0.0 (inferred from the UI build of that
time; the released setup was not unpacked). Hub takes the version from that exe before the uninstall
entry's `DisplayVersion`, so on a PC with v0.1.0 installed it reports 1.0.0, takes that for newer
than any 0.x release and offers no update. A PC that has it needs the next release installed by hand
once (Hub reads the right version after that). To keep new PCs from getting it, the owner can replace
the v0.1.0 release with this workflow's build: delete the release and its tag on GitHub (the workflow
never overwrites a release), then tag `v0.1.0` on main. Otherwise the next release (a version bump) is
the first Hub can update to.

## Licence

Purge is licensed under the MIT License (`LICENSE`). Code ported from Bulk Crap Uninstaller stays under
the Apache License 2.0; its attribution is in `NOTICE` and `THIRD_PARTY.md`.
