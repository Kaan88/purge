# Reading notes A: design-file schema, xtask, installer

Repo root = worktree root. All paths below are relative to it.

## 1. Design JSON schema (`M2_DESIGN.json`, `BASELINE_LOCAL_DESIGN.json`)

Both files are a single JSON object; both put a long free-text `summary` first and a `packages`
array next. They are not the same schema: M2 is the executor design, baseline is the local-baseline
design, and each has keys the other lacks.

**Top-level keys**
- `docs/M2_DESIGN.json:2` `summary`, `:3` `packages`, `:635` `waves`, `:682` `gate_procedure`,
  `:683` `risks_and_questions`, `:704` `decisions`, `:715` `cross_package_notes`.
- `docs/BASELINE_LOCAL_DESIGN.json:2` `summary`, `:3` `starts_after`, `:4` `model_routing`,
  `:5` `invariants`, `:14` `budgets`, `:21` `packages`, `:299` `waves`, `:307` `review_points`,
  `:311` `cut_or_move`, `:317` `open_questions`.
- There is no shared schema id/version field, no top-level `title`, and no top-level `gate` key.
- `summary` is prose with embedded `\n` sections; M2's carries survey corrections, key decisions,
  model routing and the package/wave count (`docs/M2_DESIGN.json:2`).

**Package entry shape**
- Common fields: `id`, `title`, `importance`, `depends_on`, `est_size`, `crates_files`, `scope`,
  `acceptance`; `tests` is a string in M2 and an array in baseline.
- M2 extra: `plan_refs` (e.g. `"§7.4"`). No `wave` field: a package's wave is its index in `waves`.
- Baseline extra: `wave` (integer), `rules` (array of design rules), and `importance` may be `gate`.
- M2 example (`docs/M2_DESIGN.json:6-31`):
  - `id`: `"M2-S0"`, `title`: `"Scaffolding: manifests, module lists, stub files"`,
    `importance`: `"trivial"`, `depends_on`: `[]`, `est_size`: `"S"`.
  - `scope` starts: `"Only manifests and module lists, so later waves never share a file. (a) Workspace Cargo.toml: add base64 ..."`
  - `acceptance`: `"cargo build --workspace, cargo build -p purge-win --features write, ... xtask check-deps still passes; ..."`
  - `tests`: `"Build-only plus existing suite (use a private CARGO_TARGET_DIR). No new tests."`
- Baseline example (`docs/BASELINE_LOCAL_DESIGN.json:23-41`):
  - `id`: `"BL-WIN-SXS"`, `wave`: `1`, `importance`: `"medium"`, `est_size`: `"S"`.
  - `scope` starts: `"Read feature only. find_base(): newest WinSxS\\amd64_microsoft-windows-servicingstack_* directory ..."`
  - `rules[0]`: `"No write API, no process spawn. The base is read once per build."`
  - `acceptance`: `"win-unit passes on both rig VMs and the host; 0 failures over all manifests of the three machines, or every failure explained."`

**Waves**
- M2: array of arrays of package ids, 9 waves (`docs/M2_DESIGN.json:635-681`). Example:
  `[["M2-S0"], ["M2-MODEL","M2-WIN-FS", ... ], ...]`; last wave is `["M2-GATE"]`.
- Baseline: same shape but written on one line per wave, 6 waves
  (`docs/BASELINE_LOCAL_DESIGN.json:299-306`); example `["BL-BUILD","BL-RIG-DIFF"]`.
- Baseline duplicates the wave as a package field; M2 does not.

**Gate criteria**
- M2: one long `gate_procedure` string (`docs/M2_DESIGN.json:682`), not structured. It contains a
  host per-wave gate, then VM sub-gates G0-G6 and an exit aggregate.
  - Host gate quote: `"Per-wave code gate (host, no VM): ... cargo fmt --check, cargo clippy -p <crate> ..., cargo xtask check-deps, ... vm/guest/tests/rig-selftest.ps1."`
  - VM quote: `"G0 install hardening (m2-install): (a) fresh install.ps1 -> SDDL ... equal the documented constants; re-run is a no-op."`
  - Exit quote: `"vm/truth/m2.sh aggregates into vm/results/m2-gate.{json,md}: guard_escapes 0, collateral 0, undo_fidelity 100% per row ..."`
  - The gate package `M2-GATE` restates the acceptance in `docs/M2_DESIGN.json:631`.
- Baseline: no `gate_procedure` key. Criteria live in package `acceptance` and `rules`, especially
  `BL-GATE` (`docs/BASELINE_LOCAL_DESIGN.json:283-296`): `"S1 flips = 0, danger_listed = 0, traps met, both VMs, merged and local. ..."`
  and `"A flip ... fails the gate at count 1."` (`:293`). The `.md` adds §8.3/§8.4 acceptance
  (`docs/BASELINE_LOCAL_DESIGN.md:472`, `:486`).

**Review points / cut_or_move / risks / open questions**
- `review_points` exists only in baseline (`docs/BASELINE_LOCAL_DESIGN.json:307-310`): objects with
  `after_wave`, `id`, `reviewer`, `attack`. Real entry:
  `{"after_wave": 3, "id": "BL-RM", "reviewer": "Fable", "attack": "Are the false-absent lists complete and honestly classified? ..."}`
- `cut_or_move` exists only in baseline (`:311-316`): plain strings. Example:
  `"S5 INF source: built only if gate M shows a need."`
- M2 has no `review_points`/`cut_or_move`; deferrals and review rules are prose inside
  `gate_procedure` (`:682`, "A critical package is reviewed by a second critical-tier pass ...")
  and in `risks_and_questions` (`:702`, "Not covered by any M2 package ...").
- M2 `risks_and_questions` (`docs/M2_DESIGN.json:683-703`) is a flat string array mixing user
  questions and risks. Example: `"USER QUESTION 1 (scope): ... Include service/task/firewall execute+undo in M2 now ... or defer them ...?"`
  and `"Concurrency risk: bins/purge-engine (cli.rs, args.rs), purge-model, ... are all modified-but-uncommitted M1a files ..."`.
- M2 also has `decisions` (strings, `:704-714`, e.g. `"USER 2026-11-12 Q1: service/task/firewall execute+undo DEFERRED to M1b."`)
  and `cross_package_notes` (strings, `:715+`, e.g. `"M2-INSTALL: M2-MODEL / M2-X-STORE: index.json starts as the 2-byte document {}, so the SessionIndex reader must accept an empty object ..."`).
- Baseline has `open_questions` instead (strings, `:317-324`, e.g. `"Q1 Unelevated runs without a cache: trust None with a warning (default), or an in-memory build each run?"`).
- Baseline `invariants` and `budgets` are string arrays (`:5-13`, `:14-20`); M2 has no equivalent keys.

**How the `.md` mirrors the `.json`**
- Only baseline has a paired `.md`; `M2_DESIGN.json` has no sibling `M2_DESIGN.md` in `docs/`.
- `BASELINE_LOCAL_DESIGN.md` is the prose design, the JSON is the package plan. The `.md` header
  points at the JSON: `"Package list: docs/BASELINE_LOCAL_DESIGN.json"` (`docs/BASELINE_LOCAL_DESIGN.md:3-4`).
- Mapping by heading:
  - `## 0. Summary` (`:6`) = `summary`.
  - `## 2. Invariants` (`:59`) = `invariants`.
  - `## 8. Measurement plan` (`:432`) carries the numbers behind `budgets`.
  - `## 9. Packages` (`:517`) is a table `| Wave | Id | Importance | What |` (`:522-536`), one row
    per JSON package; example `| 1 | BL-WIN-SXS | medium | purge-win: manifest expansion ... |`.
  - `## 10. Not now` (`:538`) = `cut_or_move`.
  - `## 11. Open questions` (`:545`) = `open_questions`.
  - `## 12. Assumptions not yet verified` (`:559`) has no JSON key.
- `review_points` is not mirrored as a heading; it is only in the JSON.

## 2. `tools/xtask/src/ui_strings.rs`: the `ui-strings` check

- Purpose: no user-visible string of ours may equal a string of the reference product
  (`tools/xtask/src/ui_strings.rs:1-5`; rule source ENGINE_PLAN §11.4).
- Reference data: an XML language file outside the repo, path in env `PURGE_UT_STRINGS`
  (`:16`, `:42-55`). If unset/empty the check prints `skipped` and passes (`:184-188`).
  Only our matching literal is printed, never the reference string (`:196-201`).
- Reference side parsed with `roxmltree`, DTD allowed (`:33-39`); only text/CDATA nodes, not
  attribute values (`:47-54`).
- Ours, by directory (`:142-165`):
  - `crates/**/*.rs`, `bins/**/*.rs` -> `lex::rust_literals`.
  - `ui/**/*.cs` -> `lex::csharp_literals`.
  - `ui/**/*.xaml` -> XML attributes and element text (`:58-77`).
- Directory walk (`:117-139`) skips build output only (`:86-101`):
  - `.git`, `.vs`;
  - `target` only when it holds Cargo's `CACHEDIR.TAG` (`:94-96`);
  - `bin`/`obj` only when the parent holds a `*proj` MSBuild file (`:97-99`, `:104-114`).
  - So `src/bin/*.rs` and a source module dir named `target` are still scanned (`:81-82`).
- Comparison rules (`:19-31`, `:168-181`):
  - literals shorter than 12 chars are ignored (`MIN_CHARS = 12`, `:15`);
  - both sides case-folded, whitespace collapsed, trailing whitespace/ASCII punctuation and
    `…。、：；！？` stripped (`normalize`, `:19-27`);
  - any normalised equality is a violation; exit is `Ok(false)` if any hit (`:183-226`).
- Output: `ui-strings: N match(es); M literals of 12+ chars in K files (...) vs R reference strings`
  (`:214-224`).
- Tests cover normalisation, length gating, the build-output walk, and XAML attributes/text
  (`:228-346`).

## 3. `xtask ci` ordered steps (`tools/xtask/src/main.rs`)

- Entry: `Some("ci") => ci(&workspace_root())` (`tools/xtask/src/main.rs:52`); implementation
  `:103-186`. It stops at the first failing step (`bail!`).
- Cargo steps, in order (`:104-158`):
  1. `cargo fmt --all -- --check`.
  2. `cargo clippy --workspace --all-targets -- -D warnings`.
  3. `cargo test --workspace`.
  4. `cargo clippy -p purge-mcp --all-targets -- -D warnings` (standalone tree; catches code that
     only compiles via another member's unified features).
  5. `cargo clippy -p purge-engine -p purge-exec --features purge-engine/rig-exec,purge-exec/test-support --all-targets -- -D warnings`.
  6. `cargo test -p purge-engine --features <rig features> --lib --test exec_cli --test engine`.
  7. `cargo test -p purge-exec --features purge-exec/fault-inject,purge-exec/test-support`.
- Then the xtask checks, in order (`:164-183`):
  8. `check-deps`.
  9. `no-new-walks`.
  10. `baseline-sites`.
  11. `ui-strings`.
  12. `scanner-coverage`.
- Feature constants: `RIG_FEATURES = "purge-engine/rig-exec,purge-exec/test-support"` (`:97`);
  `EXEC_TEST_FEATURES = "purge-exec/fault-inject,purge-exec/test-support"` (`:101`).
- Admin/VM: **none of the 12 ci steps needs admin or a VM.** All are host commands. The VM matrix
  (G0-G6, snapshots, power-off, reboot) is the separate M2 gate procedure, not part of `ci`
  (`docs/M2_DESIGN.json:682`). `ui-strings` quietly passes without the external reference file.
- The module doc at `tools/xtask/src/main.rs:19-22` describes this same order (it omits
  `baseline-sites` from that sentence, but `ci` does run it at `:172-175`).

## 4. `tools/xtask/src/check_deps.rs`: numbered rules

Header lists the rules at `tools/xtask/src/check_deps.rs:3-19`; `run()` at `:256-331`.

1. **MCP allowlist.** In `cargo tree -p purge-mcp`, the only Purge crates may be
   `purge-model` and `purge-rpc` (`ALLOWED`, `:32`). Implementation `own_tree_violations`
   `:63-83`; wired `:257-262`.
2. **Unified resolution.** For every other Purge crate in the workspace graph,
   `cargo tree --workspace -i <crate>` must not list `purge-mcp` (`:6-8`). Implementation
   `unified_violations` `:98-117`; wired `:264-274`. Messages say
   `"with workspace feature unification, purge-mcp depends on ..."`.
3. **No `purge-win/write` for MCP.** `purge-win` must not carry feature `write` in purge-mcp's own
   tree (`:9-10`, enforced `:78-80`).
4. **Executor containment.** Only `purge-engine` may link `purge-exec`; only with feature
   `rig-exec`; `fault-inject` comes on only through `rig-exec`; a default workspace build links
   `purge-exec` into nothing (`:11-14`, `:119-122`).
   - Implementation `exec_violations` `tools/xtask/src/check_deps.rs:146-199`; default-build
     counterpart `default_build_violations` `:209-235`; wired `:276-305`.
   - It also checks `purge-engine`'s default tree has no `purge-win/write` (`:225-233`).
   - Release builds are stated as `cargo build --release -p purge-engine`, because a
     `--workspace` build would unify `purge-win/write` into the engine (`:207-208`).
   - Trees are read with `-e normal,build` (`:241`).
5. **Forbidden identifiers in `purge-win`.** No service control, MSI product open/install/
   configure/repair, firewall-rule removal via `INetFwRules`, offreg write/merge/save call,
   hive mount (`RegLoadKey`, `RegLoadAppKey`), `netsh` or PowerShell (`:15-19`).
   - Lists: `FORBIDDEN_WIN_IDENTS` `:335-357`, `FORBIDDEN_WIN_WORDS` `:360`
     (`netsh`, `powershell`).
   - Checker `identifier_violations` `:386-406`; `INetFwRules` fails only with `Remove(` (`:400-404`).
   - Top-level `#[cfg(test)]` modules are stripped first (`strip_test_modules`, `:365-383`);
     an indented one is still checked (`:364`).
   - Applied to every `.rs` under `crates/purge-win/src` (`win_source_violations`, `:410-442`);
     wired `:307`.
- All listings use `cargo tree`; a malformed/unexpected first package is an error, not a pass
  (`:259-261`, `:154-158`, `:166-170`, `:215-219`).
- `xtask ci` also builds purge-mcp standalone (`:21-22` comment; `tools/xtask/src/main.rs:117-125`).

## 5. `install/install.ps1`: what it installs

- Runs elevated, 64-bit Windows PowerShell 5.1; modes install / `-Check` / `-Uninstall`
  (`install/install.ps1:1-5`, `:26-41`, `:619-623`). Refuses 32-bit PowerShell and non-elevated
  (`:622-623`). `-ReportPath` writes JSON schema `purge.install/1` (`:39-40`, `:620`).
- **Install locations**
  - `%ProgramFiles%\Purge`: `purge-engine.exe` plus the `kb\` tree (`:8-9`, `:626`, `:661-662`).
  - `%ProgramData%\Purge`: `sessions\`, `Quarantine\`, `fp\`, `kb\`, and
    `sessions\index.json` initialised as `{}` (`:10-13`, `:151-160`, `:627`, `:663`).
  - Defaults can be overridden for VM tests only via `-ProgramFilesDir` / `-DataRoot` (`:32-34`).
    Paths must be absolute drive paths with an existing parent (`:628-631`).
- **Admin-only directories / DACLs**
  - Both trees are created with a protected DACL, owner `BUILTIN\Administrators` (`BA`)
    (`:52-62`, `:74-88`).
  - `ProgramData\Purge` and `sessions`: SYSTEM full, Administrators full, `Users` traverse-only
    (`0x100020`, no list/read-attributes/create) (`:53-54`).
  - `Quarantine`, `fp`, `kb`: SYSTEM full, Administrators full; **no Users ACE** (`:55`).
  - `sessions\index.json`: SYSTEM/Administrators full, Users generic read (`FR`) (`:56`).
  - `%ProgramFiles%\Purge`: SYSTEM/Administrators full, Users read+execute, inherit-only
    (`0x1200a9`) (`:57`).
  - ACE flags are `OICI` (object+container inherit) except the Users traverse ACEs on
    `ProgramData\Purge` and `sessions`, and the Users read ACE on `index.json`; the
    `ProgramFiles` Users read+execute ACE is also `OICI` (`:53-57`).
  - Creation applies the security descriptor **in the same call**: `CreateDirectoryW` with
    `SECURITY_ATTRIBUTES`, `CreateFileW CREATE_NEW` with the SD and flushed data
    (`:376-408`, `:470-474`). This avoids an inherited-ACE window.
  - Existing tree adoption is strict (`:14-18`, `:168-217`, `:453-468`): every object must match
    owner + protected DACL + ACEs after canonical rendering; nothing at the top two levels may be
    a reparse point. Otherwise the root is renamed to `<name>.rejected-<utc>` through a
    no-follow handle (`RenameNoFollow`, `:344-364`), never adopted, never recursed into
    (`:504-513`). Creation retries a bounded 4 passes (`:491-533`).
- **Payload copy**
  - Engine copied to `%ProgramFiles%\Purge\purge-engine.exe` (`:559-561`).
  - `kb` files copied recursively; reparse points in the source are skipped; stale destination
    files are reported and left in place, never deleted (`:562-585`).
  - Files whose SHA-256 already matches are left alone (`:544-555`).
- **Environment variables**
  - It sets **none**. No `[Environment]::SetEnvironmentVariable`, no machine/user env writes.
  - `ProgramFiles` and `CommonApplicationData` are only read via `GetFolderPath` (`:626-627`).
  - The engine's kb is found next to the exe at run time (`:655-657`).
- **Registration**
  - It registers **nothing**: no service, scheduled task, registry key/value, shortcut, file
    association, or uninstall entry. The native P/Invoke surface is file/security only
    (`kernel32`/`advapi32`, `:271-288`). A grep for `Registry`, `New-Service`, `schtasks`,
    `New-ItemProperty` returns no hit.
  - `-Uninstall` removes only `%ProgramFiles%\Purge`, never `%ProgramData%\Purge`
    (`:19-20`, `:639-650`); it refuses a non-plain directory/reparse root (`:643-644`).
  - `-Check` verifies both trees read-only; exit 0 only when both are exactly `good`
    (`:634-638`, `:536-542`).
  - The script never downloads, signs, or changes Defender/System Restore settings (`:21`).
  - Install contract and SDDL constants are documented in `install/README.md` (`:7`); the
    self-test lives in `install/tests/install-selftest.ps1` (`:23-24`).
