# Rust UI handoff (paused 2026-11-26 at the user's request, after 0.2.0-alpha.4)

The Rust UI is `bins/purge-ui` (Purge.exe) on the shared toolkit `mdshared-ui`/`mdshared-app`. The plan is
`docs/UI_RUST_PLAN.md`. Work branch `ui/rust`, pushed; `baseline` and `main` are fast-forwarded to it at every
release. Read this file, then `git log --oneline -15` and `git worktree list`.

## Where things stand
- **Released**: GitHub pre-releases 0.2.0-alpha.1 to alpha.4 (`docs/release-notes/`). alpha.4 adds window
  place memory, whole-window Mica/Acrylic with a strength slider (trial), toolkit pin f45a71c, launch
  fixes (no unfiltered first list, `icons_visible` marker) and the fix for an idle CPU spin. Fable reviewed it
  (no blockers); S3 (`PURGE_ENGINE` only with `--bench-exit` or a debug build) and the note fixes were taken.
- **Release rule (user, 2026-11-26)**: release at every major milestone without asking. Call it beta
  (0.2.0-beta.N) only once the new window has passed the VM end-to-end test (real uninstall, move, restore from
  the Rust UI) and Fable approves. Steps: bump `[workspace.package] version` in Cargo.toml, `cargo update -w`,
  write `docs/release-notes/<v>.md`, push `ui/rust` to `baseline` and `main`, then
  `gh workflow run release.yml --ref main -f publish=true`.
- **Gates** (all green at alpha.4): `cargo fmt --all -- --check`; `cargo clippy --release --workspace
  --all-targets -- -D warnings`; `cargo test --release -p purge-ui -p purge-ui-model -p purge-client`; the
  release `Purge.exe --sample --script` (111 steps); `cargo run --release -p xtask -- check-deps`.
- **Launch time** (laptop i7-6700HQ, real engine, `cargo xtask bench-launch --real-engine`): names_visible p50
  272 ms / p90 281 ms (targets 400/460), icons in the same frame with a warm cache, cold-cache icons 630 ms.

## Open work, in order
1. **alpha.5 from the alpha.4 review** (Fable session ses_deb6b2a0effet0UVfWhHzws4Ou, job_3zg_8):
   - S1: the contrast clamp in `glass.rs` (`worst_contrast`) must also cover the Bold rail gradient and the
     page-title hero band;
   - S2: `Store::save_window` must re-read the file and replace only the `window=` line (two windows overwrite
     each other's prefs);
   - nits N3 to N11 (N4: no full-size frame copy in "Title and rail" mode; N7: stop `take_patches` when the
     engine closes; N8: hash only the on-screen rows; N9: check whether an approved retry can be reported as
     "nothing was tried").
2. **Security prompt in the toolkit (BROKER-CONSENT-UI)**, branch `broker/consent-ui`, worktree
   `E:\purge-ui-wt\consent`, NOT merged. Step 1 is built behind `--consent toolkit`; TaskDialog stays default.
   Fable's security review (session ses_deba15488ffeUHYhw3UXDn9lYE) found blockers B1 (per-user fonts can supply
   the glyphs the elevated dialog draws; needs a toolkit API for a fixed font list), B2 (release builds accept
   the switch) and B3 (the VM test would not catch a wrong code, wrong arming or parent loss), plus S1-S10.
   A fix job (job_3zg_7, same session) was working on everything but B1 when the pause came. It was stopped
   mid-gates; its edits (32 files) are the pushed commit 47059ad "WIP (unverified)" on the branch. Check them
   against the review, run every gate, then squash or fix up. Merge only after B2 is fixed and gates pass; the toolkit dialog becomes the default only
   after the review's list (b) is done, including a real VM run of `m3-consent -ConsentUi toolkit`.
3. **VM: the broker start-check fix** (branch `fix/broker-start-checks`, worktree `E:\purge-fix-wt`), NOT
   merged. The e2e run `e2e-branch2` scored 127 PASS / 16 FAIL, because the null re-record (`null-fix1`) failed
   twice on vscode while E: was full (17:07 and 18:40 on 2026-11-25), so no new ambient set was written and the
   old set does not match the new binaries (collateral and provenance fails). Also 3 G12 timing fails
   (vscode scan 1.88x and harvest 34 s, msi3010 scan 1.77x the walk floor). Next: rerun the null set
   (`vm\rig-m3.ps1 -Mode m3-e2e-null -Count 3 ...`, command in the previous coordinator's log
   `C:\purge-build\null-fix1.log` header), commit the ambient json, rerun e2e, score with
   `vm\truth\m3-e2e-score.ps1 -Evidence <dir> -Collect`, merge if green. Look at the G12 timings separately.
   Then the remaining M3 modes (consent, uac, recover, clean), the B10 M1b reruns and the M3 gate doc.
4. **Rust UI, later**: the VM UI end-to-end test for the Rust UI (the beta gate); delete `ui/` (WinUI) and the
   dotnet CI; a Narrator pass (the user may do it some time; not done).
5. **Toolkit (shared) report**: C1 numbers, touch and single instance not needed, Narrator not done, two
   wishes (a backdrop veil parameter; faster region blends). Given to the user to pass on; the toolkit must
   not be changed from this repository.

## Rules that still hold
- Claude Code runs unelevated. Never confirm UAC or run a real uninstall on the dev PC; elevated paths are
  tested in the VM. Never use VBoxManage while a VM run is going; never touch other VMs.
- Agents use their own `CARGO_TARGET_DIR` under `E:\purge-target\<name>`, release builds only; keep E: above
  5 GB free (the VMs live there). E: had 18 GB free at the pause.
- Long jobs on the opencode bridge must run builds in the background and print progress at least every
  4 minutes (idle limit 20 minutes).
