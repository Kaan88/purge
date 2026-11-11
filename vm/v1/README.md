# Rig v1 (superseded)

These are the first-generation VM rig scripts, kept for reference only: the host drivers `run-tests.ps1`,
`run-clone.ps1` and `score.ps1`, and the guest jobs under `guest\` (`lib.ps1` with its key-level `Snap`,
`test-app.ps1`, `lists.ps1`, `install-all.ps1`, `bcu-test.ps1`, `baseline.ps1`, the `diag-*` probes and the
`ut-*` helpers). They produced the measurements in `docs\COMPARISON.md` and the files in `vm\results\`. They
are replaced by rig v2 (`vm\RIG.md`, `vm\rig.ps1`, `vm\guest\riglib.ps1`, `run-app.ps1`, `null-run.ps1`,
`rigtool`) because they filtered noise at capture time, captured keys without values, never took a
post-install snapshot and did not restore the VM between apps (ENGINE_PLAN §2 L12/L15, §10.2). Do not run
them against `rig-base`; they still expect `C:\cr\guest\lib.ps1` and write into `C:\cr\out\` directly.
