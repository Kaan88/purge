# Handoff: Clean-Pro VM (DONE 2026-11-12)

**Finished.** Snapshots `rig-base-off` + `rig-base`, null run in `vm/runs/cleanpro-null1/`, baseline
`kb/baselines/Professional-26340.9882.tsv.gz`, docs updated. Lessons now in `bootstrap-vm.ps1` / `setup-base.ps1`:
guestcontrol cannot elevate (RunOnce + reboot instead), the unattended media must be ejected (it reinstalled
Windows on a cold boot), Fast Startup is turned off. The notes below are the original plan.

M0 is done (docs/M0_REPORT.md). This is the follow-up: build the Clean-Pro VM and its baseline.

## State

- VM **`Purge-CleanPro`** (`E:\purge-vm\Purge-CleanPro`) is created: Windows 11 **Pro Insider 10.0.26340.9882**
  from `C:\Users\kaank\Downloads\Windows11_InsiderPreview_Client_x64_en-us_26340_9882.iso` (image 6), EFI +
  Secure Boot + TPM 2.0, 4 vCPU / 4 GB, 3D off, SATA disk with **discard off** (discard on made setup's TRIM
  hang and the VM abort). User `tester`, password in the session password file (pass it only through
  `--passwordfile`; VBoxManage `unattended install` prints it, so filter its output).
- Installed with `VBoxManage unattended install`. Post-install command set
  `ConsentPromptBehaviorAdmin=0` (silent elevation) so the agent can bootstrap without a UAC click.
- Windows is at the desktop and the guest additions are installed (7.2.20). Guest control was **not ready** after
  first logon ("guest execution service is not ready"). The VM was rebooted (ACPI shutdown + headless start) on
  2026-11-12 ~00:10 to activate the guest additions. **After the reboot guest control works** (`guestcontrol run`
  as tester returned `purge-cleanpro\tester`), so step 1 can start right away.
- No snapshots taken yet on this VM.

## Next steps

1. `$env:VMPWFILE = '<password file>'; .\vm\bootstrap-vm.ps1 -VmName Purge-CleanPro`
   (waits up to 15 min for guest control, copies `agent.ps1`, starts it elevated, `Push-Tools`,
   `Invoke-SetupBase`, then restores `ConsentPromptBehaviorAdmin=5`). Check its log: `setup-base OK`,
   autologon (`AutoAdminLogon=1`, and no `AutoLogonCount` that would expire; if it expires, set autologon in a job).
2. Snapshots, as for the corpus VM (offline only):
   `. .\vm\rig.ps1 -VmName Purge-CleanPro; Save-BaseSnapshot -Off -Name rig-base-off`, restore it and check
   that `Wait-Agent` passes after autologon, then `Save-BaseSnapshot -Off -Name rig-base`.
3. One null run: `Invoke-Campaign -Nulls 1` (with `-VmName Purge-CleanPro` on the dot-source), then
   `rigtool baseline --snap vm\runs\null1\snap-null1-0.tsv.gz -o kb\baselines\` →
   `Professional-26340.9882.tsv.gz`. Careful: `vm\runs\null1` already holds the LTSC null run, and `Invoke-Run`
   moves it to `vm\runs\_old\`. Copy the LTSC one aside first or use a distinct run name.
4. Docs: `vm/RIG.md` §1 already has a draft Clean-Pro entry (verify facts); update `kb/baselines/README.md`
   (list of baselines), `docs/M0_REPORT.md` (Clean-Pro no longer blocked), `vm/truth/FROZEN.md` open points.
5. Not committed: `vm/rig.ps1` (`-VmName` param), `vm/bootstrap-vm.ps1`, `vm/RIG.md`, this file. Commit only
   when the user asks.

## Caveat to tell the user

The host is on **26300.9974**; the ISO is **26340.9882**. The baseline matches the host only after the host
moves to 26340. Until then the engine on the host has no matching baseline (values only + X-SYSTIDY, plan §5.7.1).

## User rules in force

See memory: model routing (M1a/M2 → Fable medium; high → Opus high; medium → Opus medium; trivial → Sonnet),
VM tests need no approval, official downloads only, never touch the clone/UT folders or other VMs.
M1 has not started; wait for the user's go.
