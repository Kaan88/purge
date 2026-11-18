# Rig migration to the laptop (2026-11-19)

The user's laptop (32 GB RAM, nothing else on it) becomes the dev and VM rig host. This PC ("desktop") stops running
campaigns. Paused state: M1b scan gate campaign 4 stopped after G4a (see HANDOFF-m1b.md, top).

## Keep the same paths on the laptop

Rig scripts, docs, memory and VirtualBox configs use absolute paths. Use the same ones on the laptop:

- Repo at `C:\Users\kaank\Desktop\uninstall\purge` (same Windows user name `kaank` if possible). Claude Code's project
  memory is keyed by this path.
- An `E:` drive. If the laptop has no E: partition, map one: `subst E: C:\E` (make it permanent with a logon task or
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices` value `E:` = `\??\C:\E`).

## What to copy (sizes measured 2026-11-19)

| What | Desktop location | Size | Notes |
|---|---|---|---|
| Inbound VM | `E:\inbound-vm\Inbound-Win11-Test\` | 39 GB | `.vbox`, base `.vdi`, `Snapshots\` (6 disks). Snapshot tree: clean-off > pre-installers > rig-base > {dirty-base, m2-base}. 4 GB RAM, 4 CPUs. The folder also has `win11-ltsc-eval-x64-en-us.iso` (optional). |
| Inbound m2 data disk | `E:\purge-vm\inbound-m2-data.vdi` | 16 MB | Attached to Inbound's `m2-base` snapshot. Must keep this exact path. |
| Clean-Pro VM | `E:\purge-vm\Purge-CleanPro\` | 33 GB | Snapshot tree: rig-base-off > rig-base > m2-base. 4 GB RAM, 4 CPUs. |
| Installer cache | `<repo>\vm\cache\` (incl. `inst\cache-sources.json`) | 1.9 GB | git-ignored; official vendor installers with pinned hashes. |
| Run folders | `<repo>\vm\runs\` | 7.6 GB | git-ignored. Needed: the five frozen M1a runs replayed by G1 (`7zip`, `vscode`, `git`, `firefox`, `npp` and their snaps), the null runs behind `truth\ambient.json`, `_old\`, and campaign 4's runs (`m1b-*`, `m1bd-*`, `m1b-traps-7zip`). |
| Campaign 4 replay outputs | `<repo>\vm\truth\m1b-replay-score.json`, `.md`, and the modified `m1b-replay-diff.json` | small | Untracked/modified; only needed to continue campaign 4 instead of rerunning. Copies in `E:\purge-build\gate-evidence\m1b-gate6\collect\`. |
| Gate evidence | `E:\purge-build\gate-evidence\` | 5.5 GB | All campaigns' logs, archived runs (gate3-gate6), smoke runs. |
| M2-head engine (G7 baseline) | `E:\purge-build\m2-base\purge-engine-m2-3265797.exe` | 0.4 GB folder | Or rebuild from commit 3265797. |
| Guest password file | user's secrets folder on the desktop (path in Claude's local memory; ask the user) | tiny | Works for both VMs, guest user `tester`. Keep it outside any Temp folder on the laptop. |
| Claude Code memory | `C:\Users\kaank\.claude\projects\C--Users-kaank-Desktop-uninstall-purge\memory\` | tiny | Copy to the same path so the laptop session knows the project history. |
| UI alpha zip | `C:\Users\kaank\Desktop\Purge-ui-alpha-2.zip` | 46 MB | Optional. |

Not copied: build folders (`E:\purge-build\gate`, `ci-unelev`, `ui-alpha`, `<repo>\target`, `vm\rigtool\target`,
`vm\build`): rebuild on the laptop. The user's other VMs (DietPi, haiku) stay on the desktop.

Git branches on origin (`Kaan88/purge`): `main`, `m1a`, `m2`, `m1b` (work branch, head 8e1a1d2 + docs), `ui-alpha`,
`sandbox-dev`, `claude/ui-shell-7a9c31`. Clone and check out `m1b`.

## Software on the laptop

- Windows 11, hardware virtualization on in BIOS/UEFI, sleep off on mains power, wired network if possible.
- VirtualBox **7.2.20** (r175154), same as the desktop.
- Git for Windows (provides bash), Rust (toolchain pinned by `rust-toolchain.toml`), .NET SDK 10 with the Windows App
  SDK workload for the UI, Python 3 (scorer scripts), PowerShell 5.1 (built in).
- Claude Code, signed in.

## Copying over SSH (set up on the desktop 2026-11-19)

- Desktop: OpenSSH Server installed, service `sshd` (startup Manual, running), key-only login
  (`PasswordAuthentication no`), firewall rule `OpenSSH-Server-In-TCP` limited to the Private profile and the local
  subnet. Desktop LAN address: `192.168.1.115`, user `kaank` (an administrator, so its keys live in
  `C:\ProgramData\ssh\administrators_authorized_keys`, ACL SYSTEM + Administrators only).
- On the laptop: `ssh-keygen -t ed25519`, then put the content of `%USERPROFILE%\.ssh\id_ed25519.pub` into the desktop's
  `C:\ProgramData\ssh\administrators_authorized_keys` (one line; USB stick or typed by the user, or Claude on the desktop
  adds it when given the public key).
- Test: `ssh kaank@192.168.1.115 hostname`.
- Copy (the VMs must be powered off on the desktop), for example:
  `scp -r kaank@192.168.1.115:E:/inbound-vm/Inbound-Win11-Test E:/inbound-vm/`
  `scp -r kaank@192.168.1.115:E:/purge-vm E:/`
  `scp -r kaank@192.168.1.115:C:/Users/kaank/Desktop/uninstall/purge/vm/cache C:/Users/kaank/Desktop/uninstall/purge/vm/`
  and the same for `vm/runs`, `E:/purge-build/gate-evidence`, `E:/purge-build/m2-base`, the memory folder.
  For ~80 GB of VM disks over gigabit, expect about 15-25 min; Wi-Fi is much slower, use a cable or a USB drive.
- After the migration: `Stop-Service sshd; Set-Service sshd -StartupType Disabled` on the desktop (or keep it if the
  laptop session should reach the desktop).

## On the laptop, in order

1. Register the VMs: `VBoxManage registervm E:\inbound-vm\Inbound-Win11-Test\Inbound-Win11-Test.vbox` and
   `VBoxManage registervm E:\purge-vm\Purge-CleanPro\Purge-CleanPro.vbox`; `VBoxManage snapshot <vm> list` must show
   the trees above. Check the host-only network the VMs use exists (desktop: `192.168.56.1/24`) and the NAT adapter.
2. Restore `rig-base` on each VM and log in through guestcontrol with the password file (smoke: `cmd /c echo ok`).
3. Build: release engine (`CARGO_TARGET_DIR=E:\purge-build\gate`), `vm\rigtool` release (source hash must print
   391c9dc8...), run `install\install.ps1` elevated (creates `%ProgramData%\Purge`; G7 needs it).
4. Unelevated `cargo xtask ci` (scheduled task with `/rl LIMITED /it`, see HANDOFF-m1b.md) and the rig self-tests
   (`bash vm/truth/m1b.sh --selftest`, `vm/guest/tests/rig-selftest.ps1`).
5. One smoke run per VM (`rig.ps1 -Mode m1b-app -App 7zip`, and `-VmName Purge-CleanPro`).
6. Then the M1b scan gate: either continue campaign 4 (G4 dirty-base traps, G8, G7, `m1b.sh`) on the same commit and
   engine build, or, cleaner, a fresh full campaign. Ask the user. With 32 GB the two VMs could run in parallel after a
   small rig change (not done yet).
7. Then G5/G6 (`vm/rig-m1b-exec.ps1`), `docs/M1B_GATE.md`, Fable review.
