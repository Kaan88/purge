# Maintenance plan (draft, for after M3)

User, 2026-11-18: the VM work occupies the PC too much, but keeping the app up to date matters. Goal: keep Purge
current with as little load on the user's PC as possible. To be designed in detail once M3 is done.

## 1. Move VM testing off the user's PC

- **GitHub Actions Windows runners** (free for a public repository). Each job is a fresh Windows VM with admin rights,
  thrown away afterwards: install, snapshot, uninstall, scan, score, without snapshots or a password file. Fits the
  "install one app, check its leftovers" test. Limits: Windows Server images, not Windows 11 client; the image has many
  tools preinstalled (it behaves like dirty-base); 6 h per job. Good for KB entries and app updates; not a replacement
  for the Windows 11 client gates.
- **Windows 11 client runs** where needed (gates, new Windows builds): a cheap dedicated rig box (a used mini PC), or
  cloud Windows 11 VMs on demand (Azure, paid per hour). Either way the user's PC stays free.
- **The user's unused laptop as the rig host** (user, 2026-11-18): the first candidate for the dedicated box. Needs:
  hardware virtualization on, 16 GB RAM or more (one 4 GB rig VM at a time plus the host), about 150-250 GB free SSD for
  the VMs, their snapshots and the installer cache, mains power with sleep off, wired network if possible. Move the
  VMs by copying their folders (or OVA export with snapshots) and install the same VirtualBox version. Run Claude Code
  (or a scheduled agent) on the laptop itself, so campaigns never touch the main PC.
- If the rig stays on this PC: campaigns only at night or when idle (scheduled task), one VM, lower priority, a memory
  floor check before each step, and a handle-count check.

## 2. Test only what changed

- Most regressions are caught without any VM: the replay of frozen snapshots (`cargo xtask replay`) and the unit tests
  run in minutes in CI on every commit.
- VM runs only when an input changes: a new version of a covered app, a new Windows build (new baseline), or an engine
  change that the replay cannot cover.
- A small watcher (scheduled job, cheap model) checks winget manifests for version bumps of the covered apps and
  Windows release notes for new builds, and opens an issue or a test job only then.

## 3. Separate engine releases from data releases

- The engine changes rarely and passes the full gates.
- The knowledge base and baseline packs change often and ship as signed data updates on their own channel, tested by
  the cheap runner jobs above. Most "keep up to date" work is data, not code.

## 4. Let users carry part of the load

- Community knowledge base (docs/FUTURE_IDEAS.md): reviewed pull requests, rig-tested by the runner jobs, signed
  releases.
- Opt-in "report a missed leftover" from the app: scrubbed of user names, SIDs and personal paths; becomes a draft entry
  for review, never an automatic change.

## 5. Routine work by agents

- Scheduled cloud agents (not on this PC): weekly check for new app versions and Windows builds, run the runner jobs,
  summarise results, draft KB updates as pull requests for the user to approve. Cheap models for routine checks,
  Fable reviews for anything that touches the guard or the executor (the review rule stands).

## Suggested order

1. After M3: move the replay and unit tests to GitHub Actions (no VM needed).
2. Add a runner job that tests one app's leftovers on a fresh Windows Server VM; use it for KB pull requests.
3. Add the version watcher and the scheduled agent.
4. Decide on a dedicated rig box or cloud Windows 11 for the client gates.
