Changes from m1a-wave-wf_67f1aac5-e39.js (Windows session 8033e7d2) to m2-wave-linux.js

1. meta.name m1a-wave -> m2-wave-linux; descriptions mention M2 and ci-linux.sh.
2. ROOT: C:\Users\kaank\Desktop\uninstall\purge -> /mnt/C/Users/kaank/Desktop/uninstall/purge. New WINROOT constant; RULES tell agents that design-file paths (all C:\...) map to ROOT/... with '/'.
3. DESIGN default: per-session Windows temp scratchpad m1a-design.json -> ROOT/docs/M2_DESIGN.json (args.design still overrides).
4. ROUTE: high was opus/high, now fable/medium (M2 crate code incl. high packages -> Fable medium, as the user requires). critical fable/medium, medium opus/medium (all medium M2 packages are rig/VM: RIG-DEEP, RIG-TRAPS, RIG-EXECDIFF, RIG-RUN, GATE), trivial sonnet unchanged. New: per-package override p.model / p.effort.
5. RULES: milestone M1a -> M2 (§7, §11.1); added "no git stash/checkout/reset", LF endings for new files, and the design's destructive-test confinement rule (temp dirs + HKU\<SID>\Software\PurgeTest-<random>). Removed the Windows build sentence (moved to BUILD).
6. New BUILD block replacing "cargo build/test/clippy -p <crate> with CARGO_TARGET_DIR=ROOT\target\pkg-<id>": cargo xwin build/test/clippy --target x86_64-pc-windows-msvc with the wine/xwin env; target dir ~/purge-target/pkg-<id> (never the repo's target/, C: nearly full), seeded by btrfs reflink copy of ~/purge-target/ci-linux; rigtool tested natively; ci-linux.sh as the full check; explicit "cargo xtask ci does not work on Linux"; pwsh 7 on Linux only for parse checks (install-selftest.ps1 22/62 and rig-selftest.ps1 13/14 fail here on Windows-only APIs).
7. Wine-limits rule: tests are written as for Windows, never weakened/ignored for wine; per-test 'needs_windows' list in the result.
8. Schemas: RES and REV gain optional needs_windows: string[].
9. Reviewer target dir ROOT\target\rev-<id> -> reuses ~/purge-target/pkg-<id>; cleanup instruction: impl leaves the dir when a review follows, the last agent deletes it.
10. Review prompt: M1a hunting list adapted to the executor (TOCTOU/handle use, link following, self-exemption scope, backup-before-act, journal ordering, wine-weakened tests); still Fable medium.
11. New args.review (importances to review, default ['critical'] = unchanged behaviour); pass ['critical','high'] to also review the high M2 crate packages.
12. New concurrency cap: args.maxParallel (default 3) package chains at once via an in-script semaphore (workflow cap here is min(16, 28-2)=16; 9 parallel cross-builds would not fit 31 GB RAM shared with 2 VMs + emulator or ~30 GB free disk).
13. Check phase: "cargo build/clippy/test/fmt --workspace" (Windows host) -> ~/purge-target/ci-linux.sh --rigtool with CI_TARGET_DIR ~/purge-target/ci-linux; report must classify unexpected test failures as wine limit vs bug; must not edit known-failure lists. Still Sonnet.
Unchanged: dependency-aware `after` scheduling, serial mode, args.context, args.packages shape, return value {results, check}.
