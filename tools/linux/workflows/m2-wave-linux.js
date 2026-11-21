export const meta = {
  name: 'm2-wave-linux',
  description: 'Implement one M2 wave of packages on the Linux host (routed models), adversarially review critical ones, then run ci-linux.sh',
  phases: [
    { title: 'Implement', detail: 'one agent per package, model by importance (M2 code: Fable medium; rig: Opus medium; trivial: Sonnet)' },
    { title: 'Review', detail: 'Fable medium adversarial review + fix of critical packages', model: 'fable' },
    { title: 'Check', detail: 'Sonnet runs ~/purge-target/ci-linux.sh', model: 'sonnet' },
  ],
}
// Adapted from m1a-wave-wf_67f1aac5-e39.js (Windows session 8033e7d2) for the CachyOS host. Every change is listed in
// m2-wave-linux.CHANGES.md next to this file.
const ROOT = '/mnt/C/Users/<user>/Desktop/uninstall/purge'
const WINROOT = 'C:\\Users\\<user>\\Desktop\\uninstall\\purge'
const PT = '/home/kaan/purge-target'
// Routing (user, model-routing memory + M2 brief): M2 crate code and its reviews -> Fable medium (critical AND high);
// rig/VM/install packages (importance medium) -> Opus medium; trivial -> Sonnet. Per-package override: p.model / p.effort.
const ROUTE = { critical: ['fable', 'medium'], high: ['fable', 'medium'], medium: ['opus', 'medium'], trivial: ['sonnet', undefined] }
const DESIGN = args.design || `${ROOT}/docs/M2_DESIGN.json`
const pkgs = args.packages
if (!Array.isArray(pkgs) || !pkgs.every(p => p && p.id && p.importance)) throw new Error('args.packages must be [{id,title,importance}]')
const serial = !!args.serial
const REVIEW = args.review || ['critical'] // importances that get the adversarial Fable review
const MAXPAR = Math.max(1, args.maxParallel || 3) // concurrent package chains (cargo builds: RAM 31 GB shared with 2 VMs + emulator; ~30 GB free disk)
const ENV = `PATH=$HOME/.cargo/bin:$PATH XWIN_CACHE_DIR=$HOME/.cache/cargo-xwin XWIN_ARCH=x86_64 WINEDEBUG=-all WINEPREFIX=${PT}/wineprefix CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER=wine`
const tdir = id => `${PT}/pkg-${id}`
const BUILD = id => `Host is Linux (CachyOS); the engine only builds for Windows targets. Build/test with cargo-xwin on x86_64-pc-windows-msvc, tests under wine. Your private target dir is ${tdir(id)}: if it does not exist, seed it with \`cp -a --reflink=always ${PT}/ci-linux ${tdir(id)}\` (btrfs, near-free) or start empty; NEVER build into the repo's target/ (C: is nearly full). Commands (from ${ROOT}): \`${ENV} CARGO_TARGET_DIR=${tdir(id)} cargo xwin build -p <crate> --target x86_64-pc-windows-msvc\`, the same with \`cargo xwin test -p <crate> --target x86_64-pc-windows-msvc --no-fail-fast\`, and \`${ENV} CARGO_TARGET_DIR=${tdir(id)} cargo xwin clippy -p <crate> --all-targets --target x86_64-pc-windows-msvc -- -D warnings\` (plus the feature sets your spec names, e.g. --features write / fault-inject,test-support / rig-exec). vm/rigtool is a separate project and builds natively: \`cd vm/rigtool && CARGO_TARGET_DIR=${PT}/rigtool-linux cargo test\` (1 known Linux-only failure: baseline::tests::baseline_drops_rig_and_trims_fields). Full check: \`CI_TARGET_DIR=${tdir(id)} ${PT}/ci-linux.sh [--rigtool]\` (fmt, clippy, M2 feature clippies, tests under wine with the 10 known wine failures tolerated, check-deps, scanner-coverage). \`cargo xtask ci\` does NOT work on Linux; do not try it. PowerShell is \`~/.local/bin/pwsh\` (7.x on Linux): use it only for parse checks; install-selftest.ps1 and rig-selftest.ps1 need Windows and cannot pass here.\nWINE LIMITS: wine's registry, ACLs, reparse points, hard links, FileId, Restart Manager, AppX, srclient and FileRenameInfoEx are not Windows. Write every test the spec asks for exactly as if on Windows; never weaken, #[ignore] or cfg-out a test to make it pass under wine. If a test fails (or passes only trivially) under wine because of a wine limit, say so per test in 'needs_windows' with the reason; those are validated later on a Windows VM.`
const RULES = `Repository ${ROOT} (Rust workspace "Purge"; Windows x86_64 product, developed on a Linux checkout of the NTFS tree). Design of record: docs/ENGINE_PLAN.md; milestone M2 executor (§11.1, §7). Paths in the design file are Windows paths: ${WINROOT}\\a\\b means ${ROOT}/a/b. Work directly in this checkout (no worktree, no git commits, no branch changes, no git stash/checkout/reset). Other agents may be editing OTHER packages' files concurrently: touch ONLY the files your package owns (listed in crates_files). You may NOT edit any Cargo.toml, Cargo.lock or crate lib.rs unless your package owns it; if you need a dependency or module that is missing, stop and report it in 'blocked'. Never read or use anything from folders named draft_clone or "Uninstall Tool"; never copy strings from that commercial tool. BCU-derived code needs the per-file attribution header from ENGINE_PLAN §11.4. Write new files with LF line endings. Unit tests may be destructive only inside temp dirs and an HKU\\<SID>\\Software\\PurgeTest-<random> subtree the test itself creates and removes (M2 gate_procedure). Write unit tests as specified. Keep code idiomatic and documented at module level.`
const RES = { type: 'object', properties: {
  id: { type: 'string' }, done: { type: 'boolean' }, files_changed: { type: 'array', items: { type: 'string' } },
  tests: { type: 'string' }, needs_windows: { type: 'array', items: { type: 'string' } },
  blocked: { type: 'string' }, deviations: { type: 'string' }, followups: { type: 'array', items: { type: 'string' } },
}, required: ['id', 'done', 'files_changed', 'tests'] }
const REV = { type: 'object', properties: {
  id: { type: 'string' }, verdict: { type: 'string', enum: ['pass', 'fixed', 'fail'] },
  issues_found: { type: 'array', items: { type: 'string' } }, fixes_applied: { type: 'array', items: { type: 'string' } },
  needs_windows: { type: 'array', items: { type: 'string' } },
  remaining: { type: 'array', items: { type: 'string' } },
}, required: ['id', 'verdict', 'issues_found', 'remaining'] }

// Concurrency cap for package chains (impl + review): the workflow's own cap (min(16, CPUs-2) = 16 here) is too high for
// parallel Windows cross-builds on this host.
let slots = MAXPAR
const waiting = []
const acquire = () => slots > 0 ? (slots--, Promise.resolve()) : new Promise(r => waiting.push(r))
const release = () => { const n = waiting.shift(); if (n) n(); else slots++ }

const reviewed = p => REVIEW.includes(p.importance)
const cleanup = (p, who) => `When done, ${who === 'impl' && reviewed(p) ? `leave ${tdir(p.id)} in place (the reviewer reuses it)` : `delete ${tdir(p.id)} (rm -rf) to free disk`}.`
const impl = p => {
  const [model, effort] = p.model ? [p.model, p.effort] : (ROUTE[p.importance] || ROUTE.medium)
  const o = { label: `impl:${p.id}`, phase: 'Implement', schema: RES, model }
  if (effort) o.effort = effort
  return agent(`${RULES}\n\n${BUILD(p.id)}\n\n${args.context || ''}\n\nImplement package ${p.id}: ${p.title}\nRead your full spec first: the entry with id "${p.id}" in the "packages" array of ${DESIGN}. Follow it exactly. Run build, test and clippy for your crates as above. ${cleanup(p, 'impl')}`, o)
}
const review = (r, p) => {
  if (!r || !reviewed(p)) return { impl: r, review: null }
  return agent(`${RULES}\n\n${BUILD(p.id)}\n\nYou are an adversarial reviewer for package ${p.id} (${p.title}), which is safety-critical executor code in an uninstaller: wrong deletions, escapes outside the plan and unrecoverable undo are the worst outcomes. Spec: the entry with id "${p.id}" in the "packages" array of ${DESIGN}.\n\nImplementer report:\n${JSON.stringify(r, null, 1)}\n\nRead the code it wrote against the spec AND the cited ENGINE_PLAN sections (§7, §5.10). Hunt for: spec deviations, TOCTOU (acting on a path instead of the inspected handle), link/junction/REG_LINK following, path/prefix/case/canonicalisation bugs, deny-list self-exemption wider than the current session's op dir, backups not flushed/verified before the act, journal ordering, panics/unwraps on untrusted input, missing tests for edge cases, tests weakened or ignored to pass under wine, wire-format breaks (rigtool must still read plans/journals). Fix real issues directly in the package's own files and add regression tests; rerun build/test/clippy for the crate as above. ${cleanup(p, 'review')} Report verdict.`,
    { label: `review:${p.id}`, phase: 'Review', schema: REV, model: 'fable', effort: 'medium' }).then(v => ({ impl: r, review: v }))
}
const chain = async p => { await acquire(); try { const r = await impl(p); return await review(r, p) } finally { release() } }
let results
if (serial) {
  results = []
  for (const p of pkgs) results.push(await chain(p))
} else {
  // Dependency-aware: a package starts when the in-wave packages it lists in `after` have finished (impl + review).
  const started = {}
  const run = p => {
    if (!started[p.id]) {
      const deps = (p.after || []).map(id => pkgs.find(q => q.id === id)).filter(Boolean)
      started[p.id] = Promise.all(deps.map(run)).then(() => chain(p))
    }
    return started[p.id]
  }
  results = await Promise.all(pkgs.map(run))
}
phase('Check')
const check = await agent(`${RULES}\n\nAll packages of this wave are done. From ${ROOT} run: \`CI_TARGET_DIR=${PT}/ci-linux ${PT}/ci-linux.sh --rigtool\` (it runs fmt check, clippy -D warnings on msvc incl. purge-mcp alone and the M2 feature sets, the workspace tests under wine tolerating exactly the known wine failures, check-deps and scanner-coverage, and vm/rigtool tests natively; logs in ${PT}/ci-linux/ci-logs/). Do not fix anything except trivial rustfmt formatting (run cargo fmt --all if only formatting fails, then rerun). Report the summary table, each failing step's exact errors (file:line), and for the test step the full list of unexpected failing tests with their panic messages, saying for each whether it looks like a wine limit (registry/ACL/reparse/FileId/RM API behaviour) or a real bug. Do not add anything to the known-failure lists.`,
  { label: 'check:workspace', phase: 'Check', model: 'sonnet' })
return { results, check }
