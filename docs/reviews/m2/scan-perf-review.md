# Scan performance review

Reviewed `d1cfa25` ("Scan performance: one open per key, parallel reference
walk, timing counters") on local branch `m2`: the diff and what it calls.
Reviewer changed no source code and did not delegate.

## Verdict

**Merge after required fixes.** Required: S1 and S2. Both are small.

On an unchanging registry the claim holds on this host: the old path reads, the
new walker on one thread and the new walker on 8 threads gave equal hits and
statistics over a synthetic tree with denied keys, a link, a 300-level path,
odd names and mixed roots (experiment E1). Fingerprint, plan and sidecar of one
program were byte-identical with `PURGE_TIMING` off and on.

Under concurrent change the claim does not hold, and could not hold for any
non-atomic walk. Three differences from the old reads were reproduced (S1, S2,
M1). None of them makes today's reference scan offer a key it should not. S1 is
a hole in the "never read through a link" rule that today's only caller cannot
reach; S2 changes the `complete` flag of the harvest.

Evidence labels: **experiment** (a run against `d1cfa25`, Windows 11 build
26300, 28 logical processors, unelevated, registry under
`HKU\<SID>\Software\PurgeTest-*`, removed afterwards), **reading**.

Tests run: `cargo test -p purge-index --lib refscan`: 18 passed, 1 ignored.
`cargo test -p purge-source`: 64 passed, 1 ignored. `cargo test -p purge-win
--features read reg::`: the first run had 11 passed and 1 failed
(`reg::tests::nt_reads_equal_win32_reads_for_well_formed_data`); the test then
passed alone and in three further full runs (12 passed each). The commit does
not touch that test. It reads the subkeys of `HKCU\Software` twice and compares,
so a concurrent write there is the likely cause, but the failure message was
not captured and the cause is not established.

## Blocking

None.

## Serious

### S1. A link key entered before it has its target is remembered as "not a link"; later opens below it read the link's target

`crates/purge-source/src/live/registry.rs:236-241`,
`crates/purge-win/src/reg.rs:740-751` and `767-771`, used by
`reg.rs:374-390`.

Defect: `enter` records "not a link" on the handle when the key has no values
(`note_no_values`), and `link_target` records its answer on the handle. The
walker keeps that handle as an ancestor, and `open_component` then skips the
link check for as long as the handle is kept. A registry link is always made in
two steps (create the key with `REG_OPTION_CREATE_LINK`, then write
`SymbolicLinkValue`), so a link key with no values exists for a moment every
time a link is made. The old code asked again on every open, so its window was
one call wide. The new window lasts until the walker leaves the subtree.

Scenario (experiment E4b): a link key without target is entered by the walker:
`(values 0, subkeys 0, is_link false)`. The target is written. The same walker
enters `<link>\Sub`, a key that exists only in the target: it returns `Ok` and
the values of the target's `Sub`, under the link's path. `key_info` of the same
path returns `ReparsePoint`. A fresh walker reports the key as a link. So the
kernel does resolve an open below a link handle into the target, and the
remembered answer lets the walker follow it.

Reach today: none found. `refscan` enters a child only when the parent listed
it, a link key lists no subkeys (creating a subkey below a link key without
target failed with error 2), and `Scope::custom` drops a root that lies below
another root. The doc comments of `KeyWalker` and `LiveWalker` promise the link
checks of `Key::open` for any path, and that is false for the next caller that
enters a path below an entered key without listing it first.

Smallest fix: remember "not a link" only when the key has subkeys of its own
at `enter` (`info.n_subkeys > 0`), because a link key cannot hold any. Stop
`Key::link_target` from writing the remembered answer; let the walker record it
explicitly under the same condition. The walk never descends below a key with
no subkeys, so this costs no extra call. Add the E4b case as a test.

Confirmed by: experiment.

### S2. A key deleted between `enter` and the reads of its values or subkeys is now "unreadable" and makes the scan incomplete; before, it was skipped

`crates/purge-source/src/live/registry.rs:253-270`,
`crates/purge-source/src/live/errors.rs:35-43`,
`crates/purge-index/src/refscan.rs:792-794` and `812-813`.

Defect: the walker reads values and subkeys through the handle `enter` opened.
On a deleted key those reads fail with `ERROR_KEY_DELETED` (1018), which
`map_code` turns into `Other(1018)`, not `NotFound`. `Visit::read` treats only
`NotFound` as "the key went away". The old code opened the key again by path
for each read and got `NotFound`.

Scenario (experiment E2): one key deleted right after it was entered. Old
reads: `complete true`, no unreadable key. Walker: `complete false`,
`unreadable: L1: os error 1018`. With the key made again at once, the old reads
also report the new key's value (9 hits against 8). The harvest writes
`refsnap: the reference scan is incomplete` into the fingerprint warnings and
reports "incomplete"; `ref_any` ignores the statistics, so the plan is not
affected.

This is not a regression in how often it happens. With eight subtrees deleted
and re-made continuously (experiment E5, 150 scans each): old reads incomplete
in 143 scans (543 keys with 1018), walker on one thread in 20 (25), walker in
parallel in 38 (44). The old code had the same error from its own open-then-read
pairs. The error mapping is the defect; the commit moves where it shows.

Smallest fix: map `ERROR_KEY_DELETED` to `SourceError::NotFound` in `map_code`
(a deleted key is not found), and add 1018 to the code table test. That removes
the difference in E2 and most of the false "incomplete" results in both
versions.

Confirmed by: experiment.

## Minor

### M1. An ancestor renamed during the walk: hits are reported under a name that no longer exists

`crates/purge-source/src/live/registry.rs:150-163` (kept ancestors). The author
documents this in the `LiveWalker` comment.

Scenario (experiment E3): `V22` renamed while the walk is at `V22\P0`. Old
reads: 2 keys visited, 0 hits, `complete true` (the rest of the subtree
silently missed). Walker: 14 keys visited, 6 hits under `V22\...`, none of
which exists under that name any more, plus `P0: os error 1018`. `ref_any`
reads each hit's value again by path and drops it when it is gone. Whether
`refsnap` records such entries in the fingerprint was not checked.

Smallest fix: none needed for the scan. If the stale names matter for the
harvest, drop hits whose key no longer opens by path.

Confirmed by: experiment.

### M2. An ordinary key that gets a `REG_LINK` `SymbolicLinkValue` during the walk: old reads refuse its children, the walker reads them

`crates/purge-win/src/reg.rs:753-763` (the link test reads the value only).

The registry accepts a `REG_LINK` value named `SymbolicLinkValue` on an ordinary
key (rc 0). Purge then calls the key a link, the kernel does not. Experiment
E4b: written while a walker was below the key, the walker went on reading the
real children; `key_info` of the same children returned `ReparsePoint`. The
walker's answer is the correct one here. Written before the scan, both versions
skip the whole subtree as one link and report the scan complete: anything that
can write to a key can hide the subtree below it from the scan. That part is
older than this commit and errs towards offering less.

Smallest fix: none in this commit. Record the limit in `docs/DECISIONS.md`.

Confirmed by: experiment.

### M3. A thread that cannot be started panics the scan

`crates/purge-index/src/refscan.rs:945` (`s.spawn`). `Scope::spawn` panics when
the OS refuses the thread. The panic is not swallowed (the process ends, no
partial result is used), but the scan could have run on the calling thread.

Smallest fix: `std::thread::Builder::new().spawn_scoped(...)`; on error stop
spawning and let the threads that exist (or the caller) drain the queue.

Confirmed by: reading.

### M4. The tests do not run the combination that ships

`crates/purge-index/src/refscan.rs:2054-2200`. `parallel_scans_equal_the_
sequential_walk` and `parallel_scans_keep_root_order_and_root_facts` run over a
fixture through the default `PlainWalker`. They prove the split, the rejoin and
the replay of unreadable keys (including past the 1,024 cap). They do not run
`LiveWalker`, whose answers depend on what it entered before, on several
threads. The two live tests (`live/tests.rs:214-316`) run the walker on one
thread. Production always uses `LiveWalker` in parallel on a machine with two or
more processors. E1 covered it once on this host; no test does.

Also not covered: a key deleted between `enter` and `values` (S2), a link that
gets its target (S1), a rename (M1), a worker panic, a `values()` error other
than access denied, one or two processors.

Smallest fix: one live test over a scratch tree under
`HKU\<SID>\Software\PurgeTest-*` that compares `scan(.., None)`, `scan(..,
Some(progress))` and a source that forwards the six path calls without
`walker()`.

Confirmed by: reading.

### M5. `unreadable_total` counts a key twice once the listing is full

`crates/purge-index/src/refscan.rs:708-719`. The "once per key in a row" test
looks at the last listed entry. After 1,024 entries that entry never changes, so
a key whose values and subkeys both fail is counted twice. Older than this
commit, and the same on one thread and on many (the replay reproduces it), so
it does not break the equivalence. The parallel test passes because both sides
overcount.

Smallest fix: remember the last counted key in the tally instead of looking at
the list.

Confirmed by: reading.

### M6. A progress line on stderr changed with timing off

`bins/purge-engine/src/pipeline.rs:327-337`: "baseline X loaded" now carries
four counts. The commit message says output is unchanged; that is true for
stdout and the written files only. Nothing in the repository matches that line.

Confirmed by: reading and the runs below.

## Checked, no finding

- `Key::open_component` against `Key::open` (reading): the same call, flags and
  view per component. The only difference of a kept handle is its access
  (`KEY_READ` instead of `KEY_QUERY_VALUE` for a key that was entered) and its
  age. A key that refuses `KEY_READ` is never entered, so it is never kept.
- Denied keys (E1): deny all read, deny enumerate only, deny query only, deny
  notify only, each with a readable child that holds a hit; a scope root below
  each. Equal in all three modes. A key readable only for `KEY_QUERY_VALUE`
  passes as an ancestor in both versions.
- Deleted and re-made ancestor (reading, the author's test, E5): an open below
  a deleted key fails and is redone from the hive root.
- Links (E1): a link with target inside the tree, as a child and as a root, and
  a root below it. Equal. A link key reports one value, so "no values, no link"
  is sound for a finished link.
- Views (reading, the author's test): `WOW6432Node` paths change the view, the
  chain is not reused across views. `HKCR` and `HKCU` are refused before the
  walker.
- Names (E1): non-ASCII, trailing dot, leading space, `/`, 255 characters,
  `WOW6432Node` and `Classes` as ordinary names, a root spelled in upper case.
  Equal. A name with a NUL or other control character is refused by
  `translate_key` and listed as unreadable, in both versions.
- Depth and handles (E1): 300 levels. The walker holds one handle per level, per
  thread; at the registry's limit of 512 levels that is about 4,100 handles.
  Handles close on every error path (`Key` closes on drop; reading).
- Order and content of the parallel result (reading, E1 with 25 parallel runs
  per case): parts are in walk order, results are sorted by index, unreadable
  events are replayed in order through the same listing rule, there is no hit
  limit, `cancelled` and `truncated` cannot be set on this path. No shared
  mutable state besides the queue.
- Worker panic (reading): rethrown on the calling thread after the other
  workers finish; no result is returned.
- Thread count (reading): `available_parallelism` clamped to 1..8; one
  processor takes the sequential walk. Not run on 1, 2 or more than 64
  processors.
- Shortcut worker (reading): the apartment is entered and left on the worker
  thread only, on every path including a caught panic; when entering fails each
  read enters on its own as before. The thread now sits in a single-threaded
  apartment without pumping messages between reads; nothing is marshalled to
  it.
- `PURGE_TIMING` (experiment): harvest and forced scan of 7-Zip ZS, twice off
  and once on: `fp.json`, `plan.json` and `plan.scan.json` have the same SHA-256
  in all three. The timing lines hold call names, counts and seconds only. Every
  trait method is forwarded, including `key_exists` and `walker`. Off, the cost
  is one `OnceLock` read per progress line.

## Not checked

- The author's four-program comparison against the old binary. The old binary
  was not built; the old reads were emulated by a source without `walker()`.
- Elevated runs, other users' hives, a hive unloaded during the walk.
- 32-bit view equivalence beyond the author's test (no writes under `HKLM`).
- Machines with 1, 2 or more than 64 processors; a 32-bit build.
- Whether `refsnap` writes entries for hits whose key was renamed (M1).
- Whether the non-pumping apartment of the shortcut worker can stall anything
  on a machine with shell extensions that this host does not have.
- Overhead of the meter when on, beyond the three wall times (20 s, 24 s off;
  22 s on, harvest plus scan).
- `xtask ci` and `check-deps`.
