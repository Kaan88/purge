# R6 review: 2454e63 (Defender fix), branch m1b

**Verdict: GO for the rerun. 0 blockers, 1 should-fix (small, optional before the campaign), 4 notes.**

Checked: the full diff, `bash vm/truth/m1b.sh --selftest` (0 failures), the gate4 archived truths against the new
rules, host run budgets, run.json depth, the version formats on a real Defender install (read-only, this host).
Not run: `guest/tests/rig-selftest.ps1` (PowerShell guest tests, outside the allowed scope), nothing in a VM.

## B (blockers)

None.

## S (should fix)

**S1. Platform version has two spellings, so a CIM failure at one end voids a good run.**
`vm/guest/riglib.ps1:841` (registry fallback) against `:826-827` (CIM), compared in `vm/truth/m1b.sh:241`.

- CIM `AMProductVersion` reads `4.18.26040.7`. The fallback takes the last folder of `InstallLocation`, which is
  `...\Platform\4.18.26040.7-0\`, and the regex `([0-9][0-9.\-]*)` keeps the `-0`. Confirmed on this host.
- Scenario: CIM answers at snap 0 and times out at snap 2 (or the reverse) on a guest whose platform lives under
  `ProgramData\...\Platform`. RUN reports `platform 4.18.x.y -> 4.18.x.y-0` and the run is INVALID although nothing
  updated.
- RIG.md 12.7 says a registry fallback at one end is not an update. The control `run_defender_registry_fallback`
  (`m1b-fixture.py:672`) models the fallback with `platform=None`, which is not what the guest produces, so it does not
  catch this.
- It is fail-closed and needs a CIM failure, so it costs at most a rerun of one run. Fix: strip `-\d+$` from the
  captured folder name (or compare platform only when both sources are equal), and give the control the real `-0` form.

## N (notes)

**N1. The rules do not swallow app leftovers.** All 7 are `ambient`, anchored with `^...$` under a Defender or AppX
root.
- I matched every Defender-looking leftover in the 18 gate4 truths: all fall under the 7 rules, none is left over,
  and there is no `MpCmdRun.log`, `Platform\` or Security Health item among them.
- RtSigs whole tree (`_m1b-noise.json:102`): Defender-only store. RtSigs items also appear in runs with no update
  (clean python313-with-312, vcredist, cp python), so the rule is needed even with the wait.
- `PackageVolumes\<n>\(User)MutablePackagesOnline` (`:122`): two volume flags only, not a package key. An MSIX app's
  own keys stay outside it.
- WINEVT (`:117`): the one GUID; the selftest checks PowerShell's publisher and channel stay unmatched.
- The hex classes are upper-case only (`mpcache-[0-9A-F]+`, `.NN`) and the GUID lower-case. They match the recorded
  spelling. A different spelling would fail towards leftover, never towards hiding.

**N2. The guest wait is bounded and safe without network.**
- Worst case about 300 s (MpCmdRun) + 300 s (stability) + CIM calls of 30 s each. gate4 runs took 125-360 s, the host
  budgets are 2400 s (null) and 5400 s (app), so no host timeout is at risk. Expect roughly 1.5-3 min more per run.
- On timeout only MpCmdRun is killed (`riglib.ps1:879`). An update the service finishes later is caught by the
  stability wait, or by RUN if it lands after snap 0.
- MpCmdRun's log and the update's own writes happen before snap 0, so they sit in snap 0. gate4 already shows the
  full trailing footprint of an update inside the window (including any scan after the update), and the rules cover it.
- `Write-JsonFile` depth is 10; `defender.idle.trigger.*` is depth 4. No StrictMode, so the final `Log` cannot throw
  on a null record.

**N3. RUN is fail-closed.** A missing record, a missing antivirus signature at either end, or any differing version
voids the run; app, trap and null runs alike. Clean-Pro and dirty-base have a live Defender (gate4 shows RtSigs and
updates there), so the normal CIM path applies. One gap in the fallback: if CIM answers but with an empty signature
version (as on a host where Defender is passive), the registry is not tried and the run is INVALID. That is the safe
direction and unlikely on the rig guests.

**N4. What can still cost a rerun, not a scripting fault.**
- Every run restores a snapshot with 1.463.242.0 and downloads the update again. On a slow link the 300 s bound can
  pass, the update then lands after snap 0 and the run is INVALID (visible in `defender.idle.trigger.timed_out`).
- Versions moved twice within gate4 (1.463.355.0, 1.463.357.0), so a second update inside one run is possible but
  rare; RUN voids it.
- snap 0 now sits 1.5-10 min later after boot, for null and app runs alike, with a variable offset. Windows tasks
  that fire in that later window were not seen in gate4; the null runs' ambient set is the only cover.
