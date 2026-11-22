#!/usr/bin/env bash
# BL-GATE scorer (docs/BASELINE_LOCAL_DESIGN.md 8.2 runs R3 and R4, 8.3 S1 and S4, 8.4 W2 and W3; package BL-GATE of
# docs/BASELINE_LOCAL_DESIGN.json). A SAFETY scorer: it fails closed. A missing, unparsable or empty input is FAIL,
# never PASS. Run from vm/ (it changes to vm/ itself; relative paths below are relative to vm/):
#
#   bash truth/bl.sh replay       R3: every corpus run replayed with the views exact, none, merged and local
#                                 (cargo xtask replay --baseline-view <v>, merged and local with --l5-against <none>)
#                                 -> $BL_OUT/r3/<run>/<view>.json (+ .scan.json, .log), <run>/bl-run.json, summary.json
#   bash truth/bl.sh evaluate     R4: truth/m1b.sh over the campaigns blm-/bll- (exit 3 "not a gate score" and exit 1
#                                 from rows outside S1 are expected); then S1, S4, W2, W3 -> verdict table and
#                                 $BL_OUT/bl-score.json
#   bash truth/bl.sh --self-test  evaluate against truth/fixtures/bl/ (a clean set passes; a flip, a missing plan, an
#                                 unparsable plan, zero runs, an L3 or L5 break and a failed trap row each fail)
#
# Exit codes: 0 every S row passes; 1 an S row fails or an input is missing; 2 usage error. W rows print their verdict
# and do not change the exit code (the feature ships presence-only, DECISIONS 2026-11-21; W2 decides the A side).
#
# Criteria as implemented (design quotes in quotation marks):
#   S1 R3  "A flip is a candidate offered with inferred absence whose key is in the truth baseline." Plans carry no
#          blockers, so every item of a merged or local plan that is more permissive than the exact plan of the same
#          run is a flip: a band above every exact item of that target, preselected where no exact item is, or a
#          target exact does not list and no exact key or directory covers at that band. Count 1 fails ("A flip ...
#          fails the gate at count 1"). A new item listed only as Blocked is reported, not a flip.
#   S1 R4  "danger_listed = 0 and every trap expectation met, in merged and in local mode, on both VMs": the m1b.sh rows
#          RUN, K1, K2, K3, K9 of each set must be present and pass, and per app danger_listed must not exceed the
#          exact M1b gate run's (m1b-evidence score-<set>.json; literal 0 would fail the exact runs, which list one
#          deny-listed item Blocked).
#          One exception (coordinator 2026-11-22, DECISIONS): a K1/K2/K3 row that m1b.sh fails only as an "empty plan"
#          is a W3-R4 report row (recall cost) when the app's RUN row passed, its plan offered 0 items with
#          danger_listed 0, the exact gate plan of that set and app offered items that are all UFH\SHC slot values
#          (Windows-owned below Exact, BL-FIX-UFH), and the R3 replay of that gate run with this view offers nothing.
#   S4     "exact plans byte-identical; every plan made with an injected view below Exact holds L5 ... against the
#          no-baseline plan of the same run (l5_violations is empty)": exact plans byte-equal to the M1b gate replay
#          plans in baseline-local/l3-ref (sha256 pinned in its manifest); xtask's --l5-against reports 0 violations
#          and a mirror of l5_violations here agrees.
#   W2     "of the key candidates that the exact view offers and the none view does not, the merged view offers at
#          least 80% (as Likely)": RegKey targets, offered = not Blocked, "as Likely" = band Likely or Safe.
#   W3     "items the exact view offers and the merged view blocks (extra presence) are at most 1% of the exact view's
#          offered items": targets exact and none both offer and merged does not offer (Blocked or not listed).
#
# Environment: PURGE_RUNS_DIR (runs, read only; default runs), BL_OUT (default truth/bl), BL_RUNS (the R3 corpus),
# BL_LOCAL_INBOUND / BL_LOCAL_CLEANPRO (the gate M local baselines), BL_KB (shipped baselines, default ../kb/baselines),
# BL_L3_REF (default truth/baseline-local/l3-ref), BL_EXACT_EVID (default truth/m1b-evidence), BL_R4_PREFIX_MERGED
# (blm), BL_R4_PREFIX_LOCAL (bll), BL_R4_SETS ("clean dirty cp"), BL_R4_COLLECT (1: run m1b.sh; 0: read
# $BL_OUT/r4-<mode>/m1b-score.json as it is), XTASK (default "cargo xtask"), PYTHON.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$HERE/.." || exit 2
PY=${PYTHON:-python}
export BL_SRC=${PURGE_RUNS_DIR:-runs} BL_OUT=${BL_OUT:-truth/bl} BL_KB=${BL_KB:-../kb/baselines}
export BL_L3_REF=${BL_L3_REF:-truth/baseline-local/l3-ref} BL_EXACT_EVID=${BL_EXACT_EVID:-truth/m1b-evidence}
export BL_R4_SETS=${BL_R4_SETS:-clean dirty cp} BL_R4_COLLECT=${BL_R4_COLLECT:-1}
export BL_R4_PREFIX_MERGED=${BL_R4_PREFIX_MERGED:-blm} BL_R4_PREFIX_LOCAL=${BL_R4_PREFIX_LOCAL:-bll}
# The corpus: the frozen runs (M0/M1a, G1 of M1b), the M1a gate campaign r2- and its Clean-Pro check r3-, and the M1b
# gate sets m1b- (Inbound rig-base), m1bd- (Inbound dirty-base), m1bcp- (Clean-Pro) with their trap runs.
M1B_APPS="7zip python python312-with-313 python313-with-312 node vcredist powershell temurin"
DEF_RUNS="vscode git firefox npp 7zip python node vcredist"
DEF_RUNS+=" r2-7zip r2-firefox r2-firefox-tb r2-git r2-npp r2-vscode r2-vscode-user r3-firefox r3-firefox-tb r3-ff-esr"
for a in $M1B_APPS; do DEF_RUNS+=" m1b-$a"; [ "$a" != node ] && DEF_RUNS+=" m1bd-$a"; done
DEF_RUNS+=" m1bcp-7zip m1bcp-python m1bcp-vcredist m1b-traps-7zip m1bd-traps-7zip m1bcp-traps-7zip"
export BL_RUNS=${BL_RUNS-$DEF_RUNS}
LOCAL_INBOUND=${BL_LOCAL_INBOUND:-$BL_SRC/bl-r2-inbound/local-cold.tsv.gz}
LOCAL_CLEANPRO=${BL_LOCAL_CLEANPRO:-$BL_SRC/bl-r1-cleanpro/local-cold.tsv.gz}
VIEWS="exact none merged local"   # none before merged and local: it is their L5 reference

py() { "$PY" -I "$HERE/bl_eval.py" "$@"; }

parts_of() { # parts_of <os of run.json> -> "local|neighbour", or nothing for a Windows without gate M parts
  case "$1" in
    "EnterpriseSEval 26100.1742") echo "$LOCAL_INBOUND|$BL_KB/Professional-26340.9882.tsv.gz" ;;
    "Professional 26340.9882") echo "$LOCAL_CLEANPRO|$BL_KB/EnterpriseSEval-26100.1742.tsv.gz" ;;
  esac
}

replay() {
  local xt r d o id os parts loc nb v rc t0 recs args
  read -r -a xt <<<"${XTASK:-cargo xtask}"
  [ -n "${BL_RUNS// }" ] || { echo "bl replay: BL_RUNS is empty" >&2; return 1; }
  mkdir -p "$BL_OUT/r3"; rm -f "$BL_OUT/r3/summary.json"
  local started; started=$(date -Iseconds)
  for r in $BL_RUNS; do
    d="$BL_SRC/$r"; o="$BL_OUT/r3/$r"; rm -rf "$o"; mkdir -p "$o"
    if ! IFS=$'\t' read -r id os < <(py runinfo "$d/run.json"); then
      echo "bl replay: $r: no readable $d/run.json" >&2; continue
    fi
    os=${os%$'\r'}   # a CR LF line end (python on Windows) is not part of the name
    parts=$(parts_of "$os"); loc=${parts%%|*}; nb=${parts#*|}
    recs=()
    for v in $VIEWS; do
      args=(--baseline-view "$v")
      case "$v" in
        merged) args+=(--local "$loc" --neighbour "$nb" --l5-against "$o/none.json") ;;
        local) args+=(--local "$loc" --l5-against "$o/none.json") ;;
      esac
      if [ -z "$parts" ] && { [ "$v" = merged ] || [ "$v" = local ]; }; then
        echo "no gate M local baseline for the Windows $os" >"$o/$v.log"; recs+=("$v:99:0"); continue
      fi
      t0=$(date +%s)
      "${xt[@]}" replay --run "$d" --app "$id" -o "$o/$v.json" "${args[@]}" >"$o/$v.log" 2>&1; rc=$?
      recs+=("$v:$rc:$(( $(date +%s) - t0 ))")
      echo "bl replay: $r $v exit $rc ($(( $(date +%s) - t0 )) s)" >&2
    done
    py runrec "$o/bl-run.json" "$r" "$id" "$os" "$loc" "$nb" "${recs[@]}" || return 1
  done
  py summary "$BL_OUT/r3/summary.json" "$started" "$(git -C "$HERE" rev-parse HEAD 2>/dev/null)" \
     "$(git -C "$HERE/../.." status --porcelain --untracked-files=no -- crates bins tools kb Cargo.toml Cargo.lock 2>/dev/null | head -c 1)" \
     "$LOCAL_INBOUND" "$LOCAL_CLEANPRO"
}

trap_runs_of() { # trap_runs_of <prefix>: the trap run of each R4 set
  local s out=""
  for s in $BL_R4_SETS; do
    case "$s" in clean) out+=" $1-m1b-traps-7zip" ;; dirty) out+=" $1-m1bd-traps-7zip" ;; cp) out+=" $1-m1bcp-traps-7zip" ;; esac
  done
  echo "${out# }"
}

evaluate() {
  local mode p dir rc
  for mode in merged local; do
    if [ "$mode" = merged ]; then p=$BL_R4_PREFIX_MERGED; else p=$BL_R4_PREFIX_LOCAL; fi
    dir="$BL_OUT/r4-$mode"; mkdir -p "$dir"
    if [ "$BL_R4_COLLECT" = 1 ]; then
      rm -f "$dir/m1b-score.json"
      M1B_CLEAN=$p-m1b M1B_DIRTY=$p-m1bd M1B_CP=$p-m1bcp M1B_SETS=$BL_R4_SETS M1B_TRAP_RUNS=$(trap_runs_of "$p") \
        M1B_OUT=$dir M1B_RUNS=$BL_SRC bash truth/m1b.sh >"$dir/m1b.log" 2>&1; rc=$?
    else
      rc=collect-skipped
    fi
    export "BL_R4_RC_${mode^^}=$rc" "BL_R4_TRAPS_${mode^^}=$(trap_runs_of "$p")"
  done
  py evaluate
}

selftest() {
  local fx="$HERE/fixtures/bl" tmp fails=0 name want got pat
  tmp=$(mktemp -d) || return 2
  run_case() { # run_case <name> <expected exit> <expected output line, a fixed string> [mutation...]
    name=$1; want=$2; pat=$3; shift 3
    rm -rf "${tmp:?}/$name"; cp -r "$fx/clean" "$tmp/$name"
    if [ $# -gt 0 ] && ! py mutate "$tmp/$name" "$@"; then echo "self-test: $name: mutation failed" >&2; fails=$((fails+1)); return; fi
    BL_OUT="$tmp/$name" BL_L3_REF="$tmp/$name/l3-ref" BL_EXACT_EVID="$tmp/$name/exact-evid" BL_KB="$tmp/$name/kb" \
      BL_RUNS="7zip m1bcp-7zip" BL_R4_SETS=clean BL_R4_COLLECT=0 evaluate >"$tmp/$name.out" 2>&1; got=$?
    if [ "$got" = "$want" ] && grep -qF -- "$pat" "$tmp/$name.out"; then echo "self-test: $name: exit $got, \"$pat\""
    else echo "self-test: $name: exit $got (expected $want) or no line \"$pat\"" >&2; sed 's/^/    /' "$tmp/$name.out" >&2
      fails=$((fails+1)); fi
  }
  run_case clean 0 "bl: S criteria PASS"
  run_case flip 1 "S1 flip merged m1bcp-7zip: new: REF-ANY Likely" flip
  run_case raised 1 "S1 flip local 7zip: raised" raise
  run_case missing-plan 1 "S1 7zip: missing or unreadable: " rm r3/7zip/local.json
  run_case unparsable-plan 1 "S4 m1bcp-7zip: missing or unreadable: " garble r3/m1bcp-7zip/merged.json
  run_case zero-runs 1 "S4 L5 over R3: 0 plan(s)" noruns
  run_case missing-summary 1 "S1 R3: missing: no runs" rm r3/summary.json
  run_case l3-break 1 "S4 L3 7zip: differs" l3
  run_case l5-break 1 "S4 L5 merged 7zip: exit 0" l5
  run_case trap-fail 1 "S1 R4 merged K9 blm-m1b-traps-7zip" trap
  run_case r4-missing 1 "S1 R4 local (bll-): m1b.sh exit collect-skipped; score unreadable" rm r4-local/m1b-score.json
  run_case danger-listed 1 "S1 R4 local clean/7zip danger_listed: 2 (exact gate 0)" danger
  run_case empty-plan-ufh 0 "W3-R4 R4 merged K1 clean/7zip: empty plan" emptyufh
  run_case empty-plan-other 1 "S1 R4 merged K1 clean/7zip: empty plan" emptyother
  run_case empty-plan-mixed 1 "S1 R4 merged K1 clean/7zip: empty plan" emptymixed
  run_case empty-plan-run-fail 1 "S1 R4 merged K1 clean/7zip: empty plan" emptyrunfail
  run_case empty-plan-danger 1 "S1 R4 merged K1 clean/7zip: empty plan" emptydanger
  run_case empty-plan-no-r3 1 "S1 R4 merged K1 clean/7zip: empty plan" emptynor3
  rm -rf "$tmp"
  [ "$fails" -eq 0 ] && { echo "self-test: PASS (18 cases)"; return 0; }
  echo "self-test: FAIL ($fails case(s))" >&2; return 1
}

case "${1:-}" in
  replay) [ $# -eq 1 ] || exit 2; replay ;;
  evaluate) [ $# -eq 1 ] || exit 2; evaluate ;;
  --self-test) [ $# -eq 1 ] || exit 2; selftest ;;
  *) echo "usage: bash truth/bl.sh replay | evaluate | --self-test" >&2; exit 2 ;;
esac
