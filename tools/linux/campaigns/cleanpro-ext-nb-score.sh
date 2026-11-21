#!/usr/bin/env bash
# cleanpro-ext-nb-score: host scoring of the cleanpro-ext-nb campaign with vm/truth/m1a.sh into vm/truth/x2-nb (generated 2026-11-14).
# One pass with M1A_SANITY=skip: the frozen M0 truth was recorded on a clean Inbound rig-base, which this campaign is
# not (dirty base, Clean-Pro or no baseline), so the sanity comparison and the frozen cross-check do not apply. Afterwards the
# label files vm/truth/labels/*.json are put back byte for byte (mk_labels.py rewrites them with LF line endings)
# and git must show the same status and diff for them as before. Log: ~/purge-target/campaigns/cleanpro-ext-nb-score.out.
# Exit code: m1a.sh's exit code (0 ok, 1 inventory check failed, 2 missing input),
# or 4 if the label files could not be restored to their previous state.
set -uo pipefail
NAME='cleanpro-ext-nb'
OUTDIR='truth/x2-nb'
FOOTPRINT=''
export M1A_PREFIX=x2-nb- M1A_APPS="firefox-tb vscode vscode-user git npp" M1A_AMBIENT=truth/f0/ambient-f0.json M1A_M0_RUNS=runs/_none M1A_BCU=0 M1A_OUT=truth/x2-nb
export M1A_SANITY=skip
export RIGTOOL=/home/kaan/.cache/purge-rigtool-target/release/rigtool
REPO=${PURGE_REPO:?set PURGE_REPO to the repo root}
DIR=$HOME/purge-target/campaigns
LOG=$DIR/$NAME-score.out
cd "$REPO/vm" || { echo "$NAME-score: cannot cd to $REPO/vm" >&2; exit 2; }
# one scorer at a time: m1a.sh regenerates the shared label files
exec 9>"$DIR/.lock-score"
if ! flock -w 3600 9; then echo "$NAME-score: another score script held the lock for an hour" >&2; exit 2; fi
if [ ! -x "$RIGTOOL" ]; then echo "$NAME-score: no Linux rigtool at $RIGTOOL" >&2; exit 2; fi
SAVE=$(mktemp -d "${TMPDIR:-/tmp}/purge-labels.XXXXXX")
cp -p truth/labels/*.json "$SAVE/"
git_before=$( { git status --porcelain -- truth/labels; git diff -- truth/labels; } 2>/dev/null | sha256sum)

restore_labels() { # put every label file back byte for byte when only its line endings changed
  python3 -I - truth/labels "$SAVE" <<'PY'
import os, sys
d, save = sys.argv[1:3]
norm = lambda b: b.replace(b'\r\n', b'\n').rstrip(b'\n')
bad = 0
for f in sorted(os.listdir(save)):
    old = open(os.path.join(save, f), 'rb').read()
    p = os.path.join(d, f)
    new = open(p, 'rb').read() if os.path.exists(p) else None
    if new == old:
        continue
    if new is not None and norm(new) == norm(old):
        open(p, 'wb').write(old)
        continue
    print(f'labels: {f}: CONTENT changed by mk_labels.py (left as written; review vm/truth/mk_labels.py)', file=sys.stderr)
    bad = 1
for f in sorted(os.listdir(d)):
    if f.endswith('.json') and not os.path.exists(os.path.join(save, f)):
        print(f'labels: {f}: new file written by mk_labels.py', file=sys.stderr)
        bad = 1
sys.exit(bad)
PY
}

residual() { python3 -I -c "import json,sys; print(json.load(open(sys.argv[1])).get('sanity_residual'))" "$OUTDIR/m1a-status.json" 2>/dev/null || echo '?'; }

{
  echo "== $NAME-score start $(date -Is): $(env | grep '^M1A_' | sort | tr '\n' ' ')"
  bash truth/m1a.sh
  rc=$?
  status="exit $rc, sanity skipped (not rig-base / frozen truth does not apply)"
  if [ -n "$FOOTPRINT" ] && [ "$rc" -ne 2 ] && [ "$rc" -ne 3 ]; then
    echo "== footprint: bash truth/footprint.sh $FOOTPRINT"
    M1A_RUNS=${M1A_RUNS:-runs} bash truth/footprint.sh $FOOTPRINT
    status="$status; footprint exit $?"
  fi
  if restore_labels; then lab=ok; else lab=FAILED; fi
  git_after=$( { git status --porcelain -- truth/labels; git diff -- truth/labels; } 2>/dev/null | sha256sum)
  if [ "$git_before" != "$git_after" ]; then lab="$lab, git status/diff of truth/labels CHANGED"; fi
  echo "== $NAME-score end $(date -Is)"
  echo "STATUS $NAME: $status; labels restored: $lab; reports in vm/$OUTDIR"
  case "$lab" in ok) exit "$rc" ;; *) exit 4 ;; esac
} > >(tee "$LOG") 2>&1
