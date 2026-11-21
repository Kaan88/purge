#!/usr/bin/env bash
# baseline-local-vm: gate M run R1 or R2 (docs/BASELINE_LOCAL_DESIGN.md 8.2, vm/RIG.md 8a) on one rig VM, from the Linux
# host. Called by baseline-local-r1.sh (Purge-CleanPro) and baseline-local-r2.sh (Inbound-Win11-Test); arguments:
#   <vm> <run> <truth baseline name> <neighbour baseline name> [-No3D]
# Restores rig-base (clean; nothing is installed), disconnects the VM's NAT cable (Set-BlNatLink of
# vm/rig-baseline-local.ps1) until the job is done, pushes rigtool.exe + purge-engine.exe + guest scripts and NO shipped
# baseline (the exact file stays hidden; the build reads only Windows' own sources), builds the local baseline three
# times (cold, warm, settled) with PURGE_TIMING=1, measures time, peak working set, file size and a load (baseline info), pulls
# C:\cr\out\<run>\ to vm/runs/<run>/, then on the host runs `rigtool baseline-diff` (truth = the VM's own shipped
# baseline, local = the cold build, neighbour = the other shipped baseline: leave-one-out) into
# vm/truth/baseline-local/<run>.json and copies build.json beside it as <run>-build.json.
# Console output: ~/purge-target/campaigns/<run>.out. Exit code: 0 ok, 1 the VM part failed, 2 refused to start,
# 3 the report shows a problem (seal failed, passes differ, wrong Windows, a build exit code), else pwsh's own code.
set -uo pipefail
VM=$1; NAME=$2; TRUTH=$3; NEIGHBOUR=$4; NO3D=${5:-}
export RIG_TMP=${RIG_TMP:-$HOME/.cache/purge-rig-tmp}
export POWERSHELL_TELEMETRY_OPTOUT=1
REPO=${PURGE_REPO:?set PURGE_REPO to the repo root}
DIR=$HOME/purge-target/campaigns
OUT=$DIR/$NAME.out
VBOX=/usr/lib/virtualbox/VBoxManage
PWSH=${PWSH:-$HOME/.local/bin/pwsh}
RIGTOOL=${RIGTOOL:-$HOME/.cache/purge-rigtool-target/release/rigtool}
ENGINE=target/release/purge-engine.exe
mkdir -p "$RIG_TMP" "$DIR"
chmod 700 "$RIG_TMP"
cd "$REPO" || { echo "$NAME: cannot cd to $REPO" >&2; exit 2; }
. tools/linux/campaigns/baseline-local-lib.sh

exec 9>"$DIR/.lock-$VM"
if ! flock -n 9; then echo "$NAME: REFUSED: another campaign script holds the lock for $VM" >&2; exit 2; fi
if [ -z "${VMPWFILE:-}" ] || [ ! -r "$VMPWFILE" ]; then echo "$NAME: REFUSED: VMPWFILE not set or not readable" >&2; exit 2; fi
state=$("$VBOX" showvminfo "$VM" --machinereadable 2>/dev/null 9>&- | sed -n 's/^VMState="\(.*\)"$/\1/p')
if [ -z "$state" ]; then echo "$NAME: REFUSED: VM $VM not found by VBoxManage" >&2; exit 2; fi
case "$state" in
  running|paused|starting|restoring|saving|stopping|stuck|livesnapshotting|onlinesnapshotting)
    echo "$NAME: REFUSED: VM $VM is $state" >&2; exit 2 ;;
esac
if pgrep -af 'rig\.ps1' | grep -F -- "$VM" >/dev/null; then echo "$NAME: REFUSED: a rig.ps1 process for $VM is alive" >&2; exit 2; fi
if [ ! -f "$ENGINE" ] || ! LC_ALL=C grep -a -q 'purge-baseline-local' "$ENGINE"; then
  echo "$NAME: REFUSED: $ENGINE missing or without the local baseline builder (BL-BUILD)" >&2; exit 2
fi
for b in "$TRUTH" "$NEIGHBOUR"; do
  [ -f "kb/baselines/$b.tsv.gz" ] || { echo "$NAME: REFUSED: no kb/baselines/$b.tsv.gz" >&2; exit 2; }
done
bl_check_rigtool "$RIGTOOL" || exit 2
avail=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
if [ "$avail" -lt 6144 ]; then echo "$NAME: REFUSED: only $avail MiB RAM available (need 6144 for a 4 GiB VM)" >&2; exit 2; fi

JOB=$RIG_TMP/$NAME-job.ps1
bl_build_job "C:\\cr\\out\\$NAME" 'C:\cr\bin\purge-engine.exe' 'C:\cr\guest\riglib.ps1' > "$JOB"
stamp=$(date +%s)
{
  echo "== $NAME start $(date -Is) on $VM; engine $(sha256sum "$ENGINE" | cut -c1-12); truth $TRUTH; neighbour $NEIGHBOUR"
} | tee "$OUT"
"$PWSH" -NoProfile -NonInteractive -Command "
. ./vm/rig.ps1 -VmName '$VM'
# Set-BlNatLink in a child scope: the -Library dot-source must not replace rig.ps1's own parameters.
function Set-Nat([string]\$State) { & { . ./vm/rig-baseline-local.ps1 -Library; Set-BlNatLink '$VM' \$State } }
\$nat = @()
try {
  \$null = Move-RunToOld -Run '$NAME'
  Restore-Base -Snapshot rig-base $( [ "$NO3D" = -No3D ] && echo '-No3D' )
  \$nat = @(Set-Nat 'off')
  Push-Tools -Engine '$ENGINE' -NoBaselines
  \$j = Invoke-GuestJob -Text ([IO.File]::ReadAllText('$JOB')) -Name '$NAME-build' -TimeoutSec 3600
  \$j.log
  if (-not \$j.done) { throw 'the build job did not finish' }
  \$got = @(Pull-Run -Run '$NAME')
  foreach (\$f in 'local-cold.tsv.gz', 'local-warm.tsv.gz', 'local-settled.tsv.gz', 'build.json', 'build-cold.log', 'info.txt') {
    if (\$got -notcontains \$f) { throw \"not pulled: \$f\" }
  }
  if (\$nat.Count) { \$null = Set-Nat 'on' }
  exit 0
} catch {
  Write-RigLog \"!! $NAME failed: \$(\$_.Exception.Message)\"
  if (\$nat.Count) { \$null = Set-Nat 'on' }
  exit 1
}
" 2>&1 9>&- | grep -v -E 'vboxdrv kernel module|available for the current kernel|failed to load\. Please|vboxconfig|You will not be able to start VMs' | tee -a "$OUT"
rc=${PIPESTATUS[0]}
if [ "$rc" -eq 0 ]; then
  R=vm/truth/baseline-local
  mkdir -p "$R"
  {
    echo "== baseline-diff (host): truth $TRUTH, local vm/runs/$NAME/local-cold.tsv.gz, neighbour $NEIGHBOUR"
    bl_diff "$RIGTOOL" "kb/baselines/$TRUTH.tsv.gz" "vm/runs/$NAME/local-cold.tsv.gz" "kb/baselines/$NEIGHBOUR.tsv.gz" "$R/$NAME.json" \
      || exit 1
    cp "vm/runs/$NAME/build.json" "$R/$NAME-build.json"
    bl_check "$R/$NAME.json" "vm/runs/$NAME/build.json" "$TRUTH" vm
  } 2>&1 | tee -a "$OUT"
  rc=${PIPESTATUS[0]}
fi
echo "== $NAME end $(date -Is), $(( ($(date +%s) - stamp) / 60 )) min, exit $rc" | tee -a "$OUT"
exit "$rc"
