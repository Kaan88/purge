#!/usr/bin/env bash
# inbound-gate: Purge rig campaign on Inbound-Win11-Test (generated 2026-11-14). Expected wall time about 55 min.
# Console output: ~/purge-target/campaigns/inbound-gate.out. Exit code: 0 all runs ok, 1 some run failed,
# 2 refused to start (VM running, another rig.ps1 for the VM, wrong engine, low memory), else pwsh's own code.
set -uo pipefail
VM='Inbound-Win11-Test'
NAME='inbound-gate'
ARGS='-Snapshot rig-base -Ids vscode,vscode-user,git,firefox,firefox-tb,npp,7zip -Nulls 3 -NullOrder spread -NullWaitSec 120 -RunPrefix r2- -Engine ./target/release/purge-engine.exe -ExecutionEngine default -No3D'
export VMPWFILE=/mnt/C/Users/kaank/AppData/Local/Temp/claude/00f7b7199d1b697b/907a18b5-8b7a-4e9b-ba62-ed4a6d257fd6/scratchpad/vmpw.txt
export RIG_TMP=$HOME/.cache/purge-rig-tmp
export POWERSHELL_TELEMETRY_OPTOUT=1
REPO=/mnt/C/Users/kaank/Desktop/uninstall/purge
DIR=$HOME/purge-target/campaigns
OUT=$DIR/$NAME.out
VBOX=/usr/lib/virtualbox/VBoxManage
PWSH=$HOME/.local/bin/pwsh
mkdir -p "$RIG_TMP" "$DIR"
chmod 700 "$RIG_TMP"
cd "$REPO" || { echo "$NAME: cannot cd to $REPO" >&2; exit 2; }

# one campaign per VM at a time (lock held by this shell until it exits; fd 9 is closed for VBoxManage and pwsh so
# a lingering VBoxSVC never inherits it)
exec 9>"$DIR/.lock-$VM"
if ! flock -n 9; then echo "$NAME: REFUSED: another campaign script holds the lock for $VM" >&2; exit 2; fi
if [ ! -r "$VMPWFILE" ]; then echo "$NAME: REFUSED: password file not readable" >&2; exit 2; fi
state=$("$VBOX" showvminfo "$VM" --machinereadable 2>/dev/null 9>&- | sed -n 's/^VMState="\(.*\)"$/\1/p')
if [ -z "$state" ]; then echo "$NAME: REFUSED: VM $VM not found by VBoxManage" >&2; exit 2; fi
case "$state" in
  running|paused|starting|restoring|saving|stopping|stuck|livesnapshotting|onlinesnapshotting)
    echo "$NAME: REFUSED: VM $VM is $state" >&2; exit 2 ;;
esac
if pgrep -af 'rig\.ps1' | grep -F -- "$VM" >/dev/null; then
  echo "$NAME: REFUSED: a rig.ps1 process for $VM is alive:" >&2; pgrep -af 'rig\.ps1' | grep -F -- "$VM" >&2; exit 2
fi
if [ "$VM" = Inbound-Win11-Test ] && pgrep -af 'rig\.ps1' | grep -v -F -- '-VmName' >/dev/null; then
  echo "$NAME: REFUSED: a rig.ps1 process without -VmName (defaults to Inbound-Win11-Test) is alive" >&2; exit 2
fi
ENGINE=target/release/purge-engine.exe
if [ ! -f "$ENGINE" ] || ! LC_ALL=C grep -a -q 'm1a\.5' "$ENGINE"; then
  echo "$NAME: REFUSED: $ENGINE missing or does not contain policy m1a.5" >&2; exit 2
fi
avail=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
if [ "$avail" -lt 6144 ]; then echo "$NAME: REFUSED: only $avail MiB RAM available (need 6144 for a 4 GiB VM)" >&2; exit 2; fi

stamp=$(date +%s)
{
  echo "== $NAME start $(date -Is) on $VM; engine $(sha256sum "$ENGINE" | cut -c1-12); RAM available $avail MiB"
  echo "== pwsh: . ./vm/rig.ps1 -VmName $VM; Invoke-Campaign $ARGS"
} | tee "$OUT"
"$PWSH" -NoProfile -NonInteractive -Command "
. ./vm/rig.ps1 -VmName '$VM'
\$r = Invoke-Campaign $ARGS
'== results'
foreach (\$x in \$r) { 'RESULT {0} {1} {2}s{3}' -f \$x.run, \$(if (\$x.ok) { 'ok' } else { 'failed' }), \$x.seconds, \$(if (\$x.error) { ' (' + \$x.error + ')' } else { '' }) }
if (@(\$r).Count -eq 0 -or @(\$r | Where-Object { -not \$_.ok }).Count -gt 0) { exit 1 } else { exit 0 }
" 2>&1 9>&- | grep -v -E 'vboxdrv kernel module|available for the current kernel|failed to load\. Please|vboxconfig|You will not be able to start VMs' | tee -a "$OUT"
rc=${PIPESTATUS[0]}
echo "== $NAME end $(date -Is), $(( ($(date +%s) - stamp) / 60 )) min, exit $rc" | tee -a "$OUT"
echo "== per run (id, result, duration):"
grep '^RESULT ' "$OUT" | sed 's/^RESULT //' || echo "(no per-run results: see $OUT)"
exit "$rc"
