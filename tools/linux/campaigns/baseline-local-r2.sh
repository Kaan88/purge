#!/usr/bin/env bash
# baseline-local-r2: gate M run R2 (docs/BASELINE_LOCAL_DESIGN.md 8.2, vm/RIG.md 8a) on Inbound-Win11-Test (Enterprise
# LTSC eval 26100.1742, rig-base, nothing installed, 3D off as for every Inbound campaign): local baseline build (cold,
# warm) and baseline-diff against the VM's own shipped baseline, local-only and merged with the neighbour
# Professional-26340.9882 (leave-one-out). Expected wall time about 10 min. Needs VMPWFILE; see baseline-local-vm.sh.
exec bash "$(dirname "$0")/baseline-local-vm.sh" Inbound-Win11-Test bl-r2-inbound EnterpriseSEval-26100.1742 Professional-26340.9882 -No3D
