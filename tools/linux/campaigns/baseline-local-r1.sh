#!/usr/bin/env bash
# baseline-local-r1: gate M run R1 (docs/BASELINE_LOCAL_DESIGN.md 8.2, vm/RIG.md 8a) on Purge-CleanPro (Professional
# 26340.9882, rig-base, nothing installed): local baseline build (cold, warm) and baseline-diff against the VM's own
# shipped baseline, local-only and merged with the neighbour EnterpriseSEval-26100.1742 (leave-one-out). Expected wall
# time about 10 min. Needs VMPWFILE; see baseline-local-vm.sh for everything else.
exec bash "$(dirname "$0")/baseline-local-vm.sh" Purge-CleanPro bl-r1-cleanpro Professional-26340.9882 EnterpriseSEval-26100.1742
