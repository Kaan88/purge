#!/bin/bash
P=$HOME/purge-target/pass11; R=${PURGE_REPO:?set PURGE_REPO}
export CARGO_BUILD_JOBS=8 RUST_TEST_THREADS=8
H() { (cd $R; find crates bins -type f | sort | xargs -d "\n" sha256sum | sha256sum; find crates bins -type f | wc -l); }
echo "== tree hash at start"; H
echo "== ci-linux"; ~/purge-target/ci-linux.sh > $P/ci11.log 2>&1; echo "rc=$?"; tail -10 $P/ci11.log
echo "== ignored snapshot tests (msvc, wine)"
(cd $R; PATH=$HOME/.cargo/bin:$PATH XWIN_CACHE_DIR=$HOME/.cache/cargo-xwin XWIN_ARCH=x86_64 WINEDEBUG=-all WINEPREFIX=$HOME/purge-target/wineprefix CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER=wine CARGO_TARGET_DIR=$HOME/purge-target/ci-linux PURGE_RUNS_DIR=$HOME/purge-target/runs-m0 cargo xwin test --workspace --target x86_64-pc-windows-msvc --no-fail-fast -- --ignored > $P/ignored11.log 2>&1; echo "rc=$?"; grep "^test result" $P/ignored11.log | awk '{p+=$4;f+=$6} END{print "ignored tests passed",p,"failed",f}'; grep "FAILED$" $P/ignored11.log | head)
echo "== replay-all + score"
(source ~/purge-target/env-win.sh; cd $R; CARGO_TARGET_DIR=$HOME/purge-target/gnullvm cargo run --release -q --target x86_64-pc-windows-gnullvm -p xtask -- replay-all --runs ~/purge-target/runs-m0 --no-score > $P/replay-all11.log 2>&1; echo "rc=$?"; ~/purge-target/rigtool-linux/release/rigtool score --set ~/purge-target/runs-m0/{vscode,git,firefox,npp} > $P/score11.log 2>&1; echo "rc=$?"; grep "/ purge:\|^| purge " $P/score11.log | cut -c1-160)
echo "== re-plan binary from touched sources"
(source ~/purge-target/env-win.sh; cd $P; rsync -a --delete $R/crates/ ws/crates/ && rsync -a --delete $R/bins/ ws/bins/ && find ws/crates ws/bins ws/tools -name "*.rs" -exec touch {} + ; cd ws && CARGO_TARGET_DIR=$P/tgt-new cargo build --release -q --target x86_64-pc-windows-gnullvm -p xtask > ../build-new.log 2>&1; echo "rc=$?"; \cp -f $P/tgt-new/x86_64-pc-windows-gnullvm/release/xtask.exe ../xtask-new.exe; cd ..; echo "rule text in binary: $(grep -a -o 'too large to be read for text' xtask-new.exe | wc -l)"; diff -rq ws/crates $R/crates; diff -rq ws/bins $R/bins
 NEW=$(cat newruns.txt); ALL=$(cat allruns.txt); rm -rf b-new a-new; mkdir -p b-new a-new
 python3 replay6.py xtask-new.exe b-new $NEW > b-new.out 2>&1
 python3 replay6.py xtask-new.exe a-new/on $ALL > a-on.out 2>&1
 PURGE_REPLAY_CUTOFF=1 python3 replay6.py xtask-new.exe a-new/cut $ALL > a-cut.out 2>&1
 PURGE_REPLAY_LIVE=1 python3 replay6.py xtask-new.exe a-new/live $ALL > a-live.out 2>&1
 PURGE_REPLAY_LIVE=1 PURGE_REPLAY_CUTOFF=1 python3 replay6.py xtask-new.exe a-new/livecut $ALL > a-livecut.out 2>&1
 grep -c " 0 replay" b-gate.out b-new.out a-on.out a-cut.out a-live.out a-livecut.out
 for m in on cut live livecut; do python3 cmp4.py ~/purge-target/pass10/after9b/$m a-new/$m > diffa-gate-$m.txt; python3 cmp4.py ~/purge-target/pass10/trial/$m a-new/$m > diffa-p10-$m.txt; done
 python3 cmp4.py vmplans b-new > diffb-vm-new.txt; python3 cmp4.py vmplans b-gate > diffb-vm-gate.txt; python3 cmp4.py b-gate b-new > diffb-gate-new.txt)
echo "== mutations"
(source ~/purge-target/env-win.sh; cd $P; python3 mut11.py > mut11-run.log 2>&1; grep -v bashrc mut11-run.log | cut -c1-100)
echo "== tree hash at end"; H
echo ALLDONE
