# M1b VM objects run: R1 S2, S4 (and S3), R2b live backends

Date 2026-11-17. VM `Inbound-Win11-Test` only (Windows 11 Enterprise LTSC Evaluation 10.0.26100). Tree: `m1b` at
`b091781`, plus the test-only and rig commit `M1b rig: ...` (extra firewall cases, the native-rule test
`rig::native_rules_recreate_byte_equal`, `win-unit.ps1 -ElevatedEnv`, and the `-Snapshot` fix). No product code was
changed. The binaries were built at 09:10-09:20 from `b091781`; `9ba0ab5` (R3a) and `f5230c7` (X-INTEG) landed on
`m1b` during the run and were not tested here. Raw outputs: `E:\purge-build\gate-evidence\m1b-vm-objects\` (libtest output per binary and pass, S2 log
and `result.json`).

## How it ran

- **Session 1 (win-unit).** Test binaries built on the Windows host (`cargo test --no-run`,
  `CARGO_TARGET_DIR=E:\purge-build\vm-unit`, `CARGO_BUILD_JOBS=4`): purge-win `scm`, `firewall`, `taskschd` with
  `--features write,com`; purge-exec `act_service`, `act_task`, `act_firewall` with
  `--features fault-inject,test-support` (xtask `EXEC_TEST_FEATURES`). `vm/win-unit.sh` is Linux-only (cargo-xwin,
  flock, `/proc/meminfo`), so the bundle (bin.tgz, fixtures.tgz with both crates' `src/` and `tests/`,
  manifest.json) was made by a scratch script with the same layout and `vm/win-unit.ps1` was called directly:
  pass `p1-user` (Medium integrity) and pass `p2-elevated` (rig agent, High) with
  `--include-ignored --nocapture --test-threads=1` and `PURGE_TEST_TASK_RIG=1`. Snapshot: `rig-base` (see the
  rig fix below: `-Snapshot m2-base` was silently replaced by rig-base). 154 s VM part.
- **Session 2 (agent jobs, `m2-base`).** (a) the new firewall test binary again, elevated, filtered to the two
  shape tests (LSM retried outbound); (b) the S2 PowerShell job (30 min). Then power off and restore `m2-base`.
- Both sessions ended powered off at a restored snapshot; the VM was left at `m2-base` (its state before).
  No `scm.rs` elevated test printed `SKIPPED` (the agent token is elevated).

## 1. Test results

### purge-win `tests/scm.rs`, module `elevated` (6), elevated pass

| test | result |
|---|---|
| `elevated::create_then_query_equals_definition` | pass |
| `elevated::create_exists_is_distinct_error` | **FAIL** |
| `elevated::delete_marked_for_delete_reported` | pass |
| `elevated::query_own_test_service_round_trips_all_fields` | pass |
| `elevated::set_config2_each_item_round_trips` | pass |
| `elevated::set_security_round_trips_sddl` | pass |

The 6 non-ignored scm tests pass in both passes.

`create_exists_is_distinct_error` (scm.rs:319): the second `create` of the same service name gives `Exists` as
expected, but a service with a **different name and the same display name** is created (`Ok(())`), not refused
with `DuplicateName`:

```
assertion `left == right` failed
  left: Ok(())
 right: Err(DuplicateName)
```

So on 26100 `CreateServiceW` does not return `ERROR_DUPLICATE_SERVICE_NAME` for a duplicate display name (the
test deleted the `_2` service it made). The test's expectation is wrong for this build; whether any executor
path relies on `DuplicateName` should be checked.

### purge-win `tests/firewall.rs`, module `rig` (9 + 1 added), elevated pass

| test | result |
|---|---|
| `rig::delete_unknown_id_is_zero` | pass |
| `rig::delete_exactly_one_of_two_rules_with_same_display_name` | pass |
| `rig::id_with_quote_escaped_or_rejected` | pass |
| `rig::id_with_control_char_or_too_long_rejected` | pass |
| `rig::create_with_instance_id_round_trips_registry_string` (the 6 spike shapes) | pass, all 6 `raw_equal=true` |
| `rig::create_with_instance_id_round_trips_unproven_fields` | **FAIL** (ICMP, LSM inbound; see section 3) |
| `rig::create_over_existing_id_is_object_exists_and_changes_nothing` | pass |
| `rig::delete_by_case_variant_of_id_deletes_nothing` | pass |
| `rig::delete_id_with_backslash_and_quote_matches_exactly` | pass |
| `rig::native_rules_recreate_byte_equal` (added) | **FAIL** (ICMP only; see section 3) |

The two non-ignored tests (`no_remove_by_name_symbols`, `host_rule_strings_parse_round_trip`) pass in both passes.
`tests/taskschd.rs` (11 tests, none ignored) passes in both passes. No other `#[ignore]`d M1b test exists in
purge-win (the other ignored tests there are M2: fs_write, reg_write, rm, sr, appx_write).

### purge-exec live tests

| test | p1-user (Medium) | p2-elevated |
|---|---|---|
| `act_service::rig_live_delete_and_recreate_round_trip` (ignored) | ignored | pass |
| `act_task::rig_live_delete_and_undo` (ignored, `PURGE_TEST_TASK_RIG=1`) | ignored | pass |
| `act_firewall::rig_live_delete_and_recreate_round_trip` (ignored) | ignored | pass |
| all other tests of the three targets | pass, except one (below) | all pass (50 / 25 / 43) |

**Unelevated failure, not ignored:** `act_service::live_read_of_a_builtin_service_is_consistent` fails at Medium
integrity (act_service.rs:1537):

```
called `Result::unwrap()` on an `Err` value: Os(KeyOpError { at: "Security", op: "open subkey", error: Win32Error(5) })
```

`LiveServices::capture_key("EventLog", ...)` cannot open `EventLog\Security` unelevated. On the host it passes
only because the host shell is elevated. Either the test needs elevation (ignore or skip like `scm.rs`), or
`capture_key` must not be used unelevated; the executor runs elevated, so this is a test issue unless a scanner
path calls it at Medium.

## 2. R1 S2: does registering a task start it?

Job: every task registered with `ITaskFolder::RegisterTask(name, xml, TASK_CREATE, VT_EMPTY, VT_EMPTY,
TASK_LOGON_NONE)`, the call `taskschd::register_xml` makes. Action `cmd.exe /c echo ran ... >> marker` (observable),
`ExecutionTimeLimit` PT5M, battery conditions off. Polled every 10 s: marker file, `LastRunTime`, `LastTaskResult`,
`NumberOfMissedRuns`; TaskScheduler/Operational log on.

| task | trigger | StartWhenAvailable | principal | phase 1: first registration, 15 min | phase 2: delete + re-register stored XML, 15 min |
|---|---|---|---|---|---|
| A | TimeTrigger, StartBoundary now - 1 day | true | SYSTEM | did not run | did not run |
| B | daily, StartBoundary 2026-01-01T03:00 | true | SYSTEM | did not run | did not run |
| C (control) | TimeTrigger, now - 1 day | false | SYSTEM | did not run | did not run |
| D | daily, 2026-01-01T03:00 | true | tester, InteractiveToken | did not run | did not run |
| `\PurgeSpikeT1` (the spike's task 1, registered the spike's way, `t1.exe` missing) | daily, 2026-01-01T03:00 | false | tester (logon 3) | did not run | did not run |
| E (spike T1 shape, marker action) | daily, 2026-01-01T03:00 | false | tester (logon 3) | did not run | did not run |

Every task ended with `LastRunTime` 1999-11-30 (never), `LastTaskResult` 0x00041303 (`SCHED_S_TASK_HAS_NOT_RUN`),
`NumberOfMissedRuns` 0, no marker file. The Operational log shows only events 106 (registered) and 141 (deleted),
no 100/110/200 (start, launch). NextRunTime: A and C none (one-shot in the past), the daily ones the next 03:00.

**Answer:** on 26100, neither a first registration nor a delete-and-re-register through the create-only path
started a task whose trigger lies in the past, with or without `StartWhenAvailable`, within 15 minutes; Task
Scheduler does not count a start boundary before the registration as a missed run. Re-registering the spike's test
task did not start it either. Not measured: a reboot or service restart after the re-registration (a daily
trigger runs at its next 03:00 as designed, which is the restored task doing its normal job), and other Windows
builds.

## 3. Firewall shapes refused as unproven (`purge_model::FIREWALL_UNPROVEN_SHAPES`)

Two round trips per shape, both elevated on Inbound:

- **own**: `create_with_instance_id` from a written rule string, read the stored string, delete by id,
  re-create from the stored fields, compare (`rig::create_with_instance_id_round_trips_unproven_fields`; prints
  `raw_equal`).
- **native**: the rule made by `New-NetFirewallRule` (as an installer would), stored string read, deleted by
  `delete_by_instance_id`, re-created by `create_with_instance_id` from its parsed fields, compared byte for byte
  (`rig::native_rules_recreate_byte_equal`). `map_rule` reported the expected shape for every native rule.

| shape (`FirewallShape`) | own round trip | native round trip | proven? |
|---|---|---|---|
| `EdgeTraversal` (`Edge=TRUE`) | pass, byte-equal | pass, byte-equal | **yes** |
| `DeferApp` (`Edge=TRUE\|Defer=App`) | pass, byte-equal | pass, byte-equal | **yes** |
| `LooseSourceMapping` (`LSM=TRUE`) | outbound UDP: pass, byte-equal. Inbound (with Profile=Domain): create fails 0x80041001 | outbound UDP: pass, byte-equal. Inbound: `New-NetFirewallRule` itself refuses ("Invalid flags", 0x80070057) | **yes for Dir=Out**; an inbound LSM rule cannot be made by the provider at all |
| `LocalOnlyMapping` (`LOM=TRUE`) | pass, byte-equal | pass, byte-equal | **yes** |
| `IcmpTypes` (`ICMP4` / `ICMP6`) | **fail**: create `PutInstance` 0x80041001 (WBEM_E_FAILED) for `ICMP4=8:*\|ICMP4=3:4` and `ICMP6=128:*` | **fail**: same error on re-create; the native rule had been deleted, so the rule was lost | **no** (keep refusing) |
| `LocalAddresses` (`LA4` / `LA6`) | pass, byte-equal | pass, byte-equal | **yes** |
| `DomainProfile` (`Profile=Domain`) | pass, byte-equal | pass, byte-equal | **yes** |
| `RemotePortRange` (`RPort2_10`) | pass, byte-equal | pass, byte-equal | **yes** |
| `LanInterface` (`IFType=Lan`) | pass, byte-equal | pass, byte-equal | **yes** |
| `OtherProtocol` (Protocol 47) | pass, byte-equal | pass, byte-equal | **yes** (protocol 47; the ICMP protocols 1 and 58 fail only through their ICMP fields, not tested without them) |

Native strings as stored (all re-created identically except ICMP):

```
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=C:\Program Files\PurgeTest\native.exe|Name=PurgeTest native edge|Edge=TRUE|
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=...|Name=PurgeTest native defer-app|Edge=TRUE|Defer=App|
v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=17|App=...|Name=PurgeTest native lsm-out|LSM=TRUE|
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App=...|Name=PurgeTest native lom|LOM=TRUE|
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=1|ICMP4=8:*|ICMP4=3:4|Name=PurgeTest native icmp4|      (re-create: 0x80041001)
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=58|ICMP6=128:*|Name=PurgeTest native icmp6|            (re-create: 0x80041001)
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=7000|LA4=10.0.0.5|LA6=fe80::/64|Name=PurgeTest native local-address|
v2.33|Action=Allow|Active=FALSE|Dir=In|Profile=Domain|App=...|Name=PurgeTest native domain|
v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|RPort2_10=8554-8558|Name=PurgeTest native remote-range|
v2.33|Action=Allow|Active=FALSE|Dir=In|IFType=Lan|App=...|Name=PurgeTest native iftype-lan|
v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=47|Name=PurgeTest native proto-47|
```

Both sessions gave the same per-shape result (the own and native tests ran once in each session).

**Decision input:** 8 of 10 shapes can be lifted (Edge, Defer=App, LOM, local addresses, Profile=Domain,
RPort2_10, IFType=Lan, other protocol), and LSM too if the lift is limited to what the provider can make (it
refuses inbound LSM on create, so an inbound `LSM=TRUE` string is either not produced by Windows or cannot be
restored: keep refusing `LSM` with `Dir=In`). **ICMP must stay refused**: the ICMP context mapping fails on
`PutInstance`, and the native test shows the R1 S3 failure scenario for real (delete succeeded, re-create failed,
rule gone). The ICMP mapping in `map_rule` (value form of `IcmpType`) needs a fix before it can be retried.

## 4. Rig changes made for this run (commit `M1b rig: ...`)

- `vm/win-unit.ps1`: new `-ElevatedEnv NAME=value` for the elevated pass (needed for `PURGE_TEST_TASK_RIG=1`).
- `vm/win-unit.ps1`: **bug fix**: dot-sourcing `rig.ps1` reset `$Snapshot` to rig.ps1's default `rig-base`, so
  `-Snapshot` / `--snapshot` was ignored (restore and final restore both used rig-base). It now passes
  `-Snapshot $Snapshot` through.
- `crates/purge-win/tests/firewall.rs`: cases `lsm-out`, `lom`, `domain`, `iftype-lan`, `proto-47` in
  `create_with_instance_id_round_trips_unproven_fields`, and the new ignored test
  `rig::native_rules_recreate_byte_equal`.
- `vm/win-unit.sh` still runs only on a Linux host; on Windows the bundle was made by a scratch script (not
  committed).
