# M1B-SPIKE: delete and re-create a service, a scheduled task and a firewall rule

Result: `RESULT.json` (schema `purge.m1b.spike/1`), Inbound-Win11-Test at m2-base (Windows 11 Enterprise LTSC
26100.1742), run twice from a fresh snapshot restore on 2026-11-16 (runs `m1b-spike-r1`, `m1b-spike-r2`): equal
apart from GUIDs and times. All three kinds re-create exactly. Raw captures: `E:\purge-build\gate-evidence\m1b-spike\`.

**Firewall: exact (method `cim_create`).**
- Delete: `IWbemServices::ExecQuery` of `MSFT_NetFirewallRule WHERE InstanceID='<id>'` plus `DeleteInstance`, with IWbemContext `PolicyStore=PersistentStore`.
- Re-create: `PutInstance(WBEM_FLAG_CREATE_ONLY)` of a spawned instance holding `InstanceID` and the rule properties (`ElementName`, `Description`, `RuleGroup`, `Enabled`, `Profiles`, `Direction`, `Action`, `EdgeTraversalPolicy`, ...). Filter fields (`Program`, `Service`, `Protocol`, `LocalPort`, `RemotePort`, `LocalAddress`, `RemoteAddress`, `InterfaceType`, `IcmpType`) go in as IWbemContext values next to `PolicyStore`.
- All 6 rules came back with the same value name and byte-equal strings, stable across a reboot. Nothing is normalised.
- The field map must fold `LPort2_10`/`RPort2_10` (port ranges) into `LocalPort`/`RemotePort`. A create over an existing id fails with `WBEM_E_ALREADY_EXISTS` and leaves the rule unchanged.
- Create-then-set-filters is not usable: a `Defer=User` rule is refused until its protocol is set.

**Task: exact.**
- Re-create with `RegisterTask(name, xml, TASK_CREATE, VT_EMPTY, VT_EMPTY, TASK_LOGON_NONE)` and **no sddl argument**. Passing the `GetSecurityDescriptor` SDDL is not exact: it adds `RegistrationInfo/SecurityDescriptor` to the XML and stores the SD with `AI`.
- XML and SDDL come back byte-equal for all 5 tasks, so `normalise` is empty. Outside XML+SDDL, Task Scheduler regenerates the TaskCache `Tree\Id` (new task GUID), `DynamicInfo`, `Hash` and `Triggers` values on every registration.
- `TASK_CREATE` over an existing task fails with `0x800700B7` and leaves the task unchanged.
- A stored-password task cannot be re-registered without its password (`0x8007052E` for XML-only and for user without password). With user and password the XML is equal.

**Service: exact with write-back. `scm_owned_values` is empty.**
- Re-create sequence: `CreateServiceW` with `lpBinaryPathName` = the raw `ImagePath` from the key backup (`QueryServiceConfigW` expands `%SystemRoot%`), then `ChangeServiceConfig2W` only for the items whose value the key backup holds.
- Then `SetServiceObjectSecurity(DACL_SECURITY_INFORMATION)` only when the backup has a `Security` subkey. OWNER|GROUP|DACL fails with 1307.
- Then write back every absent or different backed-up value or key (`write_back_needed`: vendor values and the `Parameters` subtree).
- Applying every non-null config2 item and the SD always (the design as written) leaves `DelayedAutostart`, `FailureActionsOnNonCrashFailures`, `PreshutdownTimeout`, `ServiceSidType` and a `Security` key behind. It also fails for empty triggers (87) and for `launch_protected` 0 (2).
- Marked for delete: the service is only marked while any handle is open, including the deleter's own handle. Then `DeleteFlag=1`, `OpenService` still succeeds, `DeleteService` and `CreateService` return 1072. After the last close the key is gone.

Run: `powershell -File vm\spikes\m1b\spike-objects.ps1 -Drive [-Runs 2]` with `$env:VMPWFILE` set. The script restores m2-base, runs itself in
the guest as an agent job (stage `main`, reboot, stage `reboot`), pulls `C:\cr\out\<run>\` to `vm\runs\<run>\`, then
powers the VM off and restores m2-base. Guest mode refuses to run outside the rig VM.
