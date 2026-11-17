# M1b review R1: wave 1

Scope: `git diff 3265797..f209730` without `docs/` and `vm/` (M1B-MODEL, M1B-SOURCE, M1B-WIN-MSIDB,
M1B-WIN-SCM, M1B-WIN-TASK, M1B-WIN-FW, M1B-KB). Read at `m1b` head `82bc1a0`; the wave-1 files of
`purge-model` and `purge-win` are unchanged since `f209730`. Later waves were read only where a wave-1
finding reaches them. Reviewer changed no source code.

## Verdict

**Accept with required changes.**

No blocking finding. No purge-win write function takes a selector other than the exact service name, task
path or rule id; `register_xml` and `create_with_instance_id` cannot overwrite; `delete` does not call
`DeleteService` on a service that is not stopped; the MSI reader has no path to an install, a repair or a UI;
the object digest has no collision I could construct; no M1a or M2 golden file was edited.

Four serious findings (S1 to S4). S1 is a hole in the journal model that three executor modules already
work around with a caller-supplied parameter. S2 and S3 are places where the wrappers promise more than was
measured. S4 is that two of the three write wrappers have never run. S1 must be fixed before M1B-X-INTEG is
closed; S2 to S4 need one VM session and must be settled before review R3 signs off the executor.

Evidence labels:

- **experiment**: confirmed by a read-only script run by the reviewer (only the KB check, see "Checked").
- **reading**: confirmed by reading the code; nothing was built or run (builds were off limits for this review).
- **suspected**: not confirmed.

## Reviewed

- `crates/purge-model/src/object.rs`, `fingerprint_m1b.rs`, `fingerprint.rs`, `scope.rs`, `evidence.rs`,
  `blocker.rs`, `candidate.rs`, `exec/op.rs`, `exec/journal.rs` (diff), and the `// M1b: wired by` arms in
  purge-exec, purge-policy, purge-plan, purge-scan.
- `crates/purge-win/src/scm.rs`, `taskschd.rs`, `firewall.rs`, `msi_db.rs` in full (non-test part), the test
  lists of `tests/scm.rs`, `tests/taskschd.rs`, `tests/firewall.rs`, `tests/msi_db.rs`, and the three grep tests.
- `crates/purge-source/src/sysobj.rs`, the diffs of `fixture.rs`, `metered.rs`, `system.rs`, `live/system.rs`.
- `kb/shared-iids.json`, `kb/shared-components.json`, `kb/hosts.json`, `kb/README.md`,
  `crates/purge-guard/tests/kb_data.rs` (structure).
- `vm/spikes/m1b/README.md`, `RESULT.json`, the firewall part of `spike-objects.ps1`.

## Blocking

None.

## Serious

### S1. `ProgramOutsideRoot` is defined against roots "recorded in the journal header", and the header records none

Files: `crates/purge-model/src/exec/journal.rs:173-198` (`Header`: no roots field), `:496-510`
(`UndoConflict::ProgramOutsideRoot`), contract C-EXECOP. Reached: `crates/purge-exec/src/act_task.rs:753`
and `:1392` (`roots: &[String]` parameter), the same parameter in `act_service.rs` and `act_firewall.rs`,
and M1B-X-INTEG. Evidence: reading.

C-EXECOP says the undo refuses a service or task whose backed-up program "is not under a root recorded in
the journal header", and in the same contract says the journal gains only enum variants. M1B-MODEL
implemented the second sentence. The three executor modules therefore take the roots from their caller, and
the coordinator notes say "X-INTEG must wire".

Failure scenario: whatever X-INTEG passes is not covered by the journal's hash chain. If it takes the roots
from the scan document or a fingerprint read at undo time, a file a user can replace decides which program a
re-created SYSTEM service or task may point at, which is the check's whole purpose. If it passes nothing,
every service and task undo ends in `ProgramOutsideRoot` (the X-TASK note says so).

Fix: add the field to `Header` in purge-model now: `#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub program_roots: Vec<String>`, written by the run that journals the first object intent. An M2 journal
still reads and writes byte-equal (extend `journal_m2_document_still_parses` to assert it). The undo modules
then read the roots from the verified journal and lose the parameter. The same applies to the exemption
("gone") lists the GUARD and PLAN notes report as not journalled; that part is R2's.

### S2. Re-registering a task can start it; only `RegistrationTrigger` is refused

Files: `crates/purge-win/src/taskschd.rs:382-395` (`check_register_xml`), `:338-378` (`register_xml`), module
doc line 28 ("never starts ... a task"). Reached: M1B-X-TASK undo. Evidence: suspected (handoff point 3; the
spike's tasks had no `StartWhenAvailable`, `spike-objects.ps1:924-926`).

A task with a time, daily or weekly trigger whose `StartBoundary` is in the past and
`<StartWhenAvailable>true</StartWhenAvailable>` is, by Task Scheduler's documented "run as soon as possible
after a scheduled start is missed" rule, run shortly after it is registered, because a new registration has
no last run. That is the usual shape of an updater task.

Failure scenario: the user undoes a session; the vendor's updater task comes back and its program runs as
SYSTEM minutes later, although the design and the module say nothing is ever started. If the file restore of
the same undo failed or was skipped, the path it runs is whatever is there now. A service has the same
question in a smaller form: a restored trigger (`set_config2(Triggers)`) whose condition already holds.

Fix: measure it on the VM (one task: daily trigger in the past, `StartWhenAvailable`, action writes a marker
file; register, wait 15 minutes). If it runs, either (a) refuse such XML in `check_register_xml` with a
distinct error so the scanner marks the task `ReversibilityPartial` and never preselects it, or (b) accept it
and say so: change the module doc and DECISIONS, and make the X-TASK undo require the program file to exist
and be the restored one before it registers. The broad text match on `RegistrationTrigger` is right as it
is (an element name cannot be escaped; a false hit only refuses).

### S3. `map_rule` accepts seven field shapes whose re-creation was never measured, and gives callers no way to tell

Files: `crates/purge-win/src/firewall.rs:364-655` (`Edge=TRUE` alone, `Edge=TRUE` with `Defer=App`, `LSM`,
`LOM`, `ICMP4`/`ICMP6`, `LA4`/`LA6`, `Profile=Domain`, `RPort2_10`), module doc lines 33-36. Reached:
M1B-X-FIREWALL (act deletes any rule `map_rule` accepts), M1B-S-FIREWALL (`recreate_refusal` is a copy of
`map_rule`). Evidence: reading (the mappings look right against the provider's value tables: action 2/4,
enabled 1/2, direction 1/2, profiles 1/2/4, edge policy 1/2/3, interface type 1/2/4); whether the provider
accepts `8:*` for `IcmpType` or writes `LSM`/`LOM` back the same way is suspected.

Failure scenario: a rule with `ICMP4=8:*` is offered, deleted, and on undo `PutInstance` fails or writes a
different string; X-FIREWALL then removes the half-made rule and the user's rule is gone for good (the
coordinator's X-FIREWALL risk). The cause is here: "can be re-created exactly" is answered yes for shapes
that only six spike rules never covered.

Fix: until `create_with_instance_id_round_trips_unproven_fields` (`tests/firewall.rs:375`) has passed on the
VM, `map_rule` refuses those shapes ("not proven"), behind one constant list so the flip is one line per
shape. Then S-FIREWALL's copy follows, or better calls `map_rule` instead of copying it. Also require
`Action`, `Active` and `Dir` to be present (today a rule string lacking one maps, and the provider's default
fills it in).

### S4. The write paths of `scm.rs` and all of the WMI code in `firewall.rs` have never run

Files: `crates/purge-win/tests/scm.rs:156-` (module `elevated`, 6 tests, all `#[ignore]`),
`tests/firewall.rs` module `rig` (9 tests, all `#[ignore]`); `docs/HANDOFF-m1b.md` "Rig work owed". Reached:
the live backends of M1B-X-SERVICE and M1B-X-FIREWALL, and through them M1B-X-INTEG. Evidence: reading.

The spike proved the method in PowerShell (`System.Management`, P/Invoke). The Rust code that will do it
(`CreateServiceW` argument block, the nine `ChangeServiceConfig2W` layouts, `SetServiceObjectSecurity`, the
hand-built `VARIANT`s and SAFEARRAY, `IWbemContext` value types, `__RELPATH` delete, the WQL escape for ids
with a backslash such as `TCP Query User{...}C:\...`) has been compiled and unit-tested on its pure parts
only. "`cargo xtask ci` passed" says nothing about it. (taskschd is different: its register and delete tests
are not ignored and ran on the host.)

Failure scenario: a wrong struct layout or VARIANT type is found at the gate, in wave 7, under three layers
of executor code written against the wrapper's assumed behaviour.

Fix: run the 15 tests on Inbound-Win11-Test now (they are self-contained), before the R1 fixes are closed,
not in wave 6. Record the result in the handoff. This also settles S3.

## Minor

### M1. The digest type lets one object have two digests where a reader differs on "absent"

`crates/purge-model/src/object.rs:235-254` (`TaskAction`), `:193-210`. `arguments`, `working_dir` and `data`
are `Option<String>`, and `Some("")` hashes differently from `None`, as the contract wants. Task Scheduler
cannot tell the two apart: `taskschd.rs:829` maps empty to `None`, and so does `snapfixture.rs:779`, but the
type does not enforce it and the golden task digest itself uses `data: Some(String::new())`, a value no live
reader produces. A JSON fixture or a future reader that keeps `""` gives `ObjectChangedSinceHarvest` for an
unchanged task (safe side, lost recall). The same holds for `Other { kind }`: the coordinator notes already
report `type_<n>` live against a CIM class name in snapshots. Fix: one constructor in purge-model
(`TaskAction::exec(path, args, dir)` and so on) that turns empty into absent and takes the other-kind from a
closed list (`send_email`, `show_message`, `type_<n>`); readers use only it; change the golden sample.
Also: `service_type` and `start` are `u32`, so an absent `Type` or `Start` value hashes as 0 (two readers,
`purge-index/src/sysobj.rs:488` and `purge-exec/src/act_service.rs:389`, both do this; keep them one function,
R2).

### M2. Journal checks do not know the new variants everywhere

- `crates/purge-exec/src/journal/state.rs:939-946`: `check_reconcile` accepts any outcome that is not
  `Done | HeldRetry | PendingReboot` as "the change is not there". `PendingDelete` is a change and passes.
  Use `!outcome.changed() && outcome != HeldRetry`.
- `state.rs:319-325` `pending_of`: `PendingDelete` is no pending kind, yet it is counted in
  `pending_reboot`; a summary can show one pending item and list none. For R3 (X-INTEG).
- `crates/purge-model/src/exec/journal.rs:312-317`: `Intent::is_consistent` checks only the kind of
  `ItemFacts::Object`. Also require a well-formed digest (64 lower-case hex, the rule of
  `ObjectFp::is_well_formed`) and `running == false` (a running service is skipped before any intent).

### M3. Four error types named `WinError`, and a second rule-string parser

`scm.rs:116`, `taskschd.rs:79`, `firewall.rs:103`, `msi_db.rs:181` (handoff point 5). They carry the OS code
in three shapes (`Win32Error`, `u32` HRESULT), which every caller maps to `FailCode::ObjectApi` by hand.
Rename (`ScmError`, `TaskError`, `FwError`, `MsiError`) and give each `fn os_code(&self) -> Option<u32>`.
`firewall.rs:254` `parse_rule` accepts any non-empty version segment while
`purge_model::object::parse_firewall_rule` requires `v<digits>.<digits>`; the crate boundary explains the
copy, but the two must agree: add the version check and a shared table of test strings.

### M4. MSI reader: no total budget, lossy text, UNC accepted

`crates/purge-win/src/msi_db.rs`. Row and cell caps are enforced per table and per cell (`:513-517`,
`:592-600`), but 11 tables of 200,000 rows of 64 Ki-unit cells are far beyond memory; add a total budget
(for example 256 MiB of text, then `truncated`). `:596` converts with `from_utf16_lossy`, so a key name with
an unpaired surrogate becomes a different name with U+FFFD and protects nothing; treat it as truncation.
`:361-364` accepts UNC paths, so a `LocalPackage` value naming `\\host\share\x.msi` opens a network file; the
caller (M1B-OWNERSHIP, R2) should accept only files under `%WINDIR%\Installer`. The cell cap is UTF-16 units
here and UTF-8 bytes in `purge-source/src/sysobj.rs` (`MAX_CELL_BYTES`); both fail closed, but state one unit.

### M5. Task wrapper: folders left behind, and a descriptor that cannot be restored

`taskschd.rs:553-583`: `register_xml` creates missing parent folders before `RegisterTask`; when the
registration is then refused (exists, password needed, bad XML) the new empty folders stay. Remove the
folders this call created when it fails (the one place a folder delete is justified), or report them.
`taskschd.rs:338-343`: the `sddl` argument is ignored by design (spike). A task whose descriptor was changed
after registration, so that the XML does not carry it, comes back with another DACL and no function here can
set it. The spike had no such task. R2 should confirm that X-TASK compares the SDDL after undo and reports the
difference instead of `Restored`.

### M6. SCM wrapper: smaller points

- `scm.rs:593-597`, `:1337`: `is_plain_win32_service` accepts `0x30` for `create` too; `CreateServiceW`
  refuses it with 87. Accept `0x30` only on the status side (delete) and exactly `0x10` or `0x20` (with or
  without `0x100`) for create.
- `scm.rs:1257-1271`: between the status check and `DeleteService` a demand- or trigger-start service can
  start; the delete then marks a running service. Inherent in the API; the caller's post-check
  (`DeleteFlag`, `PendingDelete`) covers it. Say so in the doc instead of "never".
- `scm.rs:1666-1668`: a handle with `SERVICE_START` access is opened for failure actions that restart. No
  start call exists (the grep test holds); noted because the attack list asks.

### M7. KB: one name and one gap are wrong

`kb/shared-iids.json`, `kb/README.md` "Gaps" (handoff point 6). `{C48C7FCF-4AB5-4056-AFA6-902D6E1D1149}` is
`IAccessibleDocument` in the IAccessible2 IDL (suspected: from the reviewer's memory of the IDL, check
`AccessibleDocument.idl`); Windows' `ia2comproxy.dll` registers it under the name `IAccessibleAction`
(experiment: that is the name in the snap). So `IAccessibleDocument` is already covered and is not a gap; fix
the `why` text and the README. `IAccessible2_3` is on the design's "must contain at least" list and is
missing because no capture has it. The design also says a missing entry is a danger and a wrong extra one
only costs recall, so add it (and `IAccessible2_4`) from the published IDL with a `"source": "idl"` marker
that the snap test skips, rather than wait for a capture. R3 should check that COM-INTERFACE does not rely on
this list alone for a shared interface key.

## Answers to the attack list (design, R1)

1. **Object digest.** No collision found: every value carries its byte length, absent is `-`, the action
   count precedes the actions, `other:<kind>` cannot equal `exec` or `com_handler`, only the service name and
   task path are folded, action order counts. One object with two digests: only through readers, M1.
2. **Selectors, overwrite, running service, start/stop.** Exact name, path or id only (`OpenServiceW` takes
   the key name, not the display name). `TASK_CREATE` and `WBEM_FLAG_CREATE_ONLY` only. Delete refuses any
   state but stopped and any type but plain Win32 (M6 for the race). No start, stop or run call exists;
   indirect start on re-registration is S2.
3. **WQL literal.** Backslash and quote escaped, parsed back and compared; control characters (C0, DEL, C1)
   and ids over 260 UTF-16 units refused before WMI; exactly one match required and its `InstanceID` compared
   exactly, so a case-variant id or a provider that ignored the filter deletes nothing. Sound by reading;
   never run (S4).
4. **MSI reader.** Only `MsiOpenDatabaseW(READONLY)`, view and record calls. Database, view and record
   handles are guarded from the line after the call that returns them. Caps enforced per table and cell; no
   total (M4).
5. **Golden files.** The diff adds three test data files and edits none; `golden.rs` gains only the
   `object_fp: None` field of a constructor; a new test shows `object_fp` outside the plan hash. Not re-run by
   the reviewer.
6. **KB IIDs.** Checked against the snap: see "Checked".

## Answers to the handoff's eight points

1. `ItemOutcome::PendingDelete`: accept. The reason given is right (no boot-move pair). Follow-ups in M2.
2. SCM refusals beyond the design: accept all three. `0x30` on the status side is right; tighten create (M6).
   A service whose original DACL was NULL cannot be restored exactly; the scanner must call that partial (R2).
3. `RegistrationTrigger`: the refusal is right and not enough: S2.
4. Firewall fields by inference: S3, S4. WQL escaping and the exact-id check: sound by reading.
5. Four `WinError`s and local types: M3. The mapping in wave 2 is R2's.
6. `{C48C7FCF-...}`: M7. The object shape of `shared-iids.json` and the `flate2` dev-dependency: accept.
7. Arms outside M1B-MODEL's list: none changes M2 behaviour. `plan_in::selectable` still gives an object
   item no op for every `resolve` result (`plan_in.rs:713-716`), `report.rs` drops a resolved object op,
   `band.rs:182-183` keeps object targets without a support scope, the executor arms refuse or are
   unreachable. The one place that needs the new variant and did not get it is M2 (first bullet).
8. Fixture rejects unknown top-level keys; an oversized cell drops the row and sets `truncated`: accept, it
   matches purge-win. One unit for the cell cap: M4.

## Checked and found sound

- KB (experiment): a read-only script over `vm/runs/dirty-base/snap-dirty-base-0.tsv.gz` found all 24 IIDs
  as `Classes\Interface\{IID}` keys whose default value is the listed name, and all 9 proxy CLSIDs as
  `Classes\CLSID` keys. The values were not typed from memory.
- Firewall value tables and the context-value types (`VT_BSTR`, `VT_ARRAY|VT_BSTR`, `VT_UI4`) agree with what
  the spike script passed through `System.Management`.
- `scm.rs` buffer handling: needed-size loop capped at 256 KiB, every pointer in a returned buffer checked to
  lie inside it, strings checked for terminator and UTF-16; `Config2Arg` keeps every pointed-to block alive.
- `set_security`: DACL only, refuses an SDDL without a DACL or with a NULL DACL.
- COM guards in taskschd and firewall: `CoUninitialize` only after an own successful `CoInitializeEx`.
- Fingerprint: the three new fields are skipped when empty; `ManifestKind` keeps its spelling.
- Blocker hard/soft match is exhaustive, no wildcard.

## Not checked

- Nothing was built or run except the KB script. Every statement about Windows behaviour not in the spike
  result is from reading or memory and is labelled.
- Test bodies were read only for scm delete (mock), the WQL tests and the three grep tests.
- `M1B-RIG-GUEST` (vm/) is outside the scope.
- Wave 2 and later code, beyond the lines cited.
