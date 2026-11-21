// The engine API's DTOs, hand-written over System.Text.Json (M3_DESIGN.md §6.5, design 15).
// No reflection: the source-generated RpcJsonContext in Generated/ is what reads and writes them,
// so Native AOT needs no metadata at run time. Enums are strings in the JSON; each member names
// its exact wire value.

using System.Text.Json.Serialization;

namespace Purge.Client.Rpc;

/// <summary>
/// Why an item is in a plan's attention list (design 8.1).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<AttentionReason>))]
public enum AttentionReason
{
    [JsonStringEnumMemberName("user_data")]
    UserData,
    [JsonStringEnumMemberName("not_preselected")]
    NotPreselected,
    [JsonStringEnumMemberName("large")]
    Large,
    [JsonStringEnumMemberName("no_undo")]
    NoUndo,
    [JsonStringEnumMemberName("inside")]
    Inside,
    [JsonStringEnumMemberName("name")]
    Name,
}

/// <summary>
/// The confidence band policy assigns to a candidate (ENGINE_PLAN.md §5.8.2).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<Band>))]
public enum Band
{
    [JsonStringEnumMemberName("Safe")]
    Safe,
    [JsonStringEnumMemberName("Likely")]
    Likely,
    [JsonStringEnumMemberName("Weak")]
    Weak,
    [JsonStringEnumMemberName("Blocked")]
    Blocked,
}

/// <summary>
/// How far a baseline view can be trusted when it says "this key is not Windows' own"
/// (BASELINE_LOCAL_DESIGN.md §4.1). Serialised by its variant name.
/// Presence ("Windows has it") blocks at every level. Absence is *proof* only at [`BaselineTrust::Exact`];
/// at `Merged` and `Local` it is *inferred* and under the trust cap (invariant L4: it never makes an item
/// Safe or preselected); at `None` it is never answered.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<BaselineTrust>))]
public enum BaselineTrust
{
    [JsonStringEnumMemberName("Exact")]
    Exact,
    [JsonStringEnumMemberName("Merged")]
    Merged,
    [JsonStringEnumMemberName("Local")]
    Local,
    [JsonStringEnumMemberName("None")]
    None,
}

/// <summary>
/// What kind of thing a candidate is, for grouping and preselection (ENGINE_PLAN.md §5.2).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<Category>))]
public enum Category
{
    [JsonStringEnumMemberName("AppFiles")]
    AppFiles,
    [JsonStringEnumMemberName("AppData")]
    AppData,
    [JsonStringEnumMemberName("UserData")]
    UserData,
    [JsonStringEnumMemberName("Cache")]
    Cache,
    [JsonStringEnumMemberName("Registration")]
    Registration,
    [JsonStringEnumMemberName("Association")]
    Association,
    [JsonStringEnumMemberName("ShellCom")]
    ShellCom,
    [JsonStringEnumMemberName("Startup")]
    Startup,
    [JsonStringEnumMemberName("System")]
    System,
    [JsonStringEnumMemberName("Privacy")]
    Privacy,
    [JsonStringEnumMemberName("Package")]
    Package,
}

/// <summary>
/// The engine token's `TokenElevationType`.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<ElevationType>))]
public enum ElevationType
{
    [JsonStringEnumMemberName("default")]
    Default,
    [JsonStringEnumMemberName("full")]
    Full,
    [JsonStringEnumMemberName("limited")]
    Limited,
}

/// <summary>
/// What kind of failure ended an item.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<FailCode>))]
public enum FailCode
{
    [JsonStringEnumMemberName("AccessDenied")]
    AccessDenied,
    [JsonStringEnumMemberName("InUse")]
    InUse,
    [JsonStringEnumMemberName("ControlledFolderAccess")]
    ControlledFolderAccess,
    [JsonStringEnumMemberName("VerifyFailed")]
    VerifyFailed,
    [JsonStringEnumMemberName("PackageApi")]
    PackageApi,
    [JsonStringEnumMemberName("ObjectApi")]
    ObjectApi,
    [JsonStringEnumMemberName("Os")]
    Os,
    [JsonStringEnumMemberName("Internal")]
    Internal,
}

/// <summary>
/// Which kind of id a [`ErrorData::Gone`] error is about.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<IdKind>))]
public enum IdKind
{
    [JsonStringEnumMemberName("uninstall_session")]
    UninstallSession,
    [JsonStringEnumMemberName("scan")]
    Scan,
    [JsonStringEnumMemberName("plan")]
    Plan,
    [JsonStringEnumMemberName("candidate")]
    Candidate,
    [JsonStringEnumMemberName("session")]
    Session,
    [JsonStringEnumMemberName("expiry")]
    Expiry,
    [JsonStringEnumMemberName("program")]
    Program,
}

/// <summary>
/// Whether an app is installed for the machine or for one user.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<InstallScope>))]
public enum InstallScope
{
    [JsonStringEnumMemberName("Machine")]
    Machine,
    [JsonStringEnumMemberName("User")]
    User,
}

/// <summary>
/// The installer technology behind an entry.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<InstallerKind>))]
public enum InstallerKind
{
    [JsonStringEnumMemberName("Msi")]
    Msi,
    [JsonStringEnumMemberName("Inno")]
    Inno,
    [JsonStringEnumMemberName("Nsis")]
    Nsis,
    [JsonStringEnumMemberName("Burn")]
    Burn,
    [JsonStringEnumMemberName("Unknown")]
    Unknown,
}

/// <summary>
/// What kind of thing an item is, for display.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<ItemKind>))]
public enum ItemKind
{
    [JsonStringEnumMemberName("file")]
    File,
    [JsonStringEnumMemberName("folder")]
    Folder,
    [JsonStringEnumMemberName("registry_key")]
    RegistryKey,
    [JsonStringEnumMemberName("registry_value")]
    RegistryValue,
    [JsonStringEnumMemberName("registry_data")]
    RegistryData,
    [JsonStringEnumMemberName("service")]
    Service,
    [JsonStringEnumMemberName("task")]
    Task,
    [JsonStringEnumMemberName("firewall_rule")]
    FirewallRule,
    [JsonStringEnumMemberName("package")]
    Package,
}

/// <summary>
/// What a run did. Carried by results; not an error.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<Outcome>))]
public enum Outcome
{
    [JsonStringEnumMemberName("complete")]
    Complete,
    [JsonStringEnumMemberName("partial")]
    Partial,
    [JsonStringEnumMemberName("undo_conflicts")]
    UndoConflicts,
    [JsonStringEnumMemberName("not_closed")]
    NotClosed,
}

/// <summary>
/// When `plan.execute` asks for a restore point.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RestorePoint>))]
public enum RestorePoint
{
    [JsonStringEnumMemberName("off")]
    Off,
    [JsonStringEnumMemberName("high_risk")]
    HighRisk,
    [JsonStringEnumMemberName("always")]
    Always,
}

/// <summary>
/// What a retention period applies to (§7.8).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RetentionClass>))]
public enum RetentionClass
{
    [JsonStringEnumMemberName("Quarantine")]
    Quarantine,
    [JsonStringEnumMemberName("Backup")]
    Backup,
    [JsonStringEnumMemberName("Journal")]
    Journal,
}

/// <summary>
/// Where a program's uninstaller runs (design 3.2).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<Route>))]
public enum Route
{
    [JsonStringEnumMemberName("broker")]
    Broker,
    [JsonStringEnumMemberName("medium")]
    Medium,
}

/// <summary>
/// How the uninstaller ended (§4.4 "Exit codes").
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RunOutcome>))]
public enum RunOutcome
{
    [JsonStringEnumMemberName("Success")]
    Success,
    [JsonStringEnumMemberName("AlreadyGone")]
    AlreadyGone,
    [JsonStringEnumMemberName("SuccessReboot")]
    SuccessReboot,
    [JsonStringEnumMemberName("Cancelled")]
    Cancelled,
    [JsonStringEnumMemberName("Failed")]
    Failed,
    [JsonStringEnumMemberName("TimedOut")]
    TimedOut,
}

/// <summary>
/// The situation a leftover scan runs in (ENGINE_PLAN.md §5.1).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<ScanMode>))]
public enum ScanMode
{
    [JsonStringEnumMemberName("post")]
    Post,
    [JsonStringEnumMemberName("external")]
    External,
    [JsonStringEnumMemberName("forced")]
    Forced,
}

/// <summary>
/// Where a session stands.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<SessionState>))]
public enum SessionState
{
    [JsonStringEnumMemberName("Open")]
    Open,
    [JsonStringEnumMemberName("Committed")]
    Committed,
    [JsonStringEnumMemberName("Aborted")]
    Aborted,
    [JsonStringEnumMemberName("Undone")]
    Undone,
    [JsonStringEnumMemberName("PartiallyUndone")]
    PartiallyUndone,
}

/// <summary>
/// Who can write an entry's Uninstall key; decides where its uninstaller may run (§4.4) and how far its
/// values are trusted (Rule T, §5.3).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<WritableBy>))]
public enum WritableBy
{
    [JsonStringEnumMemberName("admin")]
    Admin,
    [JsonStringEnumMemberName("user")]
    User,
}

/// <summary>
/// The app something belongs to: its stable id plus the name to show.
/// </summary>
public sealed class AppRef
{
    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

}

/// <summary>
/// An item of a plan's attention list.
/// </summary>
public sealed class AttentionItem
{
    [JsonPropertyName("band")]
    public Band Band { get; set; } = default!;

    [JsonPropertyName("candidate_id")]
    public string CandidateId { get; set; } = "";

    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("kind")]
    public ItemKind Kind { get; set; } = default!;

    [JsonPropertyName("reasons")]
    public System.Collections.Generic.List<AttentionReason> Reasons { get; set; } = new();

    [JsonPropertyName("size_bytes")]
    public ulong? SizeBytes { get; set; }

}

/// <summary>
/// Candidates per band.
/// </summary>
public sealed class BandCounts
{
    [JsonPropertyName("blocked")]
    public uint Blocked { get; set; }

    [JsonPropertyName("likely")]
    public uint Likely { get; set; }

    [JsonPropertyName("preselected")]
    public uint Preselected { get; set; }

    [JsonPropertyName("safe")]
    public uint Safe { get; set; }

    [JsonPropertyName("weak")]
    public uint Weak { get; set; }

}

/// <summary>
/// The state of the local baseline's background build (BASELINE_LOCAL_DESIGN.md §5, W4): it starts
/// with the engine, never blocks a scan, and a scan made before it ended can be made again after.
/// </summary>
public sealed class BaselineBuild
{
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; set; }

    [JsonPropertyName("state")]
    public string State { get; set; } = "";

    [JsonPropertyName("parts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<string>? Parts { get; set; }

    [JsonPropertyName("scan_waiting")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ScanWaiting { get; set; }

    [JsonPropertyName("rescan")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Rescan { get; set; }

}

/// <summary>
/// `baseline.changed`: the build state, and the scans worth making again when a build completed.
/// </summary>
public sealed class BaselineChanged
{
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; set; }

    [JsonPropertyName("state")]
    public string State { get; set; } = "";

    [JsonPropertyName("parts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<string>? Parts { get; set; }

    [JsonPropertyName("scan_waiting")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ScanWaiting { get; set; }

    [JsonPropertyName("rescan")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Rescan { get; set; }

    [JsonPropertyName("rescan_offered")]
    public System.Collections.Generic.List<string> RescanOffered { get; set; } = new();

}

/// <summary>
/// The baseline view a fingerprint was harvested with (design §4.5): the trust beside the absence facts
/// the fingerprint stores (`ext_journal`, the subtree records).
/// </summary>
public sealed class BaselineViewRef
{
    [JsonPropertyName("local_id")]
    public string? LocalId { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("trust")]
    public BaselineTrust Trust { get; set; } = default!;

}

/// <summary>
/// A reason against removing a candidate. Serialised as an object tagged by `"kind"`, e.g.
/// `{"kind":"ReferencedByOtherApp","app":"Mozilla Thunderbird"}`.
/// </summary>
public sealed class Blocker
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("rule")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Rule { get; set; }

    [JsonPropertyName("product")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Product { get; set; }

    [JsonPropertyName("row")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Row { get; set; }

    [JsonPropertyName("app")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? App { get; set; }

    [JsonPropertyName("names")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<string>? Names { get; set; }

    [JsonPropertyName("n")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? N { get; set; }

}

/// <summary>
/// One entry of the boot-time move list (`PendingFileRenameOperations`), as the strings stand in the
/// value: the session manager renames `src` to `dst` at the next boot.
/// </summary>
public sealed class BootMovePair
{
    [JsonPropertyName("dst")]
    public string Dst { get; set; } = "";

    [JsonPropertyName("src")]
    public string Src { get; set; } = "";

}

/// <summary>
/// `$/cancel {request}`.
/// </summary>
public sealed class CancelParams
{
    [JsonPropertyName("request")]
    public ulong Request { get; set; }

}

/// <summary>
/// One candidate of a `scan.candidates` page.
/// </summary>
public sealed class CandidateRow
{
    [JsonPropertyName("band")]
    public Band Band { get; set; } = default!;

    [JsonPropertyName("candidate_id")]
    public string CandidateId { get; set; } = "";

    [JsonPropertyName("category")]
    public Category Category { get; set; } = default!;

    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("kind")]
    public ItemKind Kind { get; set; } = default!;

    [JsonPropertyName("owner_program")]
    public string? OwnerProgram { get; set; }

    [JsonPropertyName("preselected")]
    public bool Preselected { get; set; }

    [JsonPropertyName("size_bytes")]
    public ulong? SizeBytes { get; set; }

    [JsonPropertyName("warnings")]
    public System.Collections.Generic.List<Warning> Warnings { get; set; } = new();

}

/// <summary>
/// `scan.candidates`.
/// </summary>
public sealed class CandidatesPage
{
    [JsonPropertyName("items")]
    public System.Collections.Generic.List<CandidateRow> Items { get; set; } = new();

    [JsonPropertyName("offset")]
    public uint Offset { get; set; }

    [JsonPropertyName("total")]
    public uint Total { get; set; }

}

/// <summary>
/// `scan.candidates {scan_id, offset, limit}`.
/// </summary>
public sealed class CandidatesParams
{
    [JsonPropertyName("limit")]
    public long Limit { get; set; }

    [JsonPropertyName("offset")]
    public uint Offset { get; set; }

    [JsonPropertyName("scan_id")]
    public string ScanId { get; set; } = "";

}

/// <summary>
/// A product removed together with the program.
/// </summary>
public sealed class CoProduct
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("program_id")]
    public string? ProgramId { get; set; }

}

/// <summary>
/// One conflict of an undo.
/// </summary>
public sealed class ConflictRow
{
    [JsonPropertyName("conflict")]
    public UndoConflict Conflict { get; set; } = default!;

    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("op")]
    public uint Op { get; set; }

}

/// <summary>
/// `consent.shown`.
/// </summary>
public sealed class ConsentShown
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = "";

    [JsonPropertyName("request")]
    public ulong Request { get; set; }

}

/// <summary>
/// The result of [`ENGINE_HELLO`].
/// </summary>
public sealed class EngineHello
{
    [JsonPropertyName("baseline_available")]
    public bool BaselineAvailable { get; set; }

    [JsonPropertyName("baseline_build")]
    public BaselineBuild BaselineBuild { get; set; } = default!;

    [JsonPropertyName("baseline_trust")]
    public BaselineTrust BaselineTrust { get; set; } = default!;

    [JsonPropertyName("baseline_view")]
    public BaselineViewRef? BaselineView { get; set; }

    [JsonPropertyName("build")]
    public uint Build { get; set; }

    [JsonPropertyName("edition")]
    public string Edition { get; set; } = "";

    [JsonPropertyName("elevated")]
    public bool Elevated { get; set; }

    [JsonPropertyName("policy_version")]
    public string PolicyVersion { get; set; } = "";

    [JsonPropertyName("shell_sid")]
    public string? ShellSid { get; set; }

    [JsonPropertyName("ubr")]
    public uint Ubr { get; set; }

    [JsonPropertyName("user_sid")]
    public string UserSid { get; set; } = "";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

}

/// <summary>
/// `error.data` of a [`SERVER_ERROR`]: the kind, and what the client needs to show it. Serialised as an
/// object tagged by `"kind"`.
/// </summary>
public sealed class ErrorData
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("refusals")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<Refusal>? Refusals { get; set; }

    [JsonPropertyName("sessions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<string>? Sessions { get; set; }

    [JsonPropertyName("message")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; set; }

    [JsonPropertyName("exit_code")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? ExitCode { get; set; }

    [JsonPropertyName("forced_offered")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ForcedOffered { get; set; }

    [JsonPropertyName("route")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Route? Route { get; set; }

    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IdKind? Id { get; set; }

    [JsonPropertyName("cap")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong? Cap { get; set; }

    [JsonPropertyName("needed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong? Needed { get; set; }

    [JsonPropertyName("used")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong? Used { get; set; }

    [JsonPropertyName("volume")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Volume { get; set; }

}

/// <summary>
/// The `error` member of a JSON-RPC response.
/// </summary>
public sealed class ErrorObject
{
    [JsonPropertyName("code")]
    public int Code { get; set; }

    [JsonPropertyName("data")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ErrorData? Data { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

}

/// <summary>
/// `plan.execute`.
/// </summary>
public sealed class ExecResult
{
    [JsonPropertyName("counts")]
    public OutcomeCounts Counts { get; set; } = default!;

    [JsonPropertyName("held")]
    public System.Collections.Generic.List<HeldItem> Held { get; set; } = new();

    [JsonPropertyName("outcome")]
    public Outcome Outcome { get; set; } = default!;

    [JsonPropertyName("restore_point")]
    public RestorePointOutcome RestorePoint { get; set; } = default!;

    [JsonPropertyName("session")]
    public string Session { get; set; } = "";

}

/// <summary>
/// One entry past retention.
/// </summary>
public sealed class ExpiringItem
{
    [JsonPropertyName("app")]
    public string App { get; set; } = "";

    [JsonPropertyName("bytes")]
    public ulong Bytes { get; set; }

    [JsonPropertyName("class")]
    public RetentionClass Class { get; set; } = default!;

    [JsonPropertyName("expired")]
    public ulong Expired { get; set; }

    [JsonPropertyName("expiry_id")]
    public string ExpiryId { get; set; } = "";

    [JsonPropertyName("files")]
    public System.Collections.Generic.List<string> Files { get; set; } = new();

    [JsonPropertyName("session")]
    public string Session { get; set; } = "";

    [JsonPropertyName("user_data")]
    public bool UserData { get; set; }

}

/// <summary>
/// `quarantine.expiring`.
/// </summary>
public sealed class ExpiringList
{
    [JsonPropertyName("items")]
    public System.Collections.Generic.List<ExpiringItem> Items { get; set; } = new();

}

/// <summary>
/// When each class of a session's data expires. Expiry only proposes; nothing is deleted on these dates
/// without a prompt.
/// </summary>
public sealed class Expiry
{
    [JsonPropertyName("backups")]
    public ulong Backups { get; set; }

    [JsonPropertyName("journal")]
    public ulong Journal { get; set; }

    [JsonPropertyName("quarantine")]
    public ulong Quarantine { get; set; }

}

/// <summary>
/// `candidate.explain {scan_id, candidate_id}`.
/// </summary>
public sealed class ExplainParams
{
    [JsonPropertyName("candidate_id")]
    public string CandidateId { get; set; } = "";

    [JsonPropertyName("scan_id")]
    public string ScanId { get; set; } = "";

}

/// <summary>
/// `candidate.explain`.
/// </summary>
public sealed class Explanation
{
    [JsonPropertyName("blockers")]
    public System.Collections.Generic.List<string> Blockers { get; set; } = new();

    [JsonPropertyName("candidate_id")]
    public string CandidateId { get; set; } = "";

    [JsonPropertyName("evidence")]
    public System.Collections.Generic.List<string> Evidence { get; set; } = new();

}

/// <summary>
/// What a harvest found, in counts (display only).
/// </summary>
public sealed class FingerprintSummary
{
    [JsonPropertyName("files")]
    public uint Files { get; set; }

    [JsonPropertyName("objects")]
    public uint Objects { get; set; }

    [JsonPropertyName("registry")]
    public uint Registry { get; set; }

    [JsonPropertyName("roots")]
    public uint Roots { get; set; }

}

/// <summary>
/// An item left in place because it is locked.
/// </summary>
public sealed class HeldItem
{
    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("lockers")]
    public System.Collections.Generic.List<Locker> Lockers { get; set; } = new();

    [JsonPropertyName("op")]
    public uint Op { get; set; }

}

/// <summary>
/// `history.get`.
/// </summary>
public sealed class HistoryDetail
{
    [JsonPropertyName("items")]
    public System.Collections.Generic.List<HistoryItem> Items { get; set; } = new();

    [JsonPropertyName("session")]
    public string Session { get; set; } = "";

    [JsonPropertyName("state")]
    public SessionState State { get; set; } = default!;

}

/// <summary>
/// `history.index`.
/// </summary>
public sealed class HistoryIndex
{
    [JsonPropertyName("sessions")]
    public System.Collections.Generic.List<SessionSummary> Sessions { get; set; } = new();

    [JsonPropertyName("volumes")]
    public System.Collections.Generic.List<VolumeCap> Volumes { get; set; } = new();

}

/// <summary>
/// One item of `history.get`.
/// </summary>
public sealed class HistoryItem
{
    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = "";

    [JsonPropertyName("kind")]
    public ItemKind Kind { get; set; } = default!;

    [JsonPropertyName("op")]
    public uint Op { get; set; }

    [JsonPropertyName("outcome")]
    public ItemOutcome Outcome { get; set; } = default!;

    [JsonPropertyName("undone")]
    public bool Undone { get; set; }

}

/// <summary>
/// One icon of an `icon.batch`.
/// </summary>
public sealed class Icon
{
    [JsonPropertyName("bgra")]
    public string? Bgra { get; set; }

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

    [JsonPropertyName("px")]
    public long Px { get; set; }

}

/// <summary>
/// `icon.batch`: at most [`ICONS_PER_LINE`] icons.
/// </summary>
public sealed class IconBatch
{
    [JsonPropertyName("icons")]
    public System.Collections.Generic.List<Icon> Icons { get; set; } = new();

    [JsonPropertyName("request")]
    public ulong Request { get; set; }

}

/// <summary>
/// `programs.icons {program_ids[], px}`.
/// </summary>
public sealed class IconsParams
{
    [JsonPropertyName("program_ids")]
    public System.Collections.Generic.List<string> ProgramIds { get; set; } = new();

    [JsonPropertyName("px")]
    public long Px { get; set; }

}

/// <summary>
/// `inventory.changes`, against the last list stored in `%LOCALAPPDATA%\Purge` (display only).
/// </summary>
public sealed class InventoryChanges
{
    [JsonPropertyName("appeared")]
    public System.Collections.Generic.List<ProgramRef> Appeared { get; set; } = new();

    [JsonPropertyName("disappeared")]
    public System.Collections.Generic.List<ProgramRef> Disappeared { get; set; } = new();

}

/// <summary>
/// How one item ended. Serialised as an object tagged by `"kind"`.
/// </summary>
public sealed class ItemOutcome
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SkipReason? Reason { get; set; }

    [JsonPropertyName("confirmed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Confirmed { get; set; }

    [JsonPropertyName("pair")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public BootMovePair? Pair { get; set; }

    [JsonPropertyName("code")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FailCode? Code { get; set; }

    [JsonPropertyName("detail")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }

    [JsonPropertyName("os_error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? OsError { get; set; }

}

/// <summary>
/// How far a session's journal reached when the index entry was written: its number of lines (the header
/// included) and the hash-chain value of the last of them.
/// </summary>
public sealed class JournalMark
{
    [JsonPropertyName("head")]
    public string Head { get; set; } = "";

    [JsonPropertyName("records")]
    public ulong Records { get; set; }

}

/// <summary>
/// `leftovers.scan`: one of two forms.
/// </summary>
public sealed class LeftoversScanParams
{
    [JsonPropertyName("forced")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Forced { get; set; }

    [JsonPropertyName("session_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SessionId { get; set; }

    [JsonPropertyName("program_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProgramId { get; set; }

}

/// <summary>
/// A process that holds a file open, as Restart Manager reports it.
/// </summary>
public sealed class Locker
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("pid")]
    public uint Pid { get; set; }

    [JsonPropertyName("service")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Service { get; set; }

}

/// <summary>
/// `engine.hello` of the medium engine: [`EngineHello`] and the token facts of design 3.5.
/// </summary>
public sealed class MediumHello
{
    [JsonPropertyName("baseline_available")]
    public bool BaselineAvailable { get; set; }

    [JsonPropertyName("baseline_build")]
    public BaselineBuild BaselineBuild { get; set; } = default!;

    [JsonPropertyName("baseline_trust")]
    public BaselineTrust BaselineTrust { get; set; } = default!;

    [JsonPropertyName("baseline_view")]
    public BaselineViewRef? BaselineView { get; set; }

    [JsonPropertyName("build")]
    public uint Build { get; set; }

    [JsonPropertyName("edition")]
    public string Edition { get; set; } = "";

    [JsonPropertyName("elevated")]
    public bool Elevated { get; set; }

    [JsonPropertyName("elevation_type")]
    public ElevationType ElevationType { get; set; } = default!;

    [JsonPropertyName("policy_version")]
    public string PolicyVersion { get; set; } = "";

    [JsonPropertyName("shell_matches")]
    public bool ShellMatches { get; set; }

    [JsonPropertyName("shell_sid")]
    public string? ShellSid { get; set; }

    [JsonPropertyName("ubr")]
    public uint Ubr { get; set; }

    [JsonPropertyName("user_sid")]
    public string UserSid { get; set; } = "";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "";

}

/// <summary>
/// The params of a method that takes none: absent, `null` or `{}`.
/// </summary>
public sealed class NoParams
{
}

/// <summary>
/// `uninstall.observed {session_id}`.
/// </summary>
public sealed class ObservedParams
{
    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

}

/// <summary>
/// `uninstall.observed`.
/// </summary>
public sealed class ObservedResult
{
    [JsonPropertyName("verify_gone")]
    public VerifyGone VerifyGone { get; set; } = default!;

}

/// <summary>
/// How many items ended in each [`ItemOutcome`]. Every field reads as 0 when missing.
/// </summary>
public sealed class OutcomeCounts
{
    [JsonPropertyName("done")]
    public uint Done { get; set; }

    [JsonPropertyName("failed")]
    public uint Failed { get; set; }

    [JsonPropertyName("held_retry")]
    public uint HeldRetry { get; set; }

    [JsonPropertyName("pending_reboot")]
    public uint PendingReboot { get; set; }

    [JsonPropertyName("skipped")]
    public uint Skipped { get; set; }

    [JsonPropertyName("vanished")]
    public uint Vanished { get; set; }

}

/// <summary>
/// `journal.resume`, `journal.rollback`, `journal.retry_held`.
/// </summary>
public sealed class OutcomeResult
{
    [JsonPropertyName("outcome")]
    public Outcome Outcome { get; set; } = default!;

}

/// <summary>
/// `journal.pending`.
/// </summary>
public sealed class PendingList
{
    [JsonPropertyName("sessions")]
    public System.Collections.Generic.List<PendingSession> Sessions { get; set; } = new();

}

/// <summary>
/// An interrupted session.
/// </summary>
public sealed class PendingSession
{
    [JsonPropertyName("app")]
    public string App { get; set; } = "";

    [JsonPropertyName("done")]
    public uint Done { get; set; }

    [JsonPropertyName("session")]
    public string Session { get; set; } = "";

    [JsonPropertyName("started")]
    public ulong Started { get; set; }

    [JsonPropertyName("total")]
    public uint Total { get; set; }

}

/// <summary>
/// Item counts of a plan.
/// </summary>
public sealed class PlanCounts
{
    [JsonPropertyName("items")]
    public uint Items { get; set; }

    [JsonPropertyName("preselected")]
    public uint Preselected { get; set; }

    [JsonPropertyName("ticked")]
    public uint Ticked { get; set; }

}

/// <summary>
/// `plan.create`: one of two forms.
/// </summary>
public sealed class PlanCreateParams
{
    [JsonPropertyName("scan_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ScanId { get; set; }

    [JsonPropertyName("selected")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<string>? Selected { get; set; }

    [JsonPropertyName("preselected")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Preselected { get; set; }

}

/// <summary>
/// `plan.create`. A refused plan is the error `plan_refused`.
/// </summary>
public sealed class PlanCreated
{
    [JsonPropertyName("attention")]
    public System.Collections.Generic.List<AttentionItem> Attention { get; set; } = new();

    [JsonPropertyName("bytes")]
    public ulong Bytes { get; set; }

    [JsonPropertyName("code")]
    public string Code { get; set; } = "";

    [JsonPropertyName("counts")]
    public PlanCounts Counts { get; set; } = default!;

    [JsonPropertyName("plan_hash")]
    public string PlanHash { get; set; } = "";

    [JsonPropertyName("plan_id")]
    public string PlanId { get; set; } = "";

    [JsonPropertyName("warnings")]
    public System.Collections.Generic.List<Warning> Warnings { get; set; } = new();

}

/// <summary>
/// `plan.execute {plan_id, restore_point}`.
/// </summary>
public sealed class PlanExecuteParams
{
    [JsonPropertyName("plan_id")]
    public string PlanId { get; set; } = "";

    [JsonPropertyName("restore_point")]
    public RestorePoint RestorePoint { get; set; } = default!;

}

/// <summary>
/// `plan.create` with the scan's preselection: `{scan_id, preselected: true}`.
/// </summary>
public sealed class PlanPreselectedParams
{
    [JsonPropertyName("preselected")]
    public bool Preselected { get; set; }

    [JsonPropertyName("scan_id")]
    public string ScanId { get; set; } = "";

}

/// <summary>
/// `plan.create` with the user's selection: `{scan_id, selected[]}`.
/// </summary>
public sealed class PlanSelectedParams
{
    [JsonPropertyName("scan_id")]
    public string ScanId { get; set; } = "";

    [JsonPropertyName("selected")]
    public System.Collections.Generic.List<string> Selected { get; set; } = new();

}

/// <summary>
/// `uninstall.prepare`.
/// </summary>
public sealed class PrepareResult
{
    [JsonPropertyName("programs")]
    public System.Collections.Generic.List<Prepared> Programs { get; set; } = new();

}

/// <summary>
/// One program of `uninstall.prepare`.
/// </summary>
public sealed class Prepared
{
    [JsonPropertyName("co_products")]
    public System.Collections.Generic.List<CoProduct> CoProducts { get; set; } = new();

    [JsonPropertyName("command")]
    public string Command { get; set; } = "";

    [JsonPropertyName("fingerprint_summary")]
    public FingerprintSummary FingerprintSummary { get; set; } = default!;

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

    [JsonPropertyName("quiet_command")]
    public string? QuietCommand { get; set; }

    [JsonPropertyName("route")]
    public Route Route { get; set; } = default!;

    [JsonPropertyName("running")]
    public System.Collections.Generic.List<RunningProcess> Running { get; set; } = new();

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("signer")]
    public string? Signer { get; set; }

    [JsonPropertyName("warnings")]
    public System.Collections.Generic.List<Warning> Warnings { get; set; } = new();

}

/// <summary>
/// `programs.get`: the details pane.
/// </summary>
public sealed class ProgramDetails
{
    [JsonPropertyName("install_location")]
    public string? InstallLocation { get; set; }

    [JsonPropertyName("install_time")]
    public ulong? InstallTime { get; set; }

    [JsonPropertyName("installer")]
    public InstallerKind Installer { get; set; } = default!;

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("product_code")]
    public string? ProductCode { get; set; }

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

    [JsonPropertyName("publisher")]
    public string? Publisher { get; set; }

    [JsonPropertyName("quiet_uninstall_command")]
    public string? QuietUninstallCommand { get; set; }

    [JsonPropertyName("scope")]
    public InstallScope Scope { get; set; } = default!;

    [JsonPropertyName("size_bytes")]
    public ulong? SizeBytes { get; set; }

    [JsonPropertyName("uninstall_command")]
    public string? UninstallCommand { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("writable_by")]
    public WritableBy WritableBy { get; set; } = default!;

}

/// <summary>
/// `{program_id}`: `programs.get`, `uninstall.route`.
/// </summary>
public sealed class ProgramParams
{
    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

}

/// <summary>
/// Details for a row already sent; only the members that are present change.
/// </summary>
public sealed class ProgramPatch
{
    [JsonPropertyName("appx")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Appx { get; set; }

    [JsonPropertyName("bundle")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Bundle { get; set; }

    [JsonPropertyName("installer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InstallerKind? Installer { get; set; }

    [JsonPropertyName("parent_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ParentKey { get; set; }

    [JsonPropertyName("product_code")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProductCode { get; set; }

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

    [JsonPropertyName("system_component")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? SystemComponent { get; set; }

    [JsonPropertyName("unnamed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Unnamed { get; set; }

}

/// <summary>
/// A program by id, with its display name.
/// </summary>
public sealed class ProgramRef
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

}

/// <summary>
/// One raw ARP row.
/// </summary>
public sealed class ProgramRow
{
    [JsonPropertyName("install_time")]
    public ulong? InstallTime { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

    [JsonPropertyName("publisher")]
    public string? Publisher { get; set; }

    [JsonPropertyName("scope")]
    public InstallScope Scope { get; set; } = default!;

    [JsonPropertyName("size_bytes")]
    public ulong? SizeBytes { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

}

/// <summary>
/// One size of a `size.ready`.
/// </summary>
public sealed class ProgramSize
{
    [JsonPropertyName("bytes")]
    public ulong? Bytes { get; set; }

    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

}

/// <summary>
/// `programs.batch`.
/// </summary>
public sealed class ProgramsBatch
{
    [JsonPropertyName("request")]
    public ulong Request { get; set; }

    [JsonPropertyName("rows")]
    public System.Collections.Generic.List<ProgramRow> Rows { get; set; } = new();

}

/// <summary>
/// `{program_ids[]}`: `programs.sizes`, `uninstall.prepare`, `leftovers.stored`.
/// </summary>
public sealed class ProgramsParams
{
    [JsonPropertyName("program_ids")]
    public System.Collections.Generic.List<string> ProgramIds { get; set; } = new();

}

/// <summary>
/// `programs.patch`.
/// </summary>
public sealed class ProgramsPatch
{
    [JsonPropertyName("patches")]
    public System.Collections.Generic.List<ProgramPatch> Patches { get; set; } = new();

    [JsonPropertyName("request")]
    public ulong Request { get; set; }

}

/// <summary>
/// Progress of a long request (`*.progress`).
/// </summary>
public sealed class Progress
{
    [JsonPropertyName("done")]
    public ulong Done { get; set; }

    [JsonPropertyName("phase")]
    public string Phase { get; set; } = "";

    [JsonPropertyName("program_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ProgramId { get; set; }

    [JsonPropertyName("request")]
    public ulong Request { get; set; }

    [JsonPropertyName("total")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ulong? Total { get; set; }

}

/// <summary>
/// `quarantine.purge {expiry_ids[]}`.
/// </summary>
public sealed class PurgeParams
{
    [JsonPropertyName("expiry_ids")]
    public System.Collections.Generic.List<string> ExpiryIds { get; set; } = new();

}

/// <summary>
/// `quarantine.purge`.
/// </summary>
public sealed class PurgeResult
{
    [JsonPropertyName("kept")]
    public uint Kept { get; set; }

    [JsonPropertyName("outcome")]
    public Outcome Outcome { get; set; } = default!;

    [JsonPropertyName("purged")]
    public uint Purged { get; set; }

}

/// <summary>
/// One reason `plan.create` refused a plan.
/// </summary>
public sealed class Refusal
{
    [JsonPropertyName("candidate_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CandidateId { get; set; }

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = "";

}

/// <summary>
/// What became of the restore point (§7.7). Serialised as an object tagged by `"kind"`.
/// </summary>
public sealed class RestorePointOutcome
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("sequence")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Sequence { get; set; }

    [JsonPropertyName("os_error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? OsError { get; set; }

}

/// <summary>
/// `uninstall.route`.
/// </summary>
public sealed class RouteInfo
{
    [JsonPropertyName("command")]
    public string Command { get; set; } = "";

    [JsonPropertyName("quiet_command")]
    public string? QuietCommand { get; set; }

    [JsonPropertyName("route")]
    public Route Route { get; set; } = default!;

    [JsonPropertyName("running")]
    public System.Collections.Generic.List<RunningProcess> Running { get; set; } = new();

    [JsonPropertyName("signer")]
    public string? Signer { get; set; }

}

/// <summary>
/// `uninstall.run {session_id, quiet}`.
/// </summary>
public sealed class RunParams
{
    [JsonPropertyName("quiet")]
    public bool Quiet { get; set; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

}

/// <summary>
/// `uninstall.run`.
/// </summary>
public sealed class RunResult
{
    [JsonPropertyName("exit_code")]
    public uint? ExitCode { get; set; }

    [JsonPropertyName("outcome")]
    public RunOutcome Outcome { get; set; } = default!;

    [JsonPropertyName("verify_gone")]
    public VerifyGone VerifyGone { get; set; } = default!;

}

/// <summary>
/// `uninstall.run_user {program_id, quiet}`.
/// </summary>
public sealed class RunUserParams
{
    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

    [JsonPropertyName("quiet")]
    public bool Quiet { get; set; }

}

/// <summary>
/// `uninstall.run_user`.
/// </summary>
public sealed class RunUserResult
{
    [JsonPropertyName("exit_code")]
    public uint? ExitCode { get; set; }

    [JsonPropertyName("outcome")]
    public RunOutcome Outcome { get; set; } = default!;

}

/// <summary>
/// A running process that matters for an uninstall.
/// </summary>
public sealed class RunningProcess
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("pid")]
    public uint Pid { get; set; }

}

/// <summary>
/// `leftovers.scan`.
/// </summary>
public sealed class ScanResult
{
    [JsonPropertyName("baseline_trust")]
    public BaselineTrust BaselineTrust { get; set; } = default!;

    [JsonPropertyName("counts")]
    public BandCounts Counts { get; set; } = default!;

    [JsonPropertyName("mode")]
    public ScanMode Mode { get; set; } = default!;

    [JsonPropertyName("scan_id")]
    public string ScanId { get; set; } = "";

    [JsonPropertyName("warnings")]
    public System.Collections.Generic.List<Warning> Warnings { get; set; } = new();

}

/// <summary>
/// `leftovers.scan` after an uninstall of this broker: `{session_id, forced?}`.
/// </summary>
public sealed class ScanSessionParams
{
    [JsonPropertyName("forced")]
    public bool Forced { get; set; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

}

/// <summary>
/// `leftovers.scan` of a program removed outside Purge, from its stored fingerprint: `{program_id}`.
/// </summary>
public sealed class ScanStoredParams
{
    [JsonPropertyName("program_id")]
    public string ProgramId { get; set; } = "";

}

/// <summary>
/// `{session}`: `history.get`, `journal.resume`, `journal.rollback`, `journal.retry_held`.
/// </summary>
public sealed class SessionParams
{
    [JsonPropertyName("session")]
    public string Session { get; set; } = "";

}

/// <summary>
/// One session in the index: enough for the history list and the expiry notice, without reading the
/// journal.
/// </summary>
public sealed class SessionSummary
{
    [JsonPropertyName("app")]
    public string App { get; set; } = "";

    [JsonPropertyName("backup_bytes")]
    public ulong BackupBytes { get; set; }

    [JsonPropertyName("counts")]
    public OutcomeCounts? Counts { get; set; }

    [JsonPropertyName("expires")]
    public Expiry Expires { get; set; } = default!;

    [JsonPropertyName("finished")]
    public ulong? Finished { get; set; }

    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("journal")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JournalMark? Journal { get; set; }

    [JsonPropertyName("owner")]
    public AppRef? Owner { get; set; }

    [JsonPropertyName("pending_reboot")]
    public bool PendingReboot { get; set; }

    [JsonPropertyName("plan_hash")]
    public string PlanHash { get; set; } = "";

    [JsonPropertyName("purged")]
    public System.Collections.Generic.List<RetentionClass> Purged { get; set; } = new();

    [JsonPropertyName("started")]
    public ulong Started { get; set; }

    [JsonPropertyName("state")]
    public SessionState State { get; set; } = default!;

    [JsonPropertyName("undone")]
    public uint Undone { get; set; }

    [JsonPropertyName("usage")]
    public System.Collections.Generic.List<VolumeUsage> Usage { get; set; } = new();

}

/// <summary>
/// `broker.shutdown`.
/// </summary>
public sealed class ShutdownResult
{
    [JsonPropertyName("exiting")]
    public bool Exiting { get; set; }

}

/// <summary>
/// `size.ready`.
/// </summary>
public sealed class SizeReady
{
    [JsonPropertyName("request")]
    public ulong Request { get; set; }

    [JsonPropertyName("sizes")]
    public System.Collections.Generic.List<ProgramSize> Sizes { get; set; } = new();

}

/// <summary>
/// Why an item was not acted on. Serialised as an object tagged by `"kind"`.
/// </summary>
public sealed class SkipReason
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("blocker")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Blocker? Blocker { get; set; }

}

/// <summary>
/// The result of a request whose data follows in notifications: how many items will follow.
/// </summary>
public sealed class Started
{
    [JsonPropertyName("count")]
    public uint Count { get; set; }

}

/// <summary>
/// `leftovers.stored`.
/// </summary>
public sealed class StoredResult
{
    [JsonPropertyName("stored")]
    public System.Collections.Generic.List<string> Stored { get; set; } = new();

}

/// <summary>
/// Why an inverse was not applied (§7.8). A conflict is reported, never forced. Serialised as an object
/// tagged by `"kind"`.
/// </summary>
public sealed class UndoConflict
{
    [JsonPropertyName("kind")]
    public string Kind { get; set; } = "";

    [JsonPropertyName("blocker")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Blocker? Blocker { get; set; }

}

/// <summary>
/// `undo.run {session, item_ids?}`.
/// </summary>
public sealed class UndoParams
{
    [JsonPropertyName("item_ids")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Collections.Generic.List<uint>? ItemIds { get; set; }

    [JsonPropertyName("session")]
    public string Session { get; set; } = "";

}

/// <summary>
/// `undo.run`.
/// </summary>
public sealed class UndoResult
{
    [JsonPropertyName("conflicts")]
    public System.Collections.Generic.List<ConflictRow> Conflicts { get; set; } = new();

    [JsonPropertyName("outcome")]
    public Outcome Outcome { get; set; } = default!;

}

/// <summary>
/// The verify-gone check that gates the Safe band (§4.4, §5.8.3).
/// Each part is `true` only when positively established; "could not tell" is `false`.
/// `passed` is stored for readers of the document, but it is never trusted on its own: reading a document
/// clears it unless all three parts hold, and consumers ask [`VerifyGone::is_passed`], which checks the
/// parts again. An inconsistent `{"arp_gone": false, …, "passed": true}` therefore cannot unlock the Safe
/// band.
/// </summary>
public sealed class VerifyGone
{
    [JsonPropertyName("arp_gone")]
    public bool ArpGone { get; set; }

    [JsonPropertyName("main_exes_gone")]
    public bool MainExesGone { get; set; }

    [JsonPropertyName("msi_unknown_all_ctx")]
    public bool MsiUnknownAllCtx { get; set; }

    [JsonPropertyName("passed")]
    public bool Passed { get; set; }

}

/// <summary>
/// Quarantine usage and cap of one volume.
/// </summary>
public sealed class VolumeCap
{
    [JsonPropertyName("cap")]
    public ulong Cap { get; set; }

    [JsonPropertyName("root")]
    public string Root { get; set; } = "";

    [JsonPropertyName("serial")]
    public ulong Serial { get; set; }

    [JsonPropertyName("used")]
    public ulong Used { get; set; }

}

/// <summary>
/// How many bytes a session holds on one volume. The size cap (§7.8) is per volume.
/// </summary>
public sealed class VolumeUsage
{
    [JsonPropertyName("bytes")]
    public ulong Bytes { get; set; }

    [JsonPropertyName("root")]
    public string Root { get; set; } = "";

    [JsonPropertyName("serial")]
    public ulong Serial { get; set; }

}

/// <summary>
/// A warning for the user. `code` is stable for the client to switch on; `message` is shown.
/// </summary>
public sealed class Warning
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = "";

    [JsonPropertyName("message")]
    public string Message { get; set; } = "";

}
