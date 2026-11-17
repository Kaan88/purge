namespace Purge.Client.Model;

// UI-side shapes of the engine CLI's leftover documents (purge.scan/0, purge.exec/1, purge.undo/1,
// purge.cli.recover/1, purge.cli.recovered/1). Hand-read from JSON by Cli/EngineDocs.cs; only the fields the
// shell shows are kept.

/// <summary>The engine's rating of a leftover (purge-model <c>Band</c>).</summary>
public enum LeftoverBand { Safe, Likely, Weak, Blocked }

/// <summary>
/// What kind of thing a leftover is, for grouping and filtering in the review. Derived from the target type and the
/// scanner that found it (<see cref="Cli.EngineDocs.TypeOf"/>).
/// </summary>
public enum LeftoverType
{
    Files,
    Registry,
    Associations,
    ComShell,
    Services,
    Tasks,
    FirewallRules,
    MsiBurn,
    Privacy,
    ErrorReports,
    AppxPackages,
}

/// <summary>One piece of evidence of a candidate (purge-model <c>Evidence</c>).</summary>
public sealed record LeftoverEvidence(string Kind, string Tier, int Weight, string Scope, string Source,
    List<KeyValuePair<string, string>> Detail)
{
    /// <summary>A negative weight speaks against the app owning the item.</summary>
    public bool Negative => Weight < 0;
}

/// <summary>
/// What the fingerprint recorded about a service, task or firewall rule (<c>purge.fp/0</c> <c>sys</c>): its
/// readable name where it has one, the program it runs and why the harvest took it as the app's (<c>ObjectWhy</c>).
/// </summary>
public sealed record SystemObjectNote(string Name, string Program, string Why, string Details);

/// <summary>How a program is scanned for leftovers.</summary>
public enum ScanKind
{
    /// <summary>Record the program, run its quiet uninstaller, then scan (<c>--mode post</c>).</summary>
    UninstallThenScan,

    /// <summary>Record the program and scan without running an uninstaller (<c>--mode forced</c>): nothing is
    /// rated Safe or ticked for you.</summary>
    ScanOnly,

    /// <summary>Scan a saved fingerprint of a program that was removed outside Purge (<c>--mode external</c>).</summary>
    External,
}

/// <summary>One candidate of a scan, from the plan's sidecar (<c>purge.scan/0</c> <c>items[]</c>).</summary>
public sealed record LeftoverItem(
    string Id,
    string Category,
    string TargetType,
    string Display,
    string Action,
    LeftoverBand Band,
    bool Preselected,
    string Explanation,
    string Scanner,
    long? SizeBytes,
    int Evidence)
{
    /// <summary>
    /// Whether the user may tick it: not blocked, not report-only, and not a package removal (irreversible; this
    /// build never passes --allow-irreversible).
    /// </summary>
    public bool Selectable => Band != LeftoverBand.Blocked && Action is not ("ReportOnly" or "RemovePackage");

    /// <summary>A file or folder (quarantined), as opposed to a registry entry or a system object.</summary>
    public bool IsFile => TargetType == "Path";

    public bool IsRegistry => TargetType.StartsWith("Reg", StringComparison.Ordinal);

    public bool IsUserData => Category == "UserData";

    /// <summary>The group the review shows it in.</summary>
    public LeftoverType Type { get; init; }

    /// <summary>The target as the engine wrote it (indented JSON), for the details card.</summary>
    public string TargetJson { get; init; } = "";

    /// <summary>The app the engine attributed it to (display name).</summary>
    public string Owner { get; init; } = "";

    /// <summary>purge-model <c>Harm</c>: None, Low, Medium, High, Critical.</summary>
    public string Harm { get; init; } = "";

    /// <summary>purge-model <c>Reversibility</c>: Full, Partial, None.</summary>
    public string Reversibility { get; init; } = "";

    /// <summary>The policy's score S.</summary>
    public int Score { get; init; }

    /// <summary>Number of files or values inside, when counted.</summary>
    public int? ChildCount { get; init; }

    /// <summary>Candidates nested inside this one.</summary>
    public int Children { get; init; }

    /// <summary>The reasons against removing it, one line each (<c>Kind</c> with its fields).</summary>
    public List<string> Blockers { get; init; } = [];

    /// <summary>Every piece of evidence.</summary>
    public List<LeftoverEvidence> EvidenceList { get; init; } = [];

    /// <summary>Every scanner whose evidence went into it, the listing one first.</summary>
    public List<string> Scanners { get; init; } = [];

    /// <summary>Why the harvest took a system object as the app's (<c>ObjectWhy</c>, snake case), or empty.</summary>
    public string ObjectWhy { get; init; } = "";

    /// <summary>The kind of object digest the scan bound to it (<c>service</c>, <c>task</c>, <c>firewall_rule</c>), or empty.</summary>
    public string ObjectKind { get; init; } = "";

    /// <summary>What the fingerprint says about the object (name, program), when it is a service, task or rule.</summary>
    public SystemObjectNote? ObjectNote { get; init; }
}

/// <summary>A scanned plan: the files the engine wrote, its hash and its items.</summary>
public sealed record LeftoverPlan(
    string PlanPath,
    string PlanHash,
    string App,
    string Mode,
    string ProgramName,
    List<LeftoverItem> Items,
    List<string> Warnings)
{
    /// <summary>The fingerprint the scan started from (needed by <c>exec --fp</c> for system objects).</summary>
    public string FingerprintPath { get; init; } = "";

    /// <summary>The policy version that decided the items.</summary>
    public string PolicyVersion { get; init; } = "";

    /// <summary>Candidates a Safe parent absorbed (not listed on their own).</summary>
    public int Absorbed { get; init; }

    /// <summary>The sidecar the engine wrote next to the plan (<c>&lt;plan&gt;.scan.json</c>).</summary>
    public string SidecarPath => Cli.EngineDocs.SidecarOf(PlanPath);

    /// <summary>The warnings that say the scan did not see everything (budget cuts, unreadable keys or packages).</summary>
    public List<string> IncompleteWarnings => Warnings.Where(Cli.EngineDocs.IsIncomplete).ToList();
}

/// <summary>A saved fingerprint (<c>harvest</c> output) the review can scan again.</summary>
public sealed record SavedFingerprint(string Path, string ProgramId, string Name, DateTimeOffset Recorded);

/// <summary>What an export of a plan wrote (<see cref="Cli.PlanExport"/>).</summary>
public sealed record PlanExportResult(string Directory, string ConfirmHash, int Selected, string CommandLine);

/// <summary>The journal of one session as <c>journal show</c> prints it (<c>purge.cli.journal/1</c>).</summary>
public sealed record JournalView(string SessionId, bool Finished, int Records, bool TornTail, string IndexMark,
    List<string> Summary, List<string> Ops, string RawJson);

/// <summary>How one executed item ended (<c>purge.exec/1</c> <c>items[]</c>).</summary>
public sealed record ExecItemResult(string Id, string Display, string Outcome, string Detail)
{
    /// <summary>Done, or gone already, or a remove-if-empty that was not empty: nothing left to do.</summary>
    public bool Complete => Outcome is "Done" or "Vanished" || Detail == "NoLongerEmpty";
}

/// <summary>The report of one <c>exec</c> run.</summary>
public sealed record ExecResult(
    int ExitCode,
    string SessionId,
    string State,
    List<ExecItemResult> Items,
    int Done,
    int Vanished,
    int Skipped,
    int HeldRetry,
    int PendingReboot,
    int Failed,
    long BackupBytes,
    List<string> Warnings);

/// <summary>The report of one <c>undo</c>.</summary>
public sealed record UndoResult(
    int ExitCode,
    string SessionId,
    string State,
    int Restored,
    int AlreadyRestored,
    int NothingToUndo,
    int Conflicts,
    int Failed,
    List<string> Warnings);

/// <summary>A session that was interrupted and needs <c>journal resume</c> or <c>journal rollback</c>.</summary>
public sealed record PendingSession(string SessionId, string Kind, string App, string Detail);

/// <summary>What <c>journal resume</c> / <c>rollback</c> did, per session.</summary>
public sealed record RecoveryResult(int ExitCode, bool Rollback, List<string> Lines);

/// <summary>
/// What a running engine call reports: a step starting (<paramref name="IsStep"/>; <paramref name="Text"/> is its name,
/// such as "Scanning for leftovers") or one line the engine printed on stderr.
/// </summary>
public sealed record EngineProgress(string Text, bool IsStep)
{
    public static EngineProgress Step(string name) => new(name, true);
    public static EngineProgress Line(string text) => new(text, false);
}
