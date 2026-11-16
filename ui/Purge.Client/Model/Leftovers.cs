namespace Purge.Client.Model;

// UI-side shapes of the engine CLI's leftover documents (purge.scan/0, purge.exec/1, purge.undo/1,
// purge.cli.recover/1, purge.cli.recovered/1). Hand-read from JSON by Cli/EngineDocs.cs; only the fields the
// shell shows are kept.

/// <summary>The engine's rating of a leftover (purge-model <c>Band</c>).</summary>
public enum LeftoverBand { Safe, Likely, Weak, Blocked }

/// <summary>How a program is scanned for leftovers.</summary>
public enum ScanKind
{
    /// <summary>Record the program, run its quiet uninstaller, then scan (<c>--mode post</c>).</summary>
    UninstallThenScan,

    /// <summary>Record the program and scan without running an uninstaller (<c>--mode forced</c>): nothing is
    /// rated Safe or ticked for you.</summary>
    ScanOnly,
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
}

/// <summary>A scanned plan: the files the engine wrote, its hash and its items.</summary>
public sealed record LeftoverPlan(
    string PlanPath,
    string PlanHash,
    string App,
    string Mode,
    string ProgramName,
    List<LeftoverItem> Items,
    List<string> Warnings);

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
