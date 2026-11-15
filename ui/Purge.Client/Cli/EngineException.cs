namespace Purge.Client.Cli;

/// <summary>A <c>purge-engine</c> run that ended with an exit code the caller cannot use as a result.</summary>
public sealed class EngineException(int exitCode, string verb, string message, string stderr)
    : Exception(message)
{
    /// <summary>The process exit code (see <see cref="ExitCodes"/>); -1 when the engine could not be started.</summary>
    public int ExitCode { get; } = exitCode;

    /// <summary>The verb that ran, e.g. <c>exec</c>.</summary>
    public string Verb { get; } = verb;

    /// <summary>Everything the engine wrote to stderr.</summary>
    public string Stderr { get; } = stderr;

    /// <summary>An interrupted session must be resumed or rolled back first (exit code 8).</summary>
    public bool NeedsRecovery => ExitCode == ExitCodes.NeedsRecovery;
}

/// <summary>The exit codes of <c>purge-engine</c> (bins/purge-engine/src/cli.rs) and what to tell the user.</summary>
public static class ExitCodes
{
    public const int Ok = 0;
    public const int NotImplemented = 1;
    public const int Usage = 2;
    public const int Runtime = 3;
    public const int UninstallFailed = 4;
    public const int NeedsConsent = 5;
    public const int PlanRefused = 6;
    public const int NeedsElevation = 7;
    public const int NeedsRecovery = 8;
    public const int StoreIntegrity = 9;
    public const int Partial = 10;
    public const int UndoConflicts = 11;
    public const int NotInSandbox = 12;

    /// <summary>A sentence for the user; <paramref name="detail"/> is the engine's own error line, when there is one.</summary>
    public static string Describe(int code, string detail)
    {
        var text = code switch
        {
            NotImplemented => "This engine does not have that command yet.",
            Usage => "The engine refused the request.",
            Runtime => "The engine hit an error.",
            UninstallFailed => "The program's uninstaller failed, was cancelled or timed out.",
            NeedsConsent => "This engine build cannot remove anything. Use the sandbox dev build (purge-engine built with sandbox-dev).",
            PlanRefused => "The engine refused the plan (its hash, the selection or the confirmation did not match). Nothing was done; scan again.",
            NeedsElevation => "The engine needs administrator rights for this.",
            NeedsRecovery => "An earlier cleanup was interrupted. Resume it or roll it back first; nothing new was done.",
            StoreIntegrity => "Purge's quarantine store failed its integrity check. Nothing was done.",
            Partial => "Not every item ended as planned.",
            UndoConflicts => "Some items could not be put back.",
            NotInSandbox => "Refused: this sandbox dev build removes and restores only inside Sandboxie. Start Purge in a Sandboxie box. Nothing was done.",
            -1 => "The engine could not be started.",
            _ => $"The engine stopped with exit code {code}.",
        };
        return detail.Length > 0 ? $"{text} {detail}" : text;
    }

    /// <summary>The engine's own error lines (<c>purge-engine...: error: ...</c> and the like) from its stderr.</summary>
    public static string ErrorLines(string stderr)
    {
        var lines = stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains("error:", StringComparison.Ordinal) || l.StartsWith("purge-engine ", StringComparison.Ordinal))
            .Select(l => l.Replace("purge-engine: error: ", "", StringComparison.Ordinal))
            .ToList();
        return string.Join(" ", lines.TakeLast(3));
    }
}
