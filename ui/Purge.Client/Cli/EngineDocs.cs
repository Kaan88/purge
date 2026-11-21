using System.Globalization;
using System.Text.Json;
using Purge.Client.Model;

namespace Purge.Client.Cli;

/// <summary>
/// Reads the engine CLI's documents into the client's model. Hand-written over <see cref="JsonDocument"/> (no
/// reflection, so it stays Native AOT safe) and lenient: a missing optional field reads as empty, a wrong schema
/// is an <see cref="InvalidDataException"/>.
/// </summary>
public static class EngineDocs
{
    public const string ScanSchema = "purge.scan/0";
    public const string ExecSchema = "purge.exec/1";
    public const string UndoSchema = "purge.undo/1";
    public const string RecoverSchema = "purge.cli.recover/1";
    public const string RecoveredSchema = "purge.cli.recovered/1";
    public const string IndexSchema = "purge.sessions/1";

    /// <summary>A plan's sidecar (<c>&lt;plan&gt;.scan.json</c>, <c>purge.scan/0</c>).</summary>
    public static LeftoverPlan ReadScan(string json, string planPath, string programName, List<string> warnings)
    {
        using var doc = Parse(json, ScanSchema);
        var root = doc.RootElement;
        var items = new List<LeftoverItem>();
        foreach (var c in Array(root, "items"))
        {
            var target = c.TryGetProperty("target", out var t) ? t : default;
            var decision = c.TryGetProperty("decision", out var d) && d.ValueKind == JsonValueKind.Object ? d : default;
            var band = Str(decision, "band") switch
            {
                "Safe" => LeftoverBand.Safe,
                "Likely" => LeftoverBand.Likely,
                "Blocked" => LeftoverBand.Blocked,
                _ => LeftoverBand.Weak,
            };
            items.Add(new LeftoverItem(
                Id: Str(c, "id"),
                Category: Str(c, "category"),
                TargetType: Str(target, "type"),
                Display: DescribeTarget(target),
                Action: Str(c, "action"),
                Band: band,
                Preselected: Bool(decision, "preselected"),
                Explanation: Str(decision, "explanation"),
                Scanner: Str(c, "scanner"),
                SizeBytes: c.TryGetProperty("size_bytes", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt64() : null,
                Evidence: Array(c, "evidence").Count()));
        }
        return new LeftoverPlan(planPath, Str(root, "plan_hash"), Str(root, "app"), Str(root, "mode"), programName, items, warnings);
    }

    /// <summary>A target as one line: its path or name, the value name in brackets, a segment after a colon.</summary>
    public static string DescribeTarget(JsonElement target)
    {
        if (target.ValueKind != JsonValueKind.Object) return "";
        var path = Str(target, "path");
        var name = Str(target, "name");
        var text = path.Length > 0 ? path : name.Length > 0 ? name : Str(target, "full_name");
        if (path.Length > 0 && target.TryGetProperty("name", out _))
            text += name.Length > 0 ? $" [{name}]" : " [(default)]";
        var segment = Str(target, "segment");
        if (segment.Length > 0) text += $" : {segment}";
        if (text.Length == 0) text = target.GetRawText();
        var type = Str(target, "type");
        return type is "Path" or "RegKey" or "RegValue" || type.Length == 0 ? text : $"{type}: {text}";
    }

    /// <summary>The report of <c>exec</c> (<c>purge.exec/1</c>), as printed on stdout.</summary>
    public static ExecResult ReadExec(string json, int exitCode)
    {
        using var doc = Parse(json, ExecSchema);
        var root = doc.RootElement;
        var items = Array(root, "items").Select(i =>
        {
            var outcome = i.TryGetProperty("outcome", out var o) ? o : default;
            var detail = Str(outcome, "reason");
            if (detail.Length == 0) detail = Str(outcome, "code");
            var extra = Str(outcome, "detail");
            if (extra.Length > 0) detail = detail.Length > 0 ? $"{detail}: {extra}" : extra;
            return new ExecItemResult(Str(i, "item"), DescribeTarget(i.TryGetProperty("target", out var t) ? t : default),
                Str(outcome, "kind"), detail);
        }).ToList();
        var counts = root.TryGetProperty("counts", out var c) ? c : default;
        return new ExecResult(exitCode, Str(root, "session"), Str(root, "state"), items,
            Int(counts, "done"), Int(counts, "vanished"), Int(counts, "skipped"), Int(counts, "held_retry"),
            Int(counts, "pending_reboot"), Int(counts, "failed"), Long(root, "backup_bytes"), Strings(root, "warnings"));
    }

    /// <summary>The report of <c>undo</c> (<c>purge.undo/1</c>).</summary>
    public static UndoResult ReadUndo(string json, int exitCode)
    {
        using var doc = Parse(json, UndoSchema);
        var root = doc.RootElement;
        var counts = root.TryGetProperty("counts", out var c) ? c : default;
        return new UndoResult(exitCode, Str(root, "session"), Str(root, "state"), Int(counts, "restored"),
            Int(counts, "already_restored"), Int(counts, "nothing_to_undo"), Int(counts, "conflicts"),
            Int(counts, "failed"), Strings(root, "warnings"));
    }

    /// <summary>The sessions <c>journal recover</c> lists (<c>purge.cli.recover/1</c>).</summary>
    public static List<PendingSession> ReadRecover(string json)
    {
        using var doc = Parse(json, RecoverSchema);
        return Array(doc.RootElement, "sessions")
            .Select(s => new PendingSession(Str(s, "session"), Str(s, "kind"), Str(s, "app"), Str(s, "detail")))
            .ToList();
    }

    /// <summary>What <c>journal resume</c> / <c>rollback</c> printed (<c>purge.cli.recovered/1</c>), one line per session.</summary>
    public static RecoveryResult ReadRecovered(string json, int exitCode)
    {
        using var doc = Parse(json, RecoveredSchema);
        var root = doc.RootElement;
        var lines = Array(root, "sessions").Select(s =>
        {
            var error = Str(s, "error");
            if (error.Length > 0) return $"{Str(s, "session")}: {error}";
            var state = s.TryGetProperty("state", out var st) && st.ValueKind == JsonValueKind.String ? st.GetString() : "directory removed";
            return $"{Str(s, "session")}: {state}, {Array(s, "settled").Count()} settled, {Array(s, "undone").Count()} undone";
        }).ToList();
        return new RecoveryResult(exitCode, Str(root, "mode") == "rollback", lines);
    }

    /// <summary>
    /// The store's session index (<c>sessions\index.json</c>, <c>purge.sessions/1</c>) as vault batches, with the
    /// per-session item kinds from each session's <c>report.json</c> when <paramref name="readReport"/> finds one.
    /// </summary>
    public static QuarantineStatus ReadIndex(string json, Func<string, string?> readReport, Func<string, long?> volumeSize)
    {
        using var doc = Parse(json, IndexSchema, allowEmpty: true);
        var batches = new List<QuarantineBatch>();
        var used = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in Array(doc.RootElement, "sessions"))
        {
            var id = Str(s, "id");
            var owner = s.TryGetProperty("owner", out var o) && o.ValueKind == JsonValueKind.Object ? Str(o, "display_name") : "";
            var counts = s.TryGetProperty("counts", out var c) ? c : default;
            int files = 0, registry = 0, userData = 0;
            var report = readReport(id);
            if (report is not null)
            {
                try
                {
                    using var r = JsonDocument.Parse(report);
                    foreach (var item in Array(r.RootElement, "items"))
                    {
                        var outcome = item.TryGetProperty("outcome", out var oc) ? Str(oc, "kind") : "";
                        if (outcome != "Done") continue;
                        var type = item.TryGetProperty("target", out var t) ? Str(t, "type") : "";
                        if (type == "Path") files++;
                        else registry++;
                    }
                }
                catch (JsonException) { report = null; }
            }
            if (report is null) files = Int(counts, "done");
            var volumes = Array(s, "usage").ToList();
            foreach (var u in volumes)
            {
                var root = Str(u, "root");
                used[root] = used.GetValueOrDefault(root) + Long(u, "bytes");
            }
            var state = Str(s, "state") switch
            {
                "Undone" => BatchState.Restored,
                "PartiallyUndone" => BatchState.Partial,
                _ when Int(counts, "done") == 0 => BatchState.KeptAll,
                _ => BatchState.Undoable,
            };
            batches.Add(new QuarantineBatch(
                SessionId: id,
                ProgramName: owner.Length > 0 ? owner : Str(s, "app"),
                Publisher: "",
                Created: FromFileTime(Long(s, "started")),
                Volume: volumes.Count > 0 ? Str(volumes[0], "root") : "",
                FileItems: files,
                RegistryItems: registry,
                Bytes: Long(s, "backup_bytes"),
                State: state,
                UserDataItems: userData));
        }
        var vols = used.Select(kv =>
        {
            const long tenGiB = 10L << 30;
            var cap = volumeSize(kv.Key) is { } total ? Math.Min(tenGiB, total / 20) : tenGiB;
            return new QuarantineVolume(kv.Key, kv.Value, cap, null);
        }).ToList();
        return new QuarantineStatus(vols, batches);
    }

    /// <summary>The first line of <c>--version</c> and whether the build can execute (rig-exec).</summary>
    public static (string Version, bool CanExecute) ReadVersion(string stdout)
    {
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var version = lines.Length > 0 ? lines[0].Replace("purge-engine ", "", StringComparison.Ordinal) : "?";
        return (version,
            lines.Any(l => l.StartsWith("rig-exec build", StringComparison.Ordinal)));
    }

    private static DateTimeOffset FromFileTime(long ticks)
    {
        try { return DateTimeOffset.FromFileTime(ticks); }
        catch (ArgumentOutOfRangeException) { return DateTimeOffset.MinValue; }
    }

    private static JsonDocument Parse(string json, string schema, bool allowEmpty = false)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException e) { throw new InvalidDataException($"the engine's {schema} document is not JSON: {e.Message}", e); }
        var found = Str(doc.RootElement, "schema");
        if (found != schema && !(allowEmpty && found.Length == 0))
        {
            doc.Dispose();
            throw new InvalidDataException($"expected a {schema} document, got {(found.Length > 0 ? found : "no schema")}");
        }
        return doc;
    }

    private static IEnumerable<JsonElement> Array(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray()
            : [];

    private static string Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind switch
            {
                JsonValueKind.String => v.GetString() ?? "",
                JsonValueKind.Number => v.GetRawText(),
                _ => "",
            }
            : "";

    private static bool Bool(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static long Long(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
            && v.TryGetInt64(out var n) ? n : 0;

    private static int Int(JsonElement e, string name) => (int)Math.Clamp(Long(e, name), int.MinValue, int.MaxValue);

    private static List<string> Strings(JsonElement e, string name) =>
        Array(e, name).Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString() ?? "").ToList();

    internal static string Plural(int n, string one, string many) =>
        $"{n.ToString(CultureInfo.InvariantCulture)} {(n == 1 ? one : many)}";
}
