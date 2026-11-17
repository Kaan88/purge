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
    public const string FingerprintSchema = "purge.fp/0";
    public const string JournalSchema = "purge.cli.journal/1";

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
            var evidence = Array(c, "evidence").Select(ReadEvidence).ToList();
            var scanner = Str(c, "scanner");
            var scanners = new List<string> { scanner };
            foreach (var e in evidence)
                foreach (var (k, v) in e.Detail)
                    if (k == "scanner" && !scanners.Contains(v)) scanners.Add(v);
            var objectFp = c.TryGetProperty("object_fp", out var ofp) && ofp.ValueKind == JsonValueKind.Object ? ofp : default;
            var item = new LeftoverItem(
                Id: Str(c, "id"),
                Category: Str(c, "category"),
                TargetType: Str(target, "type"),
                Display: DescribeTarget(target),
                Action: Str(c, "action"),
                Band: band,
                Preselected: Bool(decision, "preselected"),
                Explanation: Str(decision, "explanation"),
                Scanner: scanner,
                SizeBytes: c.TryGetProperty("size_bytes", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt64() : null,
                Evidence: evidence.Count)
            {
                TargetJson = target.ValueKind == JsonValueKind.Object ? Indented(target) : "",
                Owner = c.TryGetProperty("owner", out var o) ? Str(o, "display_name") : "",
                Harm = Str(c, "harm"),
                Reversibility = Str(c, "reversibility"),
                Score = Int(decision, "score"),
                ChildCount = c.TryGetProperty("child_count", out var cc) && cc.ValueKind == JsonValueKind.Number ? cc.GetInt32() : null,
                Children = Array(c, "children").Count(),
                Blockers = Array(c, "blockers").Select(DescribeBlocker).ToList(),
                EvidenceList = evidence,
                Scanners = scanners,
                ObjectWhy = evidence.SelectMany(e => e.Detail).FirstOrDefault(kv => kv.Key == "why").Value ?? "",
                ObjectKind = Str(objectFp, "kind"),
            };
            items.Add(item with { Type = TypeOf(item) });
        }
        return new LeftoverPlan(planPath, Str(root, "plan_hash"), Str(root, "app"), Str(root, "mode"), programName, items, warnings)
        {
            PolicyVersion = Str(root, "policy_version"),
            Absorbed = Array(root, "absorbed").Count(),
        };
    }

    /// <summary>The sidecar of a plan file: <c>plan.json</c> → <c>plan.scan.json</c>, as the engine names it.</summary>
    public static string SidecarOf(string planPath) =>
        planPath.Length == 0 ? "" : Path.ChangeExtension(planPath, ".scan.json");

    /// <summary>
    /// The review group of an item: system objects by their target type, then the M1b scanners (MSI and Burn
    /// registrations, privacy traces, error reports), then COM and class registrations, then files or registry.
    /// </summary>
    public static LeftoverType TypeOf(LeftoverItem i)
    {
        switch (i.TargetType)
        {
            case "Service": return LeftoverType.Services;
            case "Task": return LeftoverType.Tasks;
            case "FirewallRule": return LeftoverType.FirewallRules;
            case "AppxPackage": return LeftoverType.AppxPackages;
        }
        var s = i.Scanner;
        if (s is "REG-ARP-MSI" or "SYS-BURNDEPS" or "FS-PKGCACHE" or "REG-INSTFOLDERS" or "REG-SHAREDDLLS")
            return LeftoverType.MsiBurn;
        if (s is "FS-WER" or "REG-DIAG") return LeftoverType.ErrorReports;
        if (s == "REG-PRIVACY" || i.Category == "Privacy") return LeftoverType.Privacy;
        if (s.StartsWith("COM-", StringComparison.Ordinal) || i.Category == "ShellCom") return LeftoverType.ComShell;
        if (s.StartsWith("CLS-", StringComparison.Ordinal) || i.Category == "Association") return LeftoverType.Associations;
        return i.IsFile ? LeftoverType.Files : LeftoverType.Registry;
    }

    /// <summary>A short, readable name for a review group.</summary>
    public static string Describe(LeftoverType t) => t switch
    {
        LeftoverType.Files => "Files & folders",
        LeftoverType.Registry => "Registry",
        LeftoverType.Associations => "File types & protocols",
        LeftoverType.ComShell => "COM & shell extensions",
        LeftoverType.Services => "Services",
        LeftoverType.Tasks => "Scheduled tasks",
        LeftoverType.FirewallRules => "Firewall rules",
        LeftoverType.MsiBurn => "Installer (MSI / Burn) records",
        LeftoverType.Privacy => "Privacy traces",
        LeftoverType.ErrorReports => "Error reports & diagnostics",
        LeftoverType.AppxPackages => "App packages",
        _ => t.ToString(),
    };

    /// <summary>
    /// Whether an engine warning says the scan did not see everything: a walk cut by its budget, keys, packages or
    /// services that could not be read, or rows whose owner is unknown.
    /// </summary>
    public static bool IsIncomplete(string warning) =>
        warning.Contains("did not read every", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("budget", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("could not be read", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("unreadable", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("incomplete", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("access denied", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("are unknown", StringComparison.OrdinalIgnoreCase)
        || warning.Contains("values-only", StringComparison.OrdinalIgnoreCase);

    private static LeftoverEvidence ReadEvidence(JsonElement e)
    {
        var detail = new List<KeyValuePair<string, string>>();
        if (e.TryGetProperty("detail", out var d) && d.ValueKind == JsonValueKind.Object)
            foreach (var p in d.EnumerateObject())
                detail.Add(new(p.Name, p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.GetRawText()));
        // A kind with a payload (InstallerManifest("Inno")) is written as an object; show it as Kind(payload).
        var kind = e.TryGetProperty("kind", out var k)
            ? k.ValueKind == JsonValueKind.Object
                ? string.Join(", ", k.EnumerateObject().Select(p => $"{p.Name}({p.Value.ToString()})"))
                : k.ToString()
            : "";
        return new LeftoverEvidence(kind, Str(e, "tier"), Int(e, "weight"), Str(e, "scope"), Str(e, "source"), detail);
    }

    /// <summary>A blocker as one line: its kind, then its fields (<c>DenyListed (rule task.registry-direct)</c>).</summary>
    public static string DescribeBlocker(JsonElement b)
    {
        if (b.ValueKind == JsonValueKind.String) return b.GetString() ?? "";
        if (b.ValueKind != JsonValueKind.Object) return b.GetRawText();
        var kind = Str(b, "kind");
        var fields = b.EnumerateObject().Where(p => p.Name != "kind")
            .Select(p => $"{p.Name} {(p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText())}")
            .ToList();
        return fields.Count == 0 ? kind : $"{kind} ({string.Join(", ", fields)})";
    }

    private static string Indented(JsonElement e)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions
               {
                   Indented = true,
                   Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
               }))
            e.WriteTo(w);
        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// The system objects a fingerprint (<c>purge.fp/0</c>) recorded as the app's, keyed like
    /// <see cref="ObjectKey"/>: services by name, tasks by path, firewall rules by id (all without regard to case).
    /// </summary>
    public static Dictionary<string, SystemObjectNote> ReadFingerprintObjects(string json)
    {
        var notes = new Dictionary<string, SystemObjectNote>(StringComparer.OrdinalIgnoreCase);
        using var doc = Parse(json, FingerprintSchema);
        if (!doc.RootElement.TryGetProperty("sys", out var sys) || sys.ValueKind != JsonValueKind.Object) return notes;
        foreach (var s in Array(sys, "services"))
        {
            var id = s.TryGetProperty("identity", out var i) ? i : default;
            var name = Str(id, "name");
            var image = Str(id, "image_path");
            notes[ObjectKey("Service", name)] = new SystemObjectNote(name, Str(s, "program"), Str(s, "why"),
                image.Length > 0 ? $"ImagePath {image}" : "");
        }
        foreach (var t in Array(sys, "tasks"))
        {
            var id = t.TryGetProperty("identity", out var i) ? i : default;
            var path = Str(id, "path");
            var actions = Array(id, "actions").Select(a =>
            {
                var kind = Str(a, "kind");
                var p = Str(a, "path");
                var args = Str(a, "arguments");
                return kind == "exec" ? $"runs {p}{(args.Length > 0 ? " " + args : "")}" : kind;
            });
            notes[ObjectKey("Task", path)] = new SystemObjectNote(path, Str(t, "program"), Str(t, "why"), string.Join("; ", actions));
        }
        foreach (var r in Array(sys, "firewall_rules"))
        {
            var id = r.TryGetProperty("identity", out var i) ? i : default;
            var rule = Str(id, "rule");
            notes[ObjectKey("FirewallRule", Str(id, "id"))] = new SystemObjectNote(RuleField(rule, "Name"), Str(r, "program"), Str(r, "why"),
                string.Join(", ", new[] { "Dir", "Action", "Protocol", "LPort", "Profile" }
                    .Select(f => (f, v: RuleField(rule, f))).Where(x => x.v.Length > 0).Select(x => $"{x.f}={x.v}")));
        }
        return notes;
    }

    /// <summary>The key of a system object in <see cref="ReadFingerprintObjects"/>.</summary>
    public static string ObjectKey(string targetType, string identity) => targetType + "|" + identity;

    /// <summary>The object key of an item's target, or null when it is not a service, task or firewall rule.</summary>
    public static string? ObjectKeyOf(LeftoverItem i)
    {
        if (i.TargetJson.Length == 0) return null;
        using var t = JsonDocument.Parse(i.TargetJson);
        return i.TargetType switch
        {
            "Service" => ObjectKey("Service", Str(t.RootElement, "name")),
            "Task" => ObjectKey("Task", Str(t.RootElement, "path")),
            "FirewallRule" => ObjectKey("FirewallRule", Str(t.RootElement, "id")),
            _ => null,
        };
    }

    /// <summary>Adds what the fingerprint recorded to every service, task and firewall-rule item of a plan.</summary>
    public static LeftoverPlan WithObjectNotes(LeftoverPlan plan, IReadOnlyDictionary<string, SystemObjectNote> notes)
    {
        if (notes.Count == 0) return plan;
        var items = plan.Items.Select(i => ObjectKeyOf(i) is { } key && notes.TryGetValue(key, out var note)
            ? i with { ObjectNote = note, ObjectWhy = i.ObjectWhy.Length > 0 ? i.ObjectWhy : note.Why }
            : i).ToList();
        return plan with { Items = items };
    }

    /// <summary>One field of a firewall rule string (<c>v2.33|Action=Allow|...|Name=X|</c>); empty when absent.</summary>
    public static string RuleField(string rule, string field)
    {
        foreach (var part in rule.Split('|'))
        {
            var eq = part.IndexOf('=');
            if (eq > 0 && part.AsSpan(0, eq).Equals(field, StringComparison.OrdinalIgnoreCase)) return part[(eq + 1)..];
        }
        return "";
    }

    /// <summary>The program id and the first name of a fingerprint (<c>purge.fp/0</c>), for the list of saved ones.</summary>
    public static (string ProgramId, string Name) ReadFingerprintHead(string json)
    {
        using var doc = Parse(json, FingerprintSchema);
        var root = doc.RootElement;
        var app = root.TryGetProperty("app", out var a) ? a : default;
        var id = app.ValueKind == JsonValueKind.String ? app.GetString() ?? "" : Str(app, "program_id");
        var name = app.ValueKind == JsonValueKind.Object ? Str(app, "display_name") : "";
        if (name.Length == 0 && root.TryGetProperty("identity", out var ident))
            name = Strings(ident, "names").FirstOrDefault() ?? "";
        return (id, name.Length > 0 ? name : id);
    }

    /// <summary>The journal of a session as <c>journal show</c> prints it (<c>purge.cli.journal/1</c>).</summary>
    public static JournalView ReadJournal(string json)
    {
        using var doc = Parse(json, JournalSchema);
        var root = doc.RootElement;
        var summary = new List<string>();
        if (root.TryGetProperty("counts", out var counts) && counts.ValueKind == JsonValueKind.Object)
            summary.Add("Counts: " + string.Join(", ", counts.EnumerateObject().Select(p => $"{p.Name} {p.Value}")));
        foreach (var name in new[] { "open_intents", "pending_reboot", "held_retry", "retries_in_flight", "needs_attention", "undo_in_progress" })
        {
            var ops = Array(root, name).Select(v => v.ToString()).ToList();
            if (ops.Count > 0) summary.Add($"{name.Replace('_', ' ')}: op {string.Join(", ", ops)}");
        }
        if (root.TryGetProperty("commit", out var commit) && commit.ValueKind != JsonValueKind.Null)
            summary.Add("Committed: " + commit.GetRawText());
        if (root.TryGetProperty("aborted", out var aborted) && aborted.ValueKind != JsonValueKind.Null)
            summary.Add("Aborted: " + aborted.GetRawText());
        var lines = Array(root, "ops").Select(o =>
        {
            var outcome = o.TryGetProperty("outcome", out var oc) && oc.ValueKind == JsonValueKind.Object
                ? Str(oc, "kind") is { Length: > 0 } k ? k : oc.GetRawText()
                : oc.ValueKind == JsonValueKind.String ? oc.GetString() ?? "" : "open";
            var note = Str(o, "undo_note");
            var target = o.TryGetProperty("target", out var t) ? DescribeTarget(t) : "";
            return $"op {Str(o, "op")} · {Str(o, "item")} · {outcome} · {target}{(note.Length > 0 ? " · undo: " + note : "")}";
        }).ToList();
        return new JournalView(Str(root, "session"), Bool(root, "finished"), Int(root, "records"), Long(root, "torn_tail") > 0,
            Str(root, "index_mark"), summary, lines, Indented(root));
    }

    /// <summary>A target as one line: its path or name, the value name in brackets, a segment after a colon.</summary>
    public static string DescribeTarget(JsonElement target)
    {
        if (target.ValueKind != JsonValueKind.Object) return "";
        var path = Str(target, "path");
        var name = Str(target, "name");
        var text = path.Length > 0 ? path : name.Length > 0 ? name : Str(target, "full_name");
        if (text.Length == 0) text = Str(target, "id"); // FirewallRule
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

    /// <summary>The first line of <c>--version</c> and whether the build is the sandbox dev build.</summary>
    public static (string Version, bool SandboxDev, bool CanExecute) ReadVersion(string stdout)
    {
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var version = lines.Length > 0 ? lines[0].Replace("purge-engine ", "", StringComparison.Ordinal) : "?";
        return (version, lines.Any(l => l.Contains("SANDBOX DEV BUILD", StringComparison.Ordinal)),
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
