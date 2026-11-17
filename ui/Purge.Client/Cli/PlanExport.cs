using System.Text;
using Purge.Client.Model;

namespace Purge.Client.Cli;

/// <summary>
/// Writes a reviewed plan as files the engine CLI can run later: the plan and its sidecar exactly as the engine wrote
/// them (their hashes must not change), the fingerprint the scan used, the selection as <c>select.json</c>, and a
/// <c>README.txt</c> with the confirm hash and the <c>exec</c> command line. Nothing is run.
/// </summary>
public static class PlanExport
{
    public const string PlanFile = "plan.json";
    public const string SidecarFile = "plan.scan.json";
    public const string SelectFile = "select.json";
    public const string FingerprintFile = "fp.json";
    public const string ReadmeFile = "README.txt";

    /// <summary>
    /// Exports <paramref name="plan"/> with the ids in <paramref name="selectedIds"/> into <paramref name="directory"/>
    /// (created when missing). Ids that are not items of the plan, or that the user may not tick, are refused.
    /// </summary>
    public static PlanExportResult Write(LeftoverPlan plan, IReadOnlyCollection<string> selectedIds, string directory,
        string? planShow = null)
    {
        var known = plan.Items.ToDictionary(i => i.Id, StringComparer.Ordinal);
        foreach (var id in selectedIds)
        {
            if (!known.TryGetValue(id, out var item))
                throw new ArgumentException($"{id} is not an item of the plan", nameof(selectedIds));
            if (!item.Selectable)
                throw new ArgumentException($"{id} cannot be selected ({item.Band}, {item.Action})", nameof(selectedIds));
        }
        Directory.CreateDirectory(directory);
        File.Copy(plan.PlanPath, Path.Combine(directory, PlanFile), overwrite: true);
        File.Copy(plan.SidecarPath, Path.Combine(directory, SidecarFile), overwrite: true);
        var hasFp = plan.FingerprintPath.Length > 0 && File.Exists(plan.FingerprintPath);
        if (hasFp) File.Copy(plan.FingerprintPath, Path.Combine(directory, FingerprintFile), overwrite: true);
        var ids = selectedIds.OrderBy(i => i, StringComparer.Ordinal).ToList();
        File.WriteAllText(Path.Combine(directory, SelectFile), CliEngineClient.IdsJson(ids), new UTF8Encoding(false));
        var confirm = ConfirmHash.Confirm(plan.PlanHash, ids);
        var command = $"purge-engine exec --plan {PlanFile} --confirm {confirm} --select {SelectFile}"
                      + (hasFp ? $" --fp {FingerprintFile}" : "") + " -o report.json";
        File.WriteAllText(Path.Combine(directory, ReadmeFile), Readme(plan, ids, confirm, command, hasFp), new UTF8Encoding(false));
        if (planShow is not null) File.WriteAllText(Path.Combine(directory, "plan-show.txt"), planShow, new UTF8Encoding(false));
        return new PlanExportResult(directory, confirm, ids.Count, command);
    }

    private static string Readme(LeftoverPlan plan, List<string> ids, string confirm, string command, bool hasFp)
    {
        var b = new StringBuilder();
        b.AppendLine($"Purge plan export: {plan.ProgramName}");
        b.AppendLine($"Exported {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} by the Purge UI alpha (scan and review only).");
        b.AppendLine();
        b.AppendLine($"App id:       {plan.App}");
        b.AppendLine($"Scan mode:    {plan.Mode}");
        b.AppendLine($"Policy:       {plan.PolicyVersion}");
        b.AppendLine($"Plan hash:    {plan.PlanHash}");
        b.AppendLine($"Selected:     {ids.Count} of {plan.Items.Count} items");
        b.AppendLine($"Confirm hash: {confirm}");
        b.AppendLine();
        b.AppendLine("Files:");
        b.AppendLine($"  {PlanFile}       the plan (purge.plan/0), as the engine wrote it");
        b.AppendLine($"  {SidecarFile}  its sidecar (purge.scan/0)");
        b.AppendLine($"  {SelectFile}     the selected candidate ids");
        if (hasFp) b.AppendLine($"  {FingerprintFile}         the fingerprint the scan used (exec --fp; without it no service, task or firewall rule is deleted)");
        b.AppendLine();
        b.AppendLine("Nothing has been removed. To run this selection later, from this folder, with an engine build that has");
        b.AppendLine("the executor verbs (a rig-exec build, or the sandbox dev build inside Sandboxie) and as administrator:");
        b.AppendLine();
        b.AppendLine("  " + command);
        b.AppendLine();
        b.AppendLine("The engine checks the plan hash and the confirm hash again and refuses (exit code 6) if the plan or the");
        b.AppendLine("selection changed. A release engine refuses exec with exit code 5 until the M3 broker exists.");
        return b.ToString();
    }
}
