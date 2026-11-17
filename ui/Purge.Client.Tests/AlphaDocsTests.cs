using Purge.Client.Cli;
using Purge.Client.Model;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The M1b scan documents as the UI alpha reads them. firefox-* and rustdesk-* are real output of read-only
/// <c>harvest</c> and <c>scan --mode forced</c> runs of the m1b engine on the dev host (user paths and SIDs
/// replaced); firefox-plan.scan.json keeps one item per (target type, scanner, band), so its plan hash no longer
/// covers its items. synthetic-journal.json is hand-written in the shape of <c>journal show</c>.
/// </summary>
public sealed class AlphaDocsTests
{
    private static string Sample(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", name));

    private static LeftoverPlan Firefox() =>
        EngineDocs.ReadScan(Sample("firefox-plan.scan.json"), @"C:\w\plan.json", "Mozilla Firefox", []);

    [Fact]
    public void SystemObjectsAreTypedAndCarryTheirWhy()
    {
        var plan = Firefox();
        Assert.Equal("forced", plan.Mode);
        Assert.Equal("m1b.1", plan.PolicyVersion);
        var task = plan.Items.Single(i => i.TargetType == "Task");
        Assert.Equal(LeftoverType.Tasks, task.Type);
        Assert.Equal("program_in_root", task.ObjectWhy);
        Assert.Equal("task", task.ObjectKind);
        Assert.Equal("DeleteKey", task.Action);
        Assert.Equal("Startup", task.Category);
        Assert.Equal(LeftoverBand.Likely, task.Band);
        Assert.False(task.Preselected);
        Assert.True(task.Selectable);
        Assert.Contains("Firefox Default Browser Agent", task.Display);
        var ev = Assert.Single(task.EvidenceList);
        Assert.Equal("OwnedSystemObject", ev.Kind);
        Assert.Equal("B", ev.Tier);
        Assert.Equal(8, ev.Weight);
        Assert.Contains(ev.Detail, kv => kv.Key == "recorded_at_harvest" && kv.Value == "true");

        var rules = plan.Items.Where(i => i.TargetType == "FirewallRule").ToList();
        Assert.Equal(2, rules.Count);
        Assert.All(rules, r => Assert.Equal(LeftoverType.FirewallRules, r.Type));
        Assert.All(rules, r => Assert.Equal("firewall_rule", r.ObjectKind));
    }

    [Fact]
    public void FilesRegistryAndAssociationsAreGroupedByScanner()
    {
        var plan = Firefox();
        Assert.Equal(17, plan.Items.Count);
        var byType = plan.Items.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(6, byType[LeftoverType.Files]);
        Assert.Equal(3, byType[LeftoverType.Associations]);
        Assert.Equal(5, byType[LeftoverType.Registry]);

        var install = plan.Items.Single(i => i.Id == "c-de68c3487f6e1384");
        Assert.Equal(LeftoverBand.Blocked, install.Band);
        Assert.False(install.Selectable);
        Assert.Equal(378242135, install.SizeBytes);
        Assert.Equal(81, install.ChildCount);
        Assert.Equal(["NotGone", "UnmatchedChildren (n 81)", "UserData"], install.Blockers);
        Assert.Equal("Low", install.Harm);
        Assert.Equal("Full", install.Reversibility);
        Assert.Equal(9, install.Score);
        Assert.Equal("Mozilla Firefox (x64 en-US)", install.Owner);
        Assert.Contains("\"type\": \"Path\"", install.TargetJson);

        var denied = plan.Items.Single(i => i.Id == "c-00d344be872ac14e");
        Assert.Equal(["DenyListed (rule task.registry-direct)"], denied.Blockers);
        Assert.Equal(LeftoverType.Registry, denied.Type);

        var profile = plan.Items.Single(i => i.Scanner == "FS-APPDATA");
        Assert.True(profile.IsUserData);
        Assert.Equal(LeftoverBand.Likely, profile.Band);
    }

    [Fact]
    public void FingerprintNotesNameTheObjects()
    {
        var notes = EngineDocs.ReadFingerprintObjects(Sample("firefox-fp.json"));
        Assert.Equal(3, notes.Count);
        var plan = EngineDocs.WithObjectNotes(Firefox(), notes);
        var rule = plan.Items.First(i => i.TargetType == "FirewallRule");
        Assert.NotNull(rule.ObjectNote);
        Assert.Equal(@"Firefox (C:\Program Files\Mozilla Firefox)", rule.ObjectNote!.Name);
        Assert.EndsWith(@"Mozilla Firefox\firefox.exe", rule.ObjectNote.Program);
        Assert.Contains("Dir=In", rule.ObjectNote.Details);
        var task = plan.Items.Single(i => i.TargetType == "Task");
        Assert.Contains("default-browser-agent.exe", task.ObjectNote!.Details);
        Assert.Equal("program_in_root", task.ObjectNote.Why);
        Assert.Null(plan.Items.Single(i => i.Id == "c-de68c3487f6e1384").ObjectNote);

        var (id, name) = EngineDocs.ReadFingerprintHead(Sample("firefox-fp.json"));
        Assert.Equal("HKLM|64|Mozilla Firefox", id);
        Assert.Equal("Mozilla Firefox (x64 en-US)", name);
    }

    [Fact]
    public void WarningsOfARealScanAreSortedIntoIncomplete()
    {
        var lines = Sample("rustdesk-scan.stderr.txt").Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l["warning:".Length..].Trim()).ToList();
        var plan = EngineDocs.ReadScan(Sample("rustdesk-plan.scan.json"), "p.json", "RustDesk", lines);
        Assert.Equal(19, plan.Items.Count);
        Assert.Equal("076411510144b9e1a8c3c5824b2c75626d93052d5b825e1da13c65332ef2d356", plan.PlanHash);
        var incomplete = plan.IncompleteWarnings;
        Assert.Contains(incomplete, w => w.Contains("reference walk did not read every key"));
        Assert.Contains(incomplete, w => w.Contains("could not be read"));
        Assert.Contains(incomplete, w => w.Contains("values-only"));
        Assert.DoesNotContain(incomplete, w => w.Contains("reparse point not traversed"));
        Assert.Equal(2, plan.Items.Count(i => i.Type == LeftoverType.FirewallRules));
    }

    [Fact]
    public void RuleFieldsAreReadByName()
    {
        const string rule = "v2.33|Action=Allow|Active=TRUE|Dir=Out|App=C:\\x.exe|Name=RustDesk Service|";
        Assert.Equal("RustDesk Service", EngineDocs.RuleField(rule, "Name"));
        Assert.Equal("Out", EngineDocs.RuleField(rule, "dir"));
        Assert.Equal("", EngineDocs.RuleField(rule, "LPort"));
    }

    [Fact]
    public void ExportWritesWhatExecReads()
    {
        var dir = Path.Combine(Path.GetTempPath(), "purge-alpha-export-" + Guid.NewGuid().ToString("N"));
        var src = Path.Combine(dir, "src");
        Directory.CreateDirectory(src);
        try
        {
            var planPath = Path.Combine(src, "plan.json");
            File.WriteAllText(planPath, "{\"schema\":\"purge.plan/0\"}");
            File.WriteAllText(EngineDocs.SidecarOf(planPath), Sample("rustdesk-plan.scan.json"));
            var fp = Path.Combine(src, "x.fp.json");
            File.WriteAllText(fp, Sample("firefox-fp.json"));
            var plan = EngineDocs.ReadScan(Sample("rustdesk-plan.scan.json"), planPath, "RustDesk", []) with { FingerprintPath = fp };
            var chosen = plan.Items.Where(i => i.Selectable).Take(2).Select(i => i.Id).Reverse().ToList();
            var outDir = Path.Combine(dir, "out");
            var result = PlanExport.Write(plan, chosen, outDir, "plan show text");

            Assert.Equal(ConfirmHash.Confirm(plan.PlanHash, chosen), result.ConfirmHash);
            Assert.Equal(2, result.Selected);
            Assert.Equal(File.ReadAllText(planPath), File.ReadAllText(Path.Combine(outDir, "plan.json")));
            Assert.Equal(Sample("rustdesk-plan.scan.json"), File.ReadAllText(Path.Combine(outDir, "plan.scan.json")));
            Assert.True(File.Exists(Path.Combine(outDir, "fp.json")));
            Assert.Equal(CliEngineClient.IdsJson(chosen.OrderBy(i => i, StringComparer.Ordinal)),
                File.ReadAllText(Path.Combine(outDir, "select.json")));
            Assert.Contains("--fp fp.json", result.CommandLine);
            Assert.Contains(result.ConfirmHash, File.ReadAllText(Path.Combine(outDir, "README.txt")));
            Assert.Equal("plan show text", File.ReadAllText(Path.Combine(outDir, "plan-show.txt")));

            var blocked = plan.Items.First(i => !i.Selectable).Id;
            Assert.Throws<ArgumentException>(() => PlanExport.Write(plan, [blocked], outDir));
            Assert.Throws<ArgumentException>(() => PlanExport.Write(plan, ["c-nope"], outDir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void JournalShowReadsBack()
    {
        var j = EngineDocs.ReadJournal(Sample("synthetic-journal.json"));
        Assert.Equal("20261117-101500-ab12", j.SessionId);
        Assert.True(j.Finished);
        Assert.Equal(7, j.Records);
        Assert.False(j.TornTail);
        Assert.Equal("matches", j.IndexMark);
        Assert.Contains(j.Summary, s => s.StartsWith("Counts: done 1"));
        Assert.Contains(j.Summary, s => s == "needs attention: op 2");
        Assert.Equal(2, j.Ops.Count);
        Assert.Contains(@"C:\work\app", j.Ops[0]);
        Assert.Contains("undo: created again", j.Ops[1]);
        Assert.Contains("Service: RigSvc", j.Ops[1]);
        Assert.Throws<InvalidDataException>(() => EngineDocs.ReadJournal(Sample("rig-undo.json")));
    }

    [Fact]
    public void TypeOfMapsTheM1bScanners()
    {
        static LeftoverItem Item(string type, string scanner, string category = "Registration") =>
            new("c", category, type, "", "DeleteKey", LeftoverBand.Likely, false, "", scanner, null, 0);
        Assert.Equal(LeftoverType.Services, EngineDocs.TypeOf(Item("Service", "SYS-SERVICE")));
        Assert.Equal(LeftoverType.AppxPackages, EngineDocs.TypeOf(Item("AppxPackage", "SYS-APPX")));
        Assert.Equal(LeftoverType.MsiBurn, EngineDocs.TypeOf(Item("RegKey", "REG-ARP-MSI")));
        Assert.Equal(LeftoverType.MsiBurn, EngineDocs.TypeOf(Item("Path", "FS-PKGCACHE")));
        Assert.Equal(LeftoverType.MsiBurn, EngineDocs.TypeOf(Item("RegKey", "SYS-BURNDEPS")));
        Assert.Equal(LeftoverType.Privacy, EngineDocs.TypeOf(Item("RegValue", "REG-PRIVACY", "Privacy")));
        Assert.Equal(LeftoverType.ErrorReports, EngineDocs.TypeOf(Item("Path", "FS-WER")));
        Assert.Equal(LeftoverType.ErrorReports, EngineDocs.TypeOf(Item("RegKey", "REG-DIAG")));
        Assert.Equal(LeftoverType.ComShell, EngineDocs.TypeOf(Item("RegKey", "COM-SHELLEX")));
        Assert.Equal(LeftoverType.Associations, EngineDocs.TypeOf(Item("RegKey", "CLS-PROGID")));
        Assert.Equal(LeftoverType.Files, EngineDocs.TypeOf(Item("Path", "FS-APPDATA")));
        Assert.Equal(LeftoverType.Registry, EngineDocs.TypeOf(Item("RegValue", "REF-ANY")));
    }
}
