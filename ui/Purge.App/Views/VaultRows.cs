using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>
/// Retention from ENGINE_PLAN.md §7.8: files wait 30 days, registry/service/task backups 180 days. When a batch
/// expires Purge offers to delete it and asks; nothing is deleted on its own.
/// </summary>
public static class Retention
{
    public const int FileDays = 30;
    public const int BackupDays = 180;
    /// <summary>Batches this close to expiry are called out.</summary>
    public const int WarnDays = 7;

    public static int DaysLeft(DateTimeOffset created, int keepDays, DateTimeOffset now) =>
        Math.Clamp(keepDays - (int)Math.Floor(Math.Max(0, (now - created).TotalDays)), 0, keepDays);
}

/// <summary>One drive's share of the quarantine (board 16).</summary>
public sealed partial class VaultVolume(QuarantineVolume v, long expiringBytes)
{
    public string Volume { get; } = v.Volume;
    public string UsedText { get; } = $"{ProgramRow.FormatSize(v.UsedBytes)} of {ProgramRow.FormatSize(v.CapBytes)} limit";
    public double Percent { get; } = v.CapBytes > 0 ? 100.0 * v.UsedBytes / v.CapBytes : 0;
    public string Note { get; } = v.Note
        ?? (expiringBytes > 0 ? $"Expiring soon: {ProgramRow.FormatSize(expiringBytes)}" : "Nothing expiring this week");
    public string Tip { get; } = $"{v.Volume} {Math.Round(v.CapBytes > 0 ? 100.0 * v.UsedBytes / v.CapBytes : 0)} % of its quarantine limit";
}

/// <summary>One cleanup's batch in the vault (board 16): what is held, and how long it can still be put back.</summary>
public sealed partial class VaultBatch
{
    public VaultBatch(QuarantineBatch b, DateTimeOffset now)
    {
        Source = b;
        Name = b.ProgramName;
        Initial = b.ProgramName.Length > 0 ? b.ProgramName[..1].ToUpperInvariant() : "?";
        TileBrush = ProgramRow.TileFor(b.Publisher.Length > 0 ? b.Publisher : b.ProgramName);
        var local = b.Created.ToLocalTime();
        When = local.Date == now.LocalDateTime.Date
            ? "Today " + local.ToString("HH:mm", CultureInfo.CurrentCulture)
            : local.ToString("d MMM HH:mm", CultureInfo.CurrentCulture);
        Volume = b.Volume;

        Held = b.State is not (BatchState.Restored or BatchState.KeptAll) && b.FileItems + b.RegistryItems > 0;
        FileDays = b.FileItems > 0 ? Retention.DaysLeft(b.Created, Retention.FileDays, now) : 0;
        BackupDays = b.RegistryItems > 0 ? Retention.DaysLeft(b.Created, Retention.BackupDays, now) : 0;
        var items = b.FileItems + b.RegistryItems;

        Summary = b.State switch
        {
            BatchState.Restored => "All put back",
            BatchState.KeptAll => "Kept by you · nothing moved",
            _ => $"{items} {(items == 1 ? "item" : "items")} · {ProgramRow.FormatSize(b.Bytes)} on {b.Volume}",
        };
        var parts = new List<string>();
        if (Held && b.FileItems > 0) parts.Add(FileDays > 0 ? $"Files restorable for {FileDays} more days" : "Files expired · waiting for you to decide");
        if (Held && b.RegistryItems > 0) parts.Add($"registry backups {BackupDays} days");
        if (b.UserDataItems > 0 && Held) parts.Add($"{b.UserDataItems} user data");
        Detail = string.Join(" · ", parts);

        Expired = Held && b.FileItems > 0 && FileDays == 0;
        Expiring = Held && b.FileItems > 0 && FileDays is > 0 and <= Retention.WarnDays;
        RingValue = Held && b.FileItems > 0 ? 100.0 * FileDays / Retention.FileDays : 0;
        DaysText = !Held ? "–" : b.FileItems > 0 ? FileDays.ToString(CultureInfo.CurrentCulture) : BackupDays.ToString(CultureInfo.CurrentCulture);
        DaysCaption = !Held ? "" : FileDays == 1 ? "day" : "days";
        State = Expired ? "Expired" : Expiring ? "Expiring" : b.State switch
        {
            BatchState.Partial => "Partly restored",
            BatchState.Restored => "Restored",
            BatchState.KeptAll => "Kept all",
            _ => "Restorable",
        };
    }

    public QuarantineBatch Source { get; }
    public string Name { get; }
    public string Initial { get; }
    public Brush TileBrush { get; }
    public string When { get; }
    public string Volume { get; }
    public string Summary { get; }
    public string Detail { get; }
    public string State { get; }
    public string DaysText { get; }
    public string DaysCaption { get; }
    public double RingValue { get; }
    public int FileDays { get; }
    public int BackupDays { get; }
    public bool Held { get; }
    public bool Expired { get; }
    public bool Expiring { get; }

    // One chip per state; each has its own glyph so the state never rests on colour (board 21).
    public Visibility OkVisibility => !Expired && !Expiring && Source.State == BatchState.Undoable && Held ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WarnVisibility => Expired || Expiring || Source.State == BatchState.Partial ? Visibility.Visible : Visibility.Collapsed;
    public Visibility NeutralVisibility => !Held ? Visibility.Visible : Visibility.Collapsed;
    public Visibility HeldVisibility => Held ? Visibility.Visible : Visibility.Collapsed;
    public string WarnGlyph => Expired ? "" : Expiring ? "" : "";
}
