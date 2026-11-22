using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Purge.App.Views;

/// <summary>One drive's share of the quarantine against its real cap (board 16, design delta 4).</summary>
public sealed partial class VaultVolume(VaultVolumeModel v)
{
    public string Volume { get; } = v.Root;
    public string UsedText { get; } = v.UsedText;
    public double Percent { get; } = v.Percent;
    public string Note { get; } = v.Note;
    public string Tip { get; } = $"{v.Root} {Math.Round(v.Percent).ToString(CultureInfo.CurrentCulture)} % of its quarantine limit";
}

/// <summary>One cleanup that holds something (board 16): what is held, and how long it can still be put back.</summary>
public sealed partial class VaultBatch(VaultBatchModel model)
{
    public VaultBatchModel Model { get; } = model;
    public string Id => Model.Id;
    public string Name => Model.Name;
    public string Initial => Model.Name.Length > 0 && char.IsLetterOrDigit(Model.Name[0])
        ? char.ToUpperInvariant(Model.Name[0]).ToString() : "?";
    public Brush TileBrush { get; } = ProgramRow.TileFor(model.Name);
    public string When => Model.When;
    public string Summary => Model.Summary;
    public string Detail => Model.Detail;
    public string State => Model.State;
    public double RingValue => Model.RingPercent;
    public string DaysText => Model.DaysLeftShown.ToString(CultureInfo.CurrentCulture);
    public string DaysCaption => Model.DaysLeftShown == 1 ? "day" : "days";

    // One chip per state; each has its own glyph so the state never rests on colour (board 21).
    public Visibility OkVisibility => !Model.Expired && !Model.Expiring && !Model.Partial ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WarnVisibility => Model.Expired || Model.Expiring || Model.Partial ? Visibility.Visible : Visibility.Collapsed;
    public Visibility NeutralVisibility => Visibility.Collapsed;
    public Visibility HeldVisibility => Visibility.Visible;
    public string WarnGlyph => Model.Expired ? "" : Model.Expiring ? "" : "";
}
