using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Purge.Client.Rpc;

namespace Purge.App.Views;

/// <summary>One line of evidence in the detail pane. ● explicit, ◐ corroborating, ○ note, ⚠ warning.</summary>
public sealed class EvidenceLine(string glyph, Brush glyphBrush, string text)
{
    public string Glyph { get; } = glyph;
    public Brush GlyphBrush { get; } = glyphBrush;
    public string Text { get; } = text;
}

/// <summary>
/// A row of the flattened, virtualized Leftovers list (design 9.4): a group header or a candidate.
/// The state lives in <see cref="LeftoversViewModel"/>; this is only what the DataTemplate binds.
/// </summary>
public sealed partial class LeftoversRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private LeftoversRow(LeftoverGroup group)
    {
        Group = group;
    }

    private LeftoversRow(LeftoverItemModel item)
    {
        Item = item;
    }

    public static LeftoversRow ForGroup(LeftoverGroup group) => new(group);

    public static LeftoversRow ForItem(LeftoverItemModel item) => new(item);

    public LeftoverGroup? Group { get; }
    public LeftoverItemModel? Item { get; }
    public bool IsGroup => Group is not null;
    public bool IsSection => Group?.IsSection == true;
    public string GroupName => Group?.Name ?? Item?.GroupName ?? "";
    public LeftoverItemModel? Model => Item;

    // ---- Group header -------------------------------------------------------------------------

    public string CountText => Group is null ? "" : Group.Items.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);

    public bool? GroupChecked
    {
        get
        {
            if (Group is null || !Group.CanTick) return false;
            var selectable = Group.Items.Where(i => i.Selectable).ToList();
            if (selectable.Count == 0) return false;
            if (selectable.All(i => i.Checked)) return true;
            return selectable.Any(i => i.Checked) ? null : false;
        }
    }

    public double GroupBarWidth => Group is null || Group.Items.Count == 0
        ? 0
        : 120.0 * Group.Items.Count(i => i.Checked) / Group.Items.Count;

    public string GroupBarTip => Group is null
        ? ""
        : $"{Group.Items.Count(i => i.Checked)} of {Group.Items.Count} selected";

    public string GroupSizeText => Group is null
        ? ""
        : Group.Bytes > 0
            ? LeftoverItemModel.FormatSize(Group.Bytes)
            : $"{Group.Items.Count(i => i.Checked)} of {Group.Items.Count}";

    public string Chevron => Group?.Expanded == false ? "\uE76C" : "\uE70D";

    public Visibility GroupTickVisibility => Group?.CanTick == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility GroupVisibility => IsGroup ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ItemVisibility => IsGroup ? Visibility.Collapsed : Visibility.Visible;

    // ---- Candidate ----------------------------------------------------------------------------

    public string DisplayName => Item?.DisplayName ?? "";
    public string Why => Item?.Why ?? "";
    public string SizeText => Item?.SizeText ?? "";
    public string OwnerText => Item?.OwnerProgram is { Length: > 0 } owner ? "Shared with " + owner : "";
    public double PathOpacity => Item?.IsProtected == true ? 0.6 : 1.0;

    public bool Checked
    {
        get => Item?.Checked == true;
        set
        {
            if (Item is null || Item.Checked == value) return;
            Item.Checked = value;
            Raise(nameof(Checked));
        }
    }

    public Visibility CheckVisibility => Item?.Selectable == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LockVisibility => Item?.IsProtected == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility SafeVisibility => Item?.Band == Band.Safe ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LikelyVisibility => Item?.Band == Band.Likely ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WeakVisibility => Item?.Band == Band.Weak ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ProtectedVisibility => Item?.IsProtected == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility UserDataVisibility => Item?.IsUserData == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility AttentionVisibility => Item?.Attention == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility RefusedVisibility => Item?.Refused == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WarningVisibility => Item is { Warnings.Count: > 0 } ? Visibility.Visible : Visibility.Collapsed;
    public string RefusalText => Item?.Refused == true ? "Cannot be quarantined: " + Item.RefusalReason : "";
    public string WarningText => Item is { Warnings.Count: > 0 } ? Item.Warnings[0].Message : "";

    /// <summary>Set from the detail-pane fetch so the list can flag the item without a full rebuild.</summary>
    public void RaiseEvidence()
    {
        Raise(nameof(Why));
        Raise(nameof(WarningText));
    }

    /// <summary>A tick changed; refresh this header's computed box, bar and size without rebuilding the list.</summary>
    public void RaiseGroup()
    {
        Raise(nameof(GroupChecked));
        Raise(nameof(GroupBarWidth));
        Raise(nameof(GroupBarTip));
        Raise(nameof(GroupSizeText));
    }

    private void Raise(string name)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
