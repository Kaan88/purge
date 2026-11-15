using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace Purge.App.Views;

/// <summary>
/// S5 with the board 17 safety dial. Live: theme, preset, "Pre-select user data" and "Show Ask in review lists"
/// (in memory, see <see cref="Settings"/>). The rest shows the planned settings on sample values.
/// </summary>
public sealed partial class SettingsView : UserControl
{
    private readonly bool _ready;
    private readonly ObservableCollection<string> _protected =
        [@"D:\Projects", @"%USERPROFILE%\Documents", @"HKCU\Software\Mozilla\Thunderbird"];

    // The preview counts over the same sample the Leftovers page shows (no real scan exists yet).
    private readonly List<LeftoverRow> _sample = ReviewView.Sample().Where(r => !r.IsGroup && r.Band != Band.Weak).ToList();
    private SafetyPreset? _hover;

    public SettingsView()
    {
        InitializeComponent();
        ThemeChoice.SelectedIndex = MainWindow.Instance.Theme switch
        {
            ElementTheme.Light => 1,
            ElementTheme.Dark => 2,
            _ => 0,
        };
        UserDataSwitch.IsOn = Settings.PreSelectUserData;
        InlineAskSwitch.IsOn = Settings.InlineAssistant;
        AssistantSummary.Text = Settings.InlineAssistant ? "Ask in review lists" : "Off";
        PreviewTile.Background = ProgramRow.TileFor("Mozilla");
        (Settings.Preset switch
        {
            SafetyPreset.Cautious => PresetCautious,
            SafetyPreset.Thorough => PresetThorough,
            _ => PresetBalanced,
        }).IsChecked = true;
        _ready = true;
        UpdatePresets();

        ProtectedList.ItemsSource = _protected;

        var marks = LaunchMarkers.Snapshot();
        Markers.Text = string.Join(Environment.NewLine, marks.Select(m => $"{m.Name,-12} {m.Ms,8:F1}"));
        string Ms(string name)
        {
            foreach (var (n, ms) in marks) if (n == name) return $"{ms:F0} ms";
            return "–";
        }
        LastStart.Text = $"Last start: first frame {Ms("presented")}, names visible {Ms("first_tick")}. " +
                         "Leftover scanners include code ported from Bulk Crap Uninstaller (Apache-2.0).";

        var engine = Program.Startup.IsCompletedSuccessfully ? Program.Startup.Result.Hello : null;
        AboutLine.Text = engine is null
            ? "Purge 0.1 (shell preview)"
            : $"Purge 0.1 · engine {engine.Version} · policy {engine.PolicyVersion}";
    }

    private int Selectable => _sample.Count(r => r.Selectable);

    private int SelectedBy(SafetyPreset preset) =>
        _sample.Count(r => r.Selectable && Settings.PreSelects(preset, r.Band, r.IsUserData));

    private void UpdatePresets()
    {
        CountCautious.Text = $"{SelectedBy(SafetyPreset.Cautious)} of {Selectable} selected for Firefox";
        CountBalanced.Text = $"{SelectedBy(SafetyPreset.Balanced)} of {Selectable} selected for Firefox";
        CountThorough.Text = $"{SelectedBy(SafetyPreset.Thorough)} of {Selectable} selected for Firefox";
        OnCautious.Visibility = Settings.Preset == SafetyPreset.Cautious ? Visibility.Visible : Visibility.Collapsed;
        OnBalanced.Visibility = Settings.Preset == SafetyPreset.Balanced ? Visibility.Visible : Visibility.Collapsed;
        OnThorough.Visibility = Settings.Preset == SafetyPreset.Thorough ? Visibility.Visible : Visibility.Collapsed;
        UpdatePreview();
    }

    private void UpdatePreview()
    {
        var preset = _hover ?? Settings.Preset;
        var selected = SelectedBy(preset);
        var left = Selectable - selected;
        var prot = _sample.Count(r => r.Band == Band.Protected);
        PreviewTitle.Text = $"Firefox, with {preset}";
        PvSelected.Text = selected.ToString();
        PvLeft.Text = left.ToString();
        PvProtected.Text = prot.ToString();
        PvSelCol.Width = new GridLength(Math.Max(selected, 0.01), GridUnitType.Star);
        PvLeftCol.Width = new GridLength(Math.Max(left, 0.01), GridUnitType.Star);
        PvProtCol.Width = new GridLength(Math.Max(prot, 0.01), GridUnitType.Star);
        var userData = _sample.Count(r => r.IsUserData);
        PvUserData.Text = Settings.PreSelectUserData
            ? $"User data is pre-selected because you turned that on ({userData} item here)."
            : $"{userData} item holds user data and stays unticked.";
    }

    private static SafetyPreset ParsePreset(object? tag) => tag switch
    {
        "Cautious" => SafetyPreset.Cautious,
        "Thorough" => SafetyPreset.Thorough,
        _ => SafetyPreset.Balanced,
    };

    private void OnPresetChecked(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        Settings.Preset = ParsePreset((sender as FrameworkElement)?.Tag);
        Settings.RaiseChanged();
        UpdatePresets();
    }

    private void OnPresetHover(object sender, PointerRoutedEventArgs e)
    {
        _hover = ParsePreset((sender as FrameworkElement)?.Tag);
        UpdatePreview();
    }

    private void OnPresetLeave(object sender, PointerRoutedEventArgs e)
    {
        _hover = null;
        UpdatePreview();
    }

    private void OnUserDataToggled(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        Settings.PreSelectUserData = UserDataSwitch.IsOn;
        Settings.RaiseChanged();
        UpdatePresets();
    }

    private void OnInlineAskToggled(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        Settings.InlineAssistant = InlineAskSwitch.IsOn;
        AssistantSummary.Text = Settings.InlineAssistant ? "Ask in review lists" : "Off";
        Settings.RaiseChanged();
    }

    private void OnOpenPage(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string key) MainWindow.Instance.Navigate(key);
    }

    private void OnThemeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready) return;
        MainWindow.Instance.ApplyTheme(ThemeChoice.SelectedIndex switch
        {
            1 => ElementTheme.Light,
            2 => ElementTheme.Dark,
            _ => ElementTheme.Default,
        });
    }

    private void OnRemoveProtected(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string path) _protected.Remove(path);
        ProtectedCount.Text = $"{_protected.Count} of yours";
    }
}
