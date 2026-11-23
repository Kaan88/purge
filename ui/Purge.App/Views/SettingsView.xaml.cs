using System.Diagnostics;
using System.Reflection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Views;

/// <summary>
/// S5. Only what works or is true is shown (DECISIONS 2026-11-24): the theme, a link to the quarantine, the rule of
/// what Purge ticks for you, and the versions. The launch markers show in a DEBUG build only.
/// </summary>
public sealed partial class SettingsView : UserControl
{
    private readonly bool _ready;

    public SettingsView()
    {
        InitializeComponent();
        ThemeChoice.SelectedIndex = MainWindow.Instance.Theme switch
        {
            ElementTheme.Light => 1,
            ElementTheme.Dark => 2,
            _ => 0,
        };
        _ready = true;

        AboutLine.Text = AboutText();

#if DEBUG
        var marks = LaunchMarkers.Snapshot();
        Markers.Text = string.Join(Environment.NewLine, marks.Select(m => $"{m.Name,-12} {m.Ms,8:F1}"));
        MarkersExpander.Visibility = Visibility.Visible;
#endif
    }

    /// <summary>
    /// "Purge 0.1.2 · engine 0.1.2 · policy …", with "sample data" only when the app shows the sample data (--sample,
    /// or an engine that could not start). The app's version is the exe's FILEVERSION, which comes from Cargo.toml.
    /// </summary>
    private static string AboutText()
    {
        var parts = new List<string> { "Purge " + AppVersion() };
        var hello = Program.Startup.IsCompletedSuccessfully ? Program.Startup.Result.Hello : null;
        var live = Program.Engine.IsLive;
        if (live && hello is not null)
        {
            parts.Add("engine " + hello.Version);
            if (hello.PolicyVersion.Length > 0) parts.Add("policy " + hello.PolicyVersion);
        }
        if (!live) parts.Add("sample data");
        return string.Join(" · ", parts);
    }

    private static string AppVersion()
    {
        try
        {
            if (Environment.ProcessPath is { Length: > 0 } exe
                && FileVersionInfo.GetVersionInfo(exe).FileVersion is { Length: > 0 } file)
                return file;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // Fall back to the assembly's version below.
        }
        return typeof(SettingsView).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
               ?? "(version unknown)";
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
}
