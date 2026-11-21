using Microsoft.UI.Xaml;

namespace Purge.App;

public partial class App : Application
{
    private MainWindow? _window;

    public App()
    {
        InitializeComponent();
        UnhandledException += (_, e) =>
        {
            // Skeleton-level crash note; real diagnostics (log folder, export) come with S5 in M3.
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "purge-crash.txt"), $"{DateTime.Now:O} {e.Exception}{Environment.NewLine}"); }
            catch (IOException) { }
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        LaunchMarkers.Mark("on_launched");
        _window = new MainWindow();
        _window.Activate();
    }
}
