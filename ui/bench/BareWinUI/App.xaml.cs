using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.App;

namespace BareWinUI;

public partial class App : Application
{
    private Window? _window;

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        LaunchMarkers.Mark("on_launched");
        _window = new Window { Content = new Grid() };
        LaunchMarkers.Mark("window_ctor");
        _window.SystemBackdrop = new MicaBackdrop();
        CompositionTarget.Rendering += OnFirstRendering;
        _window.Activate();
    }

    private void OnFirstRendering(object? sender, object e)
    {
        CompositionTarget.Rendering -= OnFirstRendering;
        LaunchMarkers.Mark("first_tick");
        var queue = _window!.DispatcherQueue;
        queue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => Task.Run(() =>
        {
            LaunchMarkers.DwmFlush();
            LaunchMarkers.Mark("presented");
            LaunchMarkers.Flush();
            if (Program.BenchExit) queue.TryEnqueue(() => { _window.Close(); Exit(); });
        }));
    }
}
