using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Purge.App;

namespace BareWinUI;

public static class Program
{
    public static bool BenchExit { get; private set; }

    [STAThread]
    private static int Main(string[] args)
    {
        LaunchMarkers.Mark("main");
        BenchExit = args.Contains("--bench-exit");
        WinRT.ComWrappersSupport.InitializeComWrappers();
        Application.Start(p =>
        {
            SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
            _ = new App();
        });
        return 0;
    }
}
