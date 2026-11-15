using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Views;

/// <summary>S2 on sample data. The buttons change the sample state only; nothing runs.</summary>
public sealed partial class QueueView : UserControl
{
    public QueueView()
    {
        InitializeComponent();
        FirefoxTile.Background = ProgramRow.TileFor("Mozilla");
        PythonTile.Background = ProgramRow.TileFor("Python Software Foundation");
        GitTile.Background = ProgramRow.TileFor("The Git Development Community");
    }

    private void OnReview(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("leftovers");

    private void OnClosePython(object sender, RoutedEventArgs e)
    {
        RunningBar.IsOpen = false;
        CloseAppsWarn.Visibility = Visibility.Collapsed;
        CloseAppsDone.Visibility = Visibility.Visible;
        PythonStateText.Text = "Running uninstaller";
        PythonProgress.Value = 60;
    }

    private void OnRemoveGit(object sender, RoutedEventArgs e) => GitCard.Visibility = Visibility.Collapsed;

    private void OnSample(object sender, RoutedEventArgs e) { }
}
