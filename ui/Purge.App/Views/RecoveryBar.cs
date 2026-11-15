using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Views;

/// <summary>
/// The bar shown when the engine says an earlier cleanup was interrupted (exit code 8, or sessions listed by
/// <c>journal recover</c>): Resume finishes it, Roll back puts back what it already moved.
/// </summary>
public static class RecoveryBar
{
    public static InfoBar Create(string message, Action done)
    {
        var bar = new InfoBar
        {
            Severity = InfoBarSeverity.Warning,
            Title = "An earlier cleanup was interrupted.",
            Message = message,
            IsOpen = true,
            IsClosable = true,
            RequestedTheme = MainWindow.Instance.ActualTheme,
        };
        var resume = new Button { Content = "Resume it" };
        var rollback = new Button { Content = "Roll it back" };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 0, 0, 12) };
        buttons.Children.Add(resume);
        buttons.Children.Add(rollback);
        bar.Content = buttons;

        async void Run(bool back)
        {
            resume.IsEnabled = rollback.IsEnabled = false;
            bar.Message = back ? "Rolling back…" : "Resuming…";
            try
            {
                var result = await Program.Engine.RecoverAsync(back);
                bar.Severity = result.ExitCode == 0 ? InfoBarSeverity.Success : InfoBarSeverity.Warning;
                bar.Title = back ? "Rolled back." : "Resumed.";
                bar.Message = result.Lines.Count > 0 ? string.Join(" · ", result.Lines) : "No session needed recovery.";
                buttons.Visibility = Visibility.Collapsed;
                done();
            }
            catch (Exception e)
            {
                bar.Severity = InfoBarSeverity.Error;
                bar.Message = e.Message;
                resume.IsEnabled = rollback.IsEnabled = true;
            }
        }

        resume.Click += (_, _) => Run(false);
        rollback.Click += (_, _) => Run(true);
        return bar;
    }
}
