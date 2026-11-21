using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Shell;

/// <summary>
/// The two pieces of the admin prompt that belong to the UI (ENGINE_PLAN.md S7; M3_DESIGN.md T11): the explanation shown
/// before the first Windows prompt, and the bar shown when that prompt is cancelled (error 1223, not an engine
/// error). Both are built on first use, never for the first frame. The broker flow (M3-BROKER-FLOW) calls them; nothing
/// at launch does.
/// </summary>
public static class ElevationPrompts
{
    /// <summary>Whether the explanation has been shown in this run (persisting it comes with the settings file).</summary>
    public static bool Explained { get; private set; }

    /// <summary>
    /// Explains the Windows prompt the first time Purge asks for it. True to go on to the prompt; false for "Not now".
    /// After the first time it returns true at once.
    /// </summary>
    public static async Task<bool> ConfirmFirstElevationAsync(XamlRoot root, ElementTheme theme)
    {
        if (Explained) return true;
        var dialog = new ContentDialog
        {
            XamlRoot = root,
            RequestedTheme = theme,
            Title = "Purge needs administrator permission",
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 440,
                Text = "To remove programs for all users, Purge starts a helper called purge-broker.exe with administrator "
                     + "permission. Windows asks you first, and may show the publisher as unknown until Purge is signed.\n\n"
                     + "Any program can show a prompt like that, so the Windows prompt is not your approval. Before anything "
                     + "is moved or removed, Purge shows its own review and waits for you.",
            },
            PrimaryButtonText = "Continue",
            CloseButtonText = "Not now",
            DefaultButton = ContentDialogButton.Primary,
        };
        var answer = await dialog.ShowAsync();
        if (answer != ContentDialogResult.Primary) return false;
        Explained = true;
        return true;
    }

    /// <summary>The bar for a cancelled Windows prompt; <paramref name="tryAgain"/> adds a "Try again" button.</summary>
    public static InfoBar CancelledBar(ElementTheme theme, Action? tryAgain = null)
    {
        var bar = new InfoBar
        {
            Severity = InfoBarSeverity.Informational,
            Title = "You cancelled the admin prompt.",
            Message = "Nothing was changed. Removing programs for all users needs administrator permission.",
            IsOpen = true,
            IsClosable = true,
            RequestedTheme = theme,
        };
        if (tryAgain is not null)
        {
            var retry = new Button { Content = "Try again" };
            retry.Click += (_, _) =>
            {
                bar.IsOpen = false;
                tryAgain();
            };
            bar.ActionButton = retry;
        }
        return bar;
    }
}
