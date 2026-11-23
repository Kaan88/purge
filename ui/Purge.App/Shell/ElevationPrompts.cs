using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Shell;

/// <summary>
/// The two pieces of the admin prompt that belong to the UI (ENGINE_PLAN.md S7; M3_DESIGN.md T11): the explanation shown
/// before the first Windows prompt, and the bar shown when the prompt did not happen or was cancelled (error 1223, not
/// an engine error). Both are built on first use, never for the first frame. Every route that starts the broker
/// (Uninstall, Check for leftovers, History &amp; undo, the Quarantine vault) calls them, so their words name no route;
/// nothing at launch does.
/// </summary>
public static class ElevationPrompts
{
    /// <summary>Whether the explanation has been shown in this run (persisting it comes with the settings file).</summary>
    public static bool Explained { get; private set; }

    /// <summary>
    /// True when the last <see cref="ConfirmFirstElevationAsync"/> ended with "Not now": the Windows prompt was never
    /// shown, so the bar must not say the user cancelled it.
    /// </summary>
    public static bool DeclinedExplanation { get; private set; }

    /// <summary>
    /// Explains the Windows prompt the first time Purge asks for it. True to go on to the prompt; false for "Not now".
    /// After the first time it returns true at once.
    /// </summary>
    public static async Task<bool> ConfirmFirstElevationAsync(XamlRoot root, ElementTheme theme)
    {
        DeclinedExplanation = false;
        if (Explained) return true;
        var dialog = new ContentDialog
        {
            XamlRoot = root,
            RequestedTheme = theme,
            Title = "This needs administrator permission",
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 440,
                Text = "For this, Purge starts a helper called purge-broker.exe with administrator permission. Windows asks "
                     + "you first, and may show the publisher as unknown until Purge is signed.\n\n"
                     + "Any program can show a prompt like that, so the Windows prompt is not your approval. Before anything "
                     + "is moved or removed, Purge shows its own review and waits for you.",
            },
            PrimaryButtonText = "Continue",
            CloseButtonText = "Not now",
            DefaultButton = ContentDialogButton.Primary,
        };
        var answer = await dialog.ShowAsync();
        if (answer != ContentDialogResult.Primary)
        {
            DeclinedExplanation = true;
            return false;
        }
        Explained = true;
        return true;
    }

    /// <summary>
    /// The bar for a Windows prompt that did not lead to the broker: cancelled at Windows (1223), or not shown because
    /// the user chose "Not now" at the explanation (<paramref name="declinedExplanation"/>). <paramref name="tryAgain"/>
    /// adds a "Try again" button.
    /// </summary>
    public static InfoBar CancelledBar(ElementTheme theme, bool declinedExplanation, Action? tryAgain = null)
    {
        var bar = new InfoBar
        {
            Severity = InfoBarSeverity.Informational,
            Title = declinedExplanation ? "Not started." : "You cancelled the Windows prompt.",
            Message = declinedExplanation
                ? "You chose Not now, so Purge did not ask Windows for administrator permission. Nothing was changed."
                : "Nothing was changed. This needs administrator permission.",
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
