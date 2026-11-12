using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Views;

public sealed partial class PlaceholderView : UserControl
{
    private PlaceholderView(string glyph, string title, string screen, string milestone, string summary, string[] points)
    {
        InitializeComponent();
        GlyphIcon.Glyph = glyph;
        TitleText.Text = title;
        ScreenText.Text = $"{screen} · planned for {milestone}";
        SummaryText.Text = summary;
        PointsText.Text = string.Join(Environment.NewLine, points.Select(p => "•  " + p));
    }

    public static PlaceholderView Startup() => new("", "Startup", "Later", "after v1",
        "See and switch off what starts with Windows: Run keys, startup folders, scheduled tasks and services.",
        [
            "Each entry shows which installed program it belongs to.",
            "Switching an entry off is reversible from History & undo.",
        ]);
}
