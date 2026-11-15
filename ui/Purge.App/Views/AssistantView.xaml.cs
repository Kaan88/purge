using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Purge.App.Views;

/// <summary>S6 on sample data. No model is connected; "Ask" says so instead of answering.</summary>
public sealed partial class AssistantView : UserControl
{
    public AssistantView() => InitializeComponent();

    private void OnShowInReview(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("leftovers");

    private void OnDismiss(object sender, RoutedEventArgs e)
    {
        var card = (sender as FrameworkElement)?.Tag as string == "1" ? Suggestion1 : Suggestion2;
        card.Visibility = Visibility.Collapsed;
    }

    private void OnAddLauncher(object sender, RoutedEventArgs e)
    {
        AddLauncher.Content = "Added to queue";
        AddLauncher.IsEnabled = false;
    }

    private void OnAsk(object sender, RoutedEventArgs e)
    {
        var q = AskBox.Text.Trim();
        if (q.Length == 0) return;
        Question.Text = q;
        Answer.Text = "No model is connected in this preview. In M6 the answer comes from the model you pick in Settings, using only the tools listed on the right.";
        AskBox.Text = "";
    }
}
