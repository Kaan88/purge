namespace Purge.App.Shell;

/// <summary>
/// The one way the Uninstall pipeline reaches the Leftovers page: the shell's cached review view, then
/// <see cref="ILeftoversPage.Show"/>. Kept in one small file so the two packages agree on a single hand-off.
/// </summary>
public static class LeftoversNavigator
{
    /// <summary>Shows <paramref name="request"/> on the leftovers page; the page owns the broker link from then on.</summary>
    public static void Show(LeftoversRequest request) => MainWindow.Instance.OpenReview().Show(request);
}
