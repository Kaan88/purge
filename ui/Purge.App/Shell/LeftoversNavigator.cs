namespace Purge.App.Shell;

/// <summary>
/// The one way the Uninstall pipeline and the removed-program check reach the Leftovers page: the shell's cached
/// review view, then <see cref="ILeftoversPage.Show"/>. Kept in one small file so the callers agree on a single
/// hand-off.
/// </summary>
public static class LeftoversNavigator
{
    /// <summary>True while the Leftovers page applies a change; its broker link must not be replaced then.</summary>
    public static bool IsChanging => MainWindow.Instance.LeftoversChanging;

    /// <summary>
    /// Shows <paramref name="request"/> on the leftovers page, which owns the broker link from then on; the page comes
    /// on screen unless <paramref name="navigate"/> is false (the user has just gone to another page). False, with
    /// nothing shown and the link not taken, while the page applies a change (<see cref="IsChanging"/>): the caller
    /// keeps or ends the link and says why.
    /// </summary>
    public static bool TryShow(LeftoversRequest request, bool navigate = true)
    {
        if (IsChanging) return false;
        var page = navigate ? MainWindow.Instance.OpenReview() : MainWindow.Instance.ReviewPage;
        page.Show(request);
        return true;
    }
}
