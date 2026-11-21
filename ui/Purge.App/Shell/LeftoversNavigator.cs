using Purge.App.Views;
using Purge.Client.Broker;

namespace Purge.App.Shell;

/// <summary>
/// The one way the Uninstall pipeline reaches the Leftovers page: the shell's cached review view, then
/// <see cref="ILeftoversPage.Show"/>. Kept in one small file so the two packages agree on a single hand-off.
/// </summary>
public static class LeftoversNavigator
{
    /// <summary>
    /// Shows <paramref name="request"/> on the leftovers page. False when this build's page does not take a request
    /// yet; the caller then keeps the page's own bar and the broker link is closed rather than lost.
    /// </summary>
    public static bool Show(LeftoversRequest request)
    {
        ReviewView page;
        try
        {
            page = MainWindow.Instance.OpenReview();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Close(request.Broker);
            return false;
        }
        // The object cast keeps this file independent of S3: when the leftovers page implements the contract, it
        // receives the scan; until then the page is simply a shell and the caller shows its own bar.
        if ((object)page is ILeftoversPage target)
        {
            target.Show(request);
            return true;
        }
        Close(request.Broker);
        return false;
    }

    private static void Close(BrokerSession? session)
    {
        if (session is null) return;
        try { session.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }
}
