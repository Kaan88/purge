namespace Purge.Client.Rpc;

/// <summary>
/// The one sentence for a reconcile <see cref="Alert"/> (review M3-R2 S5), shared by the Leftovers "Put back" result
/// and the History page, so both say the same thing.
/// </summary>
public static class ReconcileAlert
{
    public static string Text(Alert alert) => alert.MovedBack
        ? $"Purge found another file in quarantine and put it back at {alert.OriginalPath}."
        : $"Purge found another file in quarantine and kept it there: {alert.OriginalPath}.";
}
