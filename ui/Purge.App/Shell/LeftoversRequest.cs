using Purge.Client.Broker;
using Purge.Client.Rpc;

namespace Purge.App.Shell;

/// <summary>
/// The Uninstall pipeline's hand-off to the Leftovers page (M3-UI-S2 → M3-UI-S3). The uninstaller has finished, the
/// broker has scanned the session, and the leftovers page takes the live broker link for <c>scan.candidates</c>,
/// <c>plan.create</c> and <c>plan.execute</c>.
/// <para>
/// The leftover page owns <see cref="Broker"/> once it is shown: it reads the candidates and, when the user confirms,
/// executes the plan. The page that handed it over no longer closes it. <see cref="RestorePoint"/> is the choice the
/// confirm dialog carried, passed on to <c>plan.execute</c> unchanged.
/// </para>
/// </summary>
/// <param name="ProgramId">The program the session recorded; candidate ids come from its scan.</param>
/// <param name="ProgramName">The name the review page titles itself with.</param>
/// <param name="SessionId">The broker session of the uninstall.</param>
/// <param name="ScanId">The scan made over that session (<c>leftovers.scan</c>).</param>
/// <param name="Mode">post, external or forced; forced means nothing is pre-selected.</param>
/// <param name="RestorePoint">The restore-point choice for the plan's execution.</param>
/// <param name="Quiet">Whether the uninstaller ran in quiet mode (the review page says so).</param>
/// <param name="Broker">The live broker link; null when the pipeline ended without one (a forced scan from a dead link).</param>
public sealed record LeftoversRequest(
    string ProgramId,
    string ProgramName,
    string SessionId,
    string ScanId,
    ScanMode Mode,
    RestorePoint RestorePoint,
    bool Quiet,
    BrokerSession? Broker)
{
    /// <summary>True for the forced scan after a failed or unverified uninstall: nothing starts ticked.</summary>
    public bool Forced => Mode == ScanMode.Forced;
}

/// <summary>
/// What the Leftovers page (M3-UI-S3) implements to receive a pipeline's scan. Kept here, apart from the page, so the
/// Uninstall page compiles and hands over whether or not the leftovers page is ready yet.
/// </summary>
public interface ILeftoversPage
{
    /// <summary>Shows the candidates of <paramref name="request"/>; the page takes ownership of its broker link.</summary>
    void Show(LeftoversRequest request);
}
