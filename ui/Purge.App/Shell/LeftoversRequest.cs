using Purge.Client.Broker;

namespace Purge.App.Shell;

/// <summary>
/// What the Uninstall pipeline hands the Leftovers page (design 3.6, 10): the program, the broker's
/// uninstall session (null when the scan comes from a stored fingerprint), whether the client asks for
/// <c>forced</c>, and the broker connection to ask through. Kept small on purpose: S2 may define its
/// own record with the same four facts and the coordinator reconciles the two.
/// </summary>
/// <param name="ProgramId">The program the leftovers belong to.</param>
/// <param name="SessionId">The broker's <c>uninstall.prepare</c> session, or null for a stored-fingerprint scan.</param>
/// <param name="Forced">Ask for a forced scan (the client can never raise a mode, only ask for this one).</param>
/// <param name="Broker">The live broker connection; null in sample mode.</param>
/// <param name="Name">The program's display name, for the page title before the scan answers.</param>
public sealed record LeftoversRequest(
    string ProgramId,
    string? SessionId,
    bool Forced,
    BrokerSession? Broker,
    string? Name = null);
