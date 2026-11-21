using System.Text.Json.Serialization;
using Purge.Client.Model;

namespace Purge.Client.Stdio;

// The parts of the engine's stdio protocol the shell reads (crates/purge-rpc: methods.rs, table.rs, error.rs).
// Members the shell does not use are ignored on read.

/// <summary><c>engine.hello</c> result of the medium engine.</summary>
internal sealed record WireHello(
    string Version,
    bool Elevated,
    string UserSid,
    string? ShellSid,
    string Edition,
    int Build,
    int? Ubr,
    bool BaselineAvailable,
    string PolicyVersion,
    WireBaselineBuild? BaselineBuild);

internal sealed record WireBaselineBuild(string? State, string? Reason);

/// <summary>Result of a request whose data follows in notifications: how many items will follow.</summary>
internal sealed record WireStarted(int Count);

/// <summary>One raw ARP row of a <c>programs.batch</c> notification.</summary>
internal sealed record WireProgramRow(
    string ProgramId,
    string Name,
    string? Publisher,
    string? Version,
    InstallScope Scope,
    ulong? SizeBytes,
    ulong? InstallTime);

/// <summary><c>programs.batch</c> notification params.</summary>
internal sealed record WireProgramsBatch(ulong Request, List<WireProgramRow> Rows);

/// <summary><c>error.data</c> of a server error: the kind, and the message of the kinds that have one.</summary>
internal sealed record WireErrorData(string? Kind, string? Message);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(WireHello))]
[JsonSerializable(typeof(WireStarted))]
[JsonSerializable(typeof(WireProgramsBatch))]
[JsonSerializable(typeof(WireErrorData))]
internal sealed partial class WireJsonContext : JsonSerializerContext;
