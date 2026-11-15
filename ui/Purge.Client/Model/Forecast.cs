using System.Text.Json.Serialization;

namespace Purge.Client.Model;

// UI-side shapes for data the engine does not produce yet. They are not in purge-model; each one is listed as an
// engine question in ui/README.md. Until then FakeEngineClient answers from embedded sample JSON.

/// <summary>How much a program is expected to leave behind after its own uninstaller ran.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ForecastVerdict>))]
public enum ForecastVerdict { Unknown, Clean, Some, Large }

[JsonConverter(typeof(JsonStringEnumConverter<ForecastLineKind>))]
public enum ForecastLineKind { Removed, Stays, UserData }

/// <summary>One line of "What Purge expects" in the S1 details pane.</summary>
public sealed record ForecastLine(ForecastLineKind Kind, string Text, string? Detail);

/// <summary>
/// <c>programs.forecast</c> (proposed): the expected leftovers of one program, from what Purge recorded at install
/// time and knowledge packs. <c>EstimateBytes</c> is null when the size is not known; a program with no entry is
/// "not known yet", never "clean".
/// </summary>
public sealed record LeftoverForecast(
    string ProgramId,
    ForecastVerdict Verdict,
    long? EstimateBytes,
    string? What,
    bool HoldsUserData,
    List<ForecastLine> Lines);

[JsonConverter(typeof(JsonStringEnumConverter<BatchState>))]
public enum BatchState { Undoable, Partial, Restored, KeptAll }

/// <summary>One cleanup's share of the quarantine (<c>quarantine.status</c>, proposed).</summary>
public sealed record QuarantineBatch(
    string SessionId,
    string ProgramName,
    string Publisher,
    DateTimeOffset Created,
    string Volume,
    int FileItems,
    int RegistryItems,
    long Bytes,
    BatchState State,
    int UserDataItems);

/// <summary>Quarantine use on one volume. The cap is min(10 GB, 5 % of the volume) (ENGINE_PLAN.md §7.8).</summary>
public sealed record QuarantineVolume(string Volume, long UsedBytes, long CapBytes, string? Note);

public sealed record QuarantineStatus(List<QuarantineVolume> Volumes, List<QuarantineBatch> Batches);
