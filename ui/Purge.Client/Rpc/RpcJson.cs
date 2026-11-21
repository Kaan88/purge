using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Purge.Client.Rpc;

/// <summary>
/// Reads and writes the engine API's DTOs (M3_DESIGN.md §6.5). The models are hand-written in
/// <c>RpcModels.cs</c>; every read and write goes through the source-generated context in
/// <c>Generated/RpcJsonContext.g.cs</c>, so Native AOT needs no reflection at run time.
/// </summary>
public static class RpcJson
{
    /// <summary>
    /// Reads <paramref name="json"/> as <typeparamref name="T"/> and writes it back. The round-trip test
    /// of every fixture uses this; a document that does not fit its type is an
    /// <see cref="InvalidDataException"/>.
    /// </summary>
    public static string RoundTrip<T>(string json, JsonTypeInfo<T> info)
    {
        T value;
        try
        {
            value = JsonSerializer.Deserialize(json, info)
                ?? throw new InvalidDataException($"the document is null, not a {info.Type.Name}");
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"the document is not a {info.Type.Name}: {e.Message}", e);
        }
        return JsonSerializer.Serialize(value, info);
    }
}
