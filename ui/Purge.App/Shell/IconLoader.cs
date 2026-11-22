using Purge.Client;
using Purge.Client.Model;

namespace Purge.App;

/// <summary>
/// Fills the Programs list's icons: first from the <see cref="IconAtlas"/>, then from <c>programs.icons</c>, in the
/// order given (viewport first). An icon the engine could not read, or a failing engine, leaves the placeholder
/// tile; nothing here ever throws to the page.
///
/// <c>icon.batch</c> carries no source path or file time, so the atlas key is the program id (with a fixed prefix
/// so it can never equal a real file) and the stamp is a stable hash of the program's version and install time:
/// an updated program asks again, an unchanged one is served from the file.
/// </summary>
public static class IconLoader
{
    /// <summary>Edge length asked from the engine; the atlas holds 24 px icons (M3_DESIGN.md A10).</summary>
    public const int Px = 24;

    /// <summary>Programs per <c>programs.icons</c> request: the engine answers one request at a time, so a details
    /// request waits for at most one chunk.</summary>
    public const int Chunk = 48;

    /// <summary>The atlas path of a program's icon.</summary>
    public static string AtlasPath(string programId) => "purge-program:" + programId;

    /// <summary>The atlas stamp of a program: a stable 64-bit hash (FNV-1a) of its version and install time.</summary>
    public static long Stamp(string? version, ulong? installTime)
    {
        var hash = 14695981039346656037UL;
        foreach (var c in (version ?? "") + "|" + (installTime?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? ""))
            hash = (hash ^ c) * 1099511628211UL;
        return unchecked((long)hash);
    }

    /// <summary>
    /// Delivers the cached icons at once, asks the engine for the rest in chunks and delivers those as they come,
    /// then saves the atlas (a null atlas is no cache: sample data keeps nothing). <paramref name="deliver"/> may run on any thread. Returns the number of icons that came
    /// from the engine.
    /// <para><paramref name="answered"/> (optional, any thread) names the ids that are settled: the cached ones once they are
    /// delivered, and each engine chunk once its request has ended, whether or not an icon came for every id (a program
    /// without one keeps its tile). It always follows the <paramref name="deliver"/> calls of those ids. The ids of a chunk
    /// the engine failed are not named. The launch bench's <c>icons_visible</c> marker waits for the first screenful.</para>
    /// </summary>
    public static async Task<int> LoadAsync(IEngineClient engine, IconAtlas? atlas, IReadOnlyList<(string Id, long Stamp)> order,
        Action<string, AtlasIcon> deliver, CancellationToken ct, Action<IReadOnlyList<string>>? answered = null)
    {
        var stamps = new Dictionary<string, long>(order.Count, StringComparer.Ordinal);
        var misses = new List<string>();
        var hits = new List<string>();
        foreach (var (id, stamp) in order)
        {
            if (!stamps.TryAdd(id, stamp)) continue;
            if (atlas is not null && atlas.TryGet(AtlasPath(id), stamp, out var cached))
            {
                deliver(id, cached);
                hits.Add(id);
            }
            else misses.Add(id);
        }
        if (hits.Count > 0) answered?.Invoke(hits);

        var fetched = 0;
        try
        {
            for (var i = 0; i < misses.Count; i += Chunk)
            {
                ct.ThrowIfCancellationRequested();
                var ids = misses.GetRange(i, Math.Min(Chunk, misses.Count - i));
                await engine.LoadIconsAsync(ids, Px, icons =>
                {
                    foreach (var icon in icons)
                    {
                        if (icon.Bgra is not { } bgra || icon.Px < 1 || !stamps.TryGetValue(icon.ProgramId, out var stamp)) continue;
                        var made = new AtlasIcon(icon.Px, bgra);
                        try { atlas?.Put(AtlasPath(icon.ProgramId), stamp, icon.Px, bgra); }
                        catch (ArgumentException) { continue; }
                        Interlocked.Increment(ref fetched);
                        deliver(icon.ProgramId, made);
                    }
                }, ct).ConfigureAwait(false);
                answered?.Invoke(ids);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // The engine ended or refused: the rest keep their placeholder tiles.
        }
        atlas?.Save();
        return fetched;
    }

    /// <summary>The straight-alpha BGRA pixels of the engine as premultiplied ones, the format of a WriteableBitmap.</summary>
    public static byte[] Premultiply(byte[] bgra)
    {
        var result = new byte[bgra.Length];
        for (var i = 0; i + 3 < bgra.Length; i += 4)
        {
            var a = bgra[i + 3];
            result[i] = (byte)((bgra[i] * a + 127) / 255);
            result[i + 1] = (byte)((bgra[i + 1] * a + 127) / 255);
            result[i + 2] = (byte)((bgra[i + 2] * a + 127) / 255);
            result[i + 3] = a;
        }
        return result;
    }
}
