using Purge.App;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>The UI's icon atlas: one file, keyed by path and modification time (M3-ICONS).</summary>
public sealed class IconAtlasTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "purge-atlas-" + Guid.NewGuid().ToString("N"));
    private readonly string _file;

    public IconAtlasTests()
    {
        Directory.CreateDirectory(_directory);
        _file = Path.Combine(_directory, "icons.atlas");
    }

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static byte[] Pixels(int px) => Enumerable.Repeat((byte)0x40, px * px * 4).ToArray();

    [Fact]
    public void A_stored_icon_is_a_hit_and_survives_a_reload()
    {
        var path = Path.Combine(_directory, "app.exe");
        const long modified = 133_900_000_000_000_000;
        var atlas = new IconAtlas(_file);

        atlas.Put(path, modified, 24, Pixels(24));

        Assert.True(atlas.TryGet(path, modified, out var hit));
        Assert.Equal(24, hit.Px);
        Assert.Equal(Pixels(24), hit.Bgra);
        Assert.True(atlas.Save());

        var reloaded = new IconAtlas(_file);
        Assert.True(reloaded.TryGet(path, modified, out var persisted));
        Assert.Equal(Pixels(24), persisted.Bgra);
    }

    [Fact]
    public void An_unknown_path_or_a_changed_file_is_a_miss()
    {
        var path = Path.Combine(_directory, "app.exe");
        const long modified = 133_900_000_000_000_000;
        var atlas = new IconAtlas(_file);
        atlas.Put(path, modified, 24, Pixels(24));

        Assert.False(atlas.TryGet(Path.Combine(_directory, "other.exe"), modified, out _));
        Assert.False(atlas.TryGet(path, modified + 1, out _), "the file changed after the icon was cached");

        // Paths compare case-insensitively, as Windows does.
        Assert.True(atlas.TryGet(path.ToUpperInvariant(), modified, out _));
    }

    [Fact]
    public void A_damaged_atlas_starts_empty_and_is_not_an_error()
    {
        File.WriteAllText(_file, "not an atlas");
        var atlas = new IconAtlas(_file);

        Assert.Equal(0, atlas.Count);
        Assert.False(atlas.TryGet(Path.Combine(_directory, "app.exe"), 1, out _));
        Assert.True(atlas.Save());
        Assert.Equal(0, new IconAtlas(_file).Count);
    }
}
