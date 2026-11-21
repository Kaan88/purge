using System.Text;

namespace Purge.App;

/// <summary>One cached icon: its edge length and its top-down BGRA pixels.</summary>
public readonly struct AtlasIcon
{
    /// <summary>An icon at <paramref name="px"/> pixels square.</summary>
    public AtlasIcon(int px, byte[] bgra)
    {
        Px = px;
        Bgra = bgra;
    }

    /// <summary>Edge length in pixels.</summary>
    public int Px { get; }

    /// <summary><see cref="Px"/> × <see cref="Px"/> BGRA pixels, top-down.</summary>
    public byte[] Bgra { get; }
}

/// <summary>
/// The UI's one icon atlas: the 24 px icons the engine sent, keyed by source path and that file's
/// modification time, persisted as a single file under <c>%LOCALAPPDATA%\Purge</c>
/// (M3_DESIGN.md §10, package M3-ICONS).
///
/// The atlas is a display cache and nothing else: a damaged, missing or read-only atlas file starts
/// empty or refuses to save, and the UI simply shows the placeholder tile. A hit needs both the path
/// and the recorded modification time to match, so replacing a file makes its old icon a miss.
///
/// Format (little-endian, written by <see cref="Save"/>): the magic <c>PICA</c>, a <c>u16</c>
/// version, a <c>u16</c> reserved word and an <c>i32</c> entry count; each entry is an <c>i32</c>
/// UTF-8 path length and its bytes, an <c>i64</c> modification time, a <c>u16</c> edge length, an
/// <c>i32</c> pixel length and its BGRA bytes. Unknown versions and malformed entries are ignored.
/// </summary>
public sealed class IconAtlas
{
    private const uint Magic = 0x41434950; // "PICA" little-endian
    private const ushort Version = 1;
    private const int MaxEntries = 8192;
    private const int MaxPathBytes = 32 * 1024;
    private const int MaxPx = 256;

    private readonly record struct Key(string Path, long Modified);

    private sealed class KeyComparer : IEqualityComparer<Key>
    {
        public static readonly KeyComparer Instance = new();

        public bool Equals(Key x, Key y) =>
            x.Modified == y.Modified && string.Equals(x.Path, y.Path, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(Key key) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(key.Path), key.Modified);
    }

    private readonly object _gate = new();
    private readonly Dictionary<Key, AtlasIcon> _icons = new(KeyComparer.Instance);
    private bool _dirty;

    /// <summary>The atlas opened for this user: <c>%LOCALAPPDATA%\Purge\icons.atlas</c>.</summary>
    public static string DefaultFile { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Purge", "icons.atlas");

    /// <summary>Opens the atlas at <paramref name="file"/>; a missing or damaged file starts empty.</summary>
    public IconAtlas(string? file = null)
    {
        FilePath = file ?? DefaultFile;
        Load();
    }

    /// <summary>The one atlas file.</summary>
    public string FilePath { get; }

    /// <summary>How many icons the atlas holds.</summary>
    public int Count
    {
        get { lock (_gate) return _icons.Count; }
    }

    /// <summary>The cached icon of <paramref name="path"/> as last seen at <paramref name="modifiedTicks"/>.</summary>
    public bool TryGet(string path, long modifiedTicks, out AtlasIcon icon)
    {
        var key = KeyOf(path, modifiedTicks);
        lock (_gate) return _icons.TryGetValue(key, out icon);
    }

    /// <summary>Records an icon. The pixel length must be <c>px * px * 4</c>.</summary>
    /// <exception cref="ArgumentException">The edge length or pixel buffer is not a square BGRA image.</exception>
    public void Put(string path, long modifiedTicks, int px, ReadOnlySpan<byte> bgra)
    {
        if (px is < 1 or > MaxPx || bgra.Length != px * px * 4)
            throw new ArgumentException("an icon is px * px * 4 BGRA bytes, 1 to 256 px square", nameof(bgra));
        var key = KeyOf(path, modifiedTicks);
        lock (_gate)
        {
            // A bounded cache: at the limit, start over rather than grow without end.
            if (_icons.Count >= MaxEntries && !_icons.ContainsKey(key)) _icons.Clear();
            _icons[key] = new AtlasIcon(px, bgra.ToArray());
            _dirty = true;
        }
    }

    /// <summary>Writes the atlas to <see cref="FilePath"/> atomically; false when it could not be saved.</summary>
    public bool Save()
    {
        lock (_gate)
        {
            if (!_dirty && File.Exists(FilePath)) return true;
            var directory = Path.GetDirectoryName(FilePath);
            var temporary = FilePath + ".tmp";
            try
            {
                if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: false))
                {
                    writer.Write(Magic);
                    writer.Write(Version);
                    writer.Write((ushort)0);
                    writer.Write(_icons.Count);
                    foreach (var (key, icon) in _icons)
                    {
                        var path = Encoding.UTF8.GetBytes(key.Path);
                        writer.Write(path.Length);
                        writer.Write(path);
                        writer.Write(key.Modified);
                        writer.Write((ushort)icon.Px);
                        writer.Write(icon.Bgra.Length);
                        writer.Write(icon.Bgra);
                    }
                }
                File.Move(temporary, FilePath, overwrite: true);
                _dirty = false;
                return true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                TryDelete(temporary);
                return false;
            }
        }
    }

    /// <summary>Drops every cached icon; the file is rewritten by the next <see cref="Save"/>.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _icons.Clear();
            _dirty = true;
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return;
            using var stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: false);
            if (reader.ReadUInt32() != Magic || reader.ReadUInt16() != Version) return;
            _ = reader.ReadUInt16();
            var count = reader.ReadInt32();
            if (count < 0 || count > MaxEntries) return;
            for (var i = 0; i < count; i++)
            {
                var pathLength = reader.ReadInt32();
                if (pathLength is < 0 or > MaxPathBytes || pathLength > stream.Length - stream.Position) return;
                var path = Encoding.UTF8.GetString(reader.ReadBytes(pathLength));
                var modified = reader.ReadInt64();
                var px = reader.ReadUInt16();
                var length = reader.ReadInt32();
                if (px is < 1 or > MaxPx || length != px * px * 4 || length > stream.Length - stream.Position) return;
                var bgra = reader.ReadBytes(length);
                if (bgra.Length != length) return;
                _icons[new Key(path, modified)] = new AtlasIcon(px, bgra);
            }
            _dirty = false;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // A damaged cache is not an error: icons fall back to the placeholder.
            _icons.Clear();
        }
    }

    private static Key KeyOf(string path, long modifiedTicks)
    {
        try
        {
            return new Key(Path.GetFullPath(path), modifiedTicks);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new Key(path, modifiedTicks);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }
}
