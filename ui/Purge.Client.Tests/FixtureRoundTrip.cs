using System.Text.Json.Nodes;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// Every fixture of the engine API, read as its DTO and written back (M3_DESIGN.md §6.5). The Rust test
/// `purge_rpc::api_tests::fixture_round_trip_for_every_type` does the same on the engine side from the
/// same files; the fixtures are copied into Fixtures\ at build time.
/// </summary>
public sealed class FixtureRoundTrip
{
    private static string FixtureDir => Path.Combine(AppContext.BaseDirectory, "Fixtures");

    [Fact]
    public void EveryFixtureReadsAndWritesBack()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (stem, roundTrip) in RpcFixtures.All)
        {
            Assert.True(seen.Add(stem), $"{stem} is in the registry twice");
            var path = Path.Combine(FixtureDir, stem + ".json");
            var text = File.ReadAllText(path);
            var written = roundTrip(text);
            Assert.True(
                JsonNode.DeepEquals(JsonNode.Parse(text), JsonNode.Parse(written)),
                $"{stem} does not round trip:\n{written}");
        }

        var onDisk = Directory.EnumerateFiles(FixtureDir, "*.json")
            .Select(n => Path.GetFileNameWithoutExtension(n)!)
            .Order(StringComparer.Ordinal)
            .ToList();
        Assert.Equal(onDisk, seen.Order(StringComparer.Ordinal).ToList());
    }

    [Fact]
    public void AWrongShapeIsRefused()
    {
        var (_, hello) = RpcFixtures.All.Single(f => f.Stem == "pipe.engine.hello.result");
        Assert.Throws<InvalidDataException>(() => hello("""{"elevated":"yes"}"""));
        Assert.Throws<InvalidDataException>(() => hello("not json"));
    }
}
