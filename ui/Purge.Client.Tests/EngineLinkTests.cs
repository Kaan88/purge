using Purge.Client.Stdio;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>The start of the app: the engine, or the fallback notice and the sample data when it is missing or failing.</summary>
public sealed class EngineLinkTests
{
    private static IEngineClient Sample() => new FakeEngineClient();

    [Fact]
    public async Task AnEngineThatAnswersIsUsedWithoutANotice()
    {
        using var engine = ScriptedEngine.Healthy();
        var marks = new List<string>();
        var link = new EngineLink(() => engine.Client, Sample, engineReady: () => marks.Add("engine_ready"), listReply: () => marks.Add("list_reply"));

        var result = await link.Startup;

        Assert.Null(result.Error);
        Assert.Same(engine.Client, result.Engine);
        Assert.Same(engine.Client, link.Client);
        Assert.Equal("Git", Assert.Single(result.Inventory.Entries).DisplayName);
        Assert.Equal(["engine_ready", "list_reply"], marks);
    }

    [Fact]
    public async Task AMissingEngineFileFallsBackToSampleDataWithANotice()
    {
        var path = Path.Combine(Path.GetTempPath(), "purge-no-such-engine", "purge-engine.exe");
        var link = new EngineLink(() => StdioEngineClient.Start(path), Sample);

        var result = await link.Startup;

        Assert.NotNull(result.Error);
        Assert.Contains("sample data", result.Error);
        Assert.Contains("purge-engine.exe", result.Error);
        Assert.False(result.Engine.IsLive);
        Assert.IsType<FakeEngineClient>(link.Client);
        Assert.NotEmpty(result.Inventory.Entries);
        Assert.Equal("0.0.0-stub", result.Hello.Version);
    }

    [Fact]
    public async Task AFileThatIsNotAnEngineFallsBack()
    {
        var path = Path.Combine(Path.GetTempPath(), "purge-not-an-engine-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(path, "not a program");
        try
        {
            var result = await new EngineLink(() => StdioEngineClient.Start(path), Sample).Startup;
            Assert.Contains("sample data", result.Error);
            Assert.False(result.Engine.IsLive);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task AnEngineThatEndsAtOnceFallsBack()
    {
        using var engine = new ScriptedEngine((_, e) => e.End());
        var link = new EngineLink(() => engine.Client, Sample);

        var result = await link.Startup;

        Assert.Contains("sample data", result.Error);
        Assert.Contains("ended", result.Error);
        Assert.IsType<FakeEngineClient>(link.Client);
        Assert.NotEmpty(result.Inventory.Entries);
    }

    [Fact]
    public async Task AnEngineThatAnswersWithAnErrorFallsBack()
    {
        using var engine = new ScriptedEngine((line, e) =>
            e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{ScriptedEngine.IdOf(line)},\"error\":{ScriptedEngine.Compact(ScriptedEngine.Sample("stdio.error.runtime.json"))}}}"));

        var result = await new EngineLink(() => engine.Client, Sample).Startup;

        Assert.Contains("the harvest store could not be opened", result.Error);
        Assert.False(result.Engine.IsLive);
    }

    [Fact]
    public async Task AnEngineThatFailsAfterHelloFallsBack()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            if (ScriptedEngine.MethodOf(line) == "engine.hello")
                e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{ScriptedEngine.HelloResult()}}}");
            else
                e.End();
        });

        var result = await new EngineLink(() => engine.Client, Sample).Startup;

        Assert.Contains("sample data", result.Error);
        Assert.False(result.Engine.IsLive);
    }

    [Fact]
    public async Task AnEngineThatDoesNotAnswerInTimeFallsBack()
    {
        using var engine = new ScriptedEngine();
        var link = new EngineLink(() => engine.Client, Sample, timeout: TimeSpan.FromMilliseconds(300));

        var result = await link.Startup;

        Assert.Contains("did not answer", result.Error);
        Assert.IsType<FakeEngineClient>(link.Client);
    }

    [Fact]
    public async Task SampleModeNeverOpensTheEngine()
    {
        var opened = false;
        var link = new EngineLink(() => { opened = true; return Sample(); }, Sample, sample: true);

        var result = await link.Startup;

        Assert.False(opened);
        Assert.Null(result.Error);
        Assert.NotEmpty(result.Inventory.Entries);
    }
}
