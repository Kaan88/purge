using System.Text.Json;
using Purge.App;
using Purge.Client.Model;
using Purge.Client.Stdio;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// What the Programs page reads from the engine (patches, sizes, icons, details, changes) against an engine played by
/// the test, and the list rules the page shares with its tests.
/// </summary>
public sealed class ProgramsPageTests
{
    private const string Hklm = "HKLM|64|";
    private const string Sid = "S-1-5-21-1-2-3-1001";

    private static string Row(string key, string name, string scope = "Machine", string? time = null) =>
        $"{{\"program_id\":\"{(key.StartsWith("HKU", StringComparison.Ordinal) ? key : Hklm + key)}\",\"name\":\"{name}\",\"publisher\":\"Vendor\",\"version\":\"1.0\",\"scope\":\"{scope}\"{(time is null ? "" : $",\"install_time\":{time}")}}}";

    private static string Notify(string method, string args) => $"{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\",\"params\":{args}}}";

    private static string Reply(ulong id, string result) => $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}";

    /// <summary>An engine that lists the given rows and patches (before the reply, as the real one does).</summary>
    private static ScriptedEngine Listing(string[] rows, string[] patches, bool patchesAfterReply = false) => new((line, e) =>
    {
        var id = ScriptedEngine.IdOf(line);
        switch (ScriptedEngine.MethodOf(line))
        {
            case "engine.hello":
                e.Send(Reply(id, ScriptedEngine.HelloResult()));
                break;
            case "programs.list":
                e.Send(Notify("programs.batch", $"{{\"request\":{id},\"rows\":[{string.Join(',', rows)}]}}"));
                var patch = Notify("programs.patch", $"{{\"request\":{id},\"patches\":[{string.Join(',', patches)}]}}");
                if (!patchesAfterReply) e.Send(patch);
                e.Send(Reply(id, $"{{\"count\":{rows.Length}}}"));
                if (patchesAfterReply) e.Send(patch);
                break;
        }
    });

    [Fact]
    public async Task Patches_fill_in_installer_msi_burn_appx_system_and_unnamed_before_the_list_returns()
    {
        string[] rows =
        [
            Row("Plain", "Plain App"), Row("Msi", "Msi App"), Row("Burn", "Burn Bundle"), Row("Child", "Burn Child"),
            Row("Store", "Store App"), Row("Sys", "System Thing"), Row("{AAAA}", "{AAAA}"),
        ];
        string[] patches =
        [
            $"{{\"program_id\":\"{Hklm}Plain\",\"installer\":\"Inno\"}}",
            $"{{\"program_id\":\"{Hklm}Msi\",\"installer\":\"Msi\",\"product_code\":\"{{PC}}\"}}",
            $"{{\"program_id\":\"{Hklm}Burn\",\"installer\":\"Burn\",\"bundle\":\"{Hklm}Burn\"}}",
            $"{{\"program_id\":\"{Hklm}Child\",\"installer\":\"Burn\",\"bundle\":\"{Hklm}Burn\",\"parent_key\":\"Burn\"}}",
            $"{{\"program_id\":\"{Hklm}Store\",\"appx\":true}}",
            $"{{\"program_id\":\"{Hklm}Sys\",\"system_component\":true}}",
            $"{{\"program_id\":\"{Hklm}{{AAAA}}\",\"unnamed\":true}}",
        ];
        using var engine = Listing(rows, patches);
        await using var client = engine.Client;

        var doc = await client.ListProgramsAsync();
        InventoryEntry E(string key) => doc.Entries.Single(x => x.ProgramId == Hklm + key);

        Assert.Equal(InstallerKind.Inno, E("Plain").InstallerKind);
        Assert.Equal(InstallerKind.Msi, E("Msi").InstallerKind);
        Assert.Equal("{PC}", E("Msi").ProductCode);
        Assert.True(E("Msi").Flags.WindowsInstaller);
        Assert.Equal(InstallerKind.Burn, E("Burn").InstallerKind);
        Assert.Null(E("Burn").Flags.ParentKey);
        Assert.Equal("Burn", E("Child").Flags.ParentKey);
        Assert.True(E("Store").Appx);
        Assert.False(E("Plain").Appx);
        Assert.True(E("Sys").Flags.SystemComponent);
        Assert.False(E("{AAAA}").Flags.HasDisplayName);

        // The tabs follow from the patched flags.
        var today = DateTime.Today;
        ProgramClass C(string key) => ProgramRules.Classify(E(key), null, today);
        Assert.True(C("Plain").IsApp);
        Assert.True(C("Store").IsApp);
        Assert.True(C("Burn").IsApp);
        Assert.True(C("Child").IsComponent && C("Child").IsChild && !C("Child").IsApp);
        Assert.True(C("Sys").IsComponent);
        Assert.True(C("{AAAA}").IsUnnamed && !C("{AAAA}").IsApp && !C("{AAAA}").IsComponent);
    }

    [Fact]
    public async Task A_row_without_a_patch_reads_as_a_named_app()
    {
        using var engine = Listing([Row("Plain", "Plain App")], []);
        await using var client = engine.Client;
        var entry = Assert.Single((await client.ListProgramsAsync()).Entries);
        Assert.True(ProgramRules.Classify(entry, null, DateTime.Today).IsApp);
        Assert.Equal(InstallerKind.Unknown, entry.InstallerKind);
    }

    [Fact]
    public async Task Patches_after_the_reply_come_through_the_event()
    {
        using var engine = Listing([Row("Sys", "System Thing")], [$"{{\"program_id\":\"{Hklm}Sys\",\"system_component\":true}}"], patchesAfterReply: true);
        await using var client = engine.Client;
        var late = new TaskCompletionSource<IReadOnlyList<Rpc.ProgramPatch>>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.ProgramsPatched += p => late.TrySetResult(p);

        var doc = await client.ListProgramsAsync();
        var patches = await late.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(Hklm + "Sys", Assert.Single(patches).ProgramId);
        Assert.True(Assert.Single(patches).SystemComponent);
        // Whether the list itself saw it depends on timing; the page applies the event either way.
        var merged = ProgramEntries.Apply(Assert.Single(doc.Entries), patches[0]);
        Assert.True(merged.Flags.SystemComponent);
    }

    [Fact]
    public async Task Sizes_arrive_in_batches_and_an_unmeasured_one_is_null()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            if (ScriptedEngine.MethodOf(line) != "programs.sizes") return;
            e.Send(Notify("size.ready", $"{{\"request\":{id},\"sizes\":[{{\"program_id\":\"{Hklm}A\",\"bytes\":345000000}}]}}"));
            e.Send(Notify("size.ready", $"{{\"request\":{id},\"sizes\":[{{\"program_id\":\"{Hklm}B\",\"bytes\":null}}]}}"));
            e.Send(Reply(id, "{\"count\":2}"));
        });
        await using var client = engine.Client;
        var seen = new List<(string Id, ulong? Bytes)>();
        await client.MeasureSizesAsync([Hklm + "A", Hklm + "B"], batch => { lock (seen) seen.AddRange(batch.Select(s => (s.ProgramId, s.Bytes))); });

        Assert.Equal([(Hklm + "A", (ulong?)345000000UL), (Hklm + "B", null)], seen);
        var request = JsonDocument.Parse(engine.Requests[0]).RootElement;
        Assert.Equal("programs.sizes", request.GetProperty("method").GetString());
        Assert.Equal([Hklm + "A", Hklm + "B"], request.GetProperty("params").GetProperty("program_ids").EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public async Task A_size_reply_that_comes_first_still_waits_for_its_batches()
    {
        using var engine = new ScriptedEngine((line, e) => e.Send(Reply(ScriptedEngine.IdOf(line), "{\"count\":1}")));
        await using var client = engine.Client;
        var got = 0;
        var call = client.MeasureSizesAsync([Hklm + "A"], b => Interlocked.Add(ref got, b.Count));
        await Task.Delay(150);
        Assert.False(call.IsCompleted);
        engine.Send(Notify("size.ready", $"{{\"request\":1,\"sizes\":[{{\"program_id\":\"{Hklm}A\",\"bytes\":1}}]}}"));
        await call;
        Assert.Equal(1, got);
    }

    [Fact]
    public async Task Icons_are_decoded_and_a_failed_or_malformed_one_has_no_pixels()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            if (ScriptedEngine.MethodOf(line) != "programs.icons") return;
            // 1 px = 4 bytes; "AAAA/w==" is 00 00 00 FF.
            e.Send(Notify("icon.batch", $"{{\"request\":{id},\"icons\":[" +
                $"{{\"program_id\":\"{Hklm}A\",\"px\":1,\"bgra\":\"AAAA/w==\"}}," +
                $"{{\"program_id\":\"{Hklm}B\",\"px\":24,\"bgra\":null}}," +
                $"{{\"program_id\":\"{Hklm}C\",\"px\":24,\"bgra\":\"AAAA/w==\"}}]}}"));
            e.Send(Reply(id, "{\"count\":3}"));
        });
        await using var client = engine.Client;
        var icons = new List<ProgramIcon>();
        await client.LoadIconsAsync([Hklm + "A", Hklm + "B", Hklm + "C"], 24, b => icons.AddRange(b));

        Assert.Equal([0, 0, 0, 255], icons[0].Bgra);
        Assert.Null(icons[1].Bgra);
        Assert.Null(icons[2].Bgra); // 24 px asked for, 4 bytes given
        Assert.Equal(24, JsonDocument.Parse(engine.Requests[0]).RootElement.GetProperty("params").GetProperty("px").GetInt32());
    }

    [Fact]
    public async Task Details_fill_in_the_uninstaller_and_a_gone_program_is_null()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            if (line.Contains("NoSuch", StringComparison.Ordinal))
                e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32000,\"message\":\"gone\",\"data\":{{\"kind\":\"gone\",\"id\":\"scan\"}}}}}}");
            else
                e.Send(Reply(id, ScriptedEngine.Compact(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "stdio.programs.get.result.json")))));
        });
        await using var client = engine.Client;

        var details = await client.GetProgramAsync("HKLM|64|Git_is1");
        Assert.NotNull(details);
        var raw = new Rpc.ProgramRow { ProgramId = "HKLM|64|Git_is1", Name = "Git", Scope = Rpc.InstallScope.Machine };
        var entry = ProgramEntries.Apply(ProgramEntries.FromRow(raw), details!);
        Assert.Equal(@"C:\Program Files\Git\", entry.InstallLocation);
        Assert.Equal("\"C:\\Program Files\\Git\\unins000.exe\"", entry.UninstallString);
        Assert.Equal("\"C:\\Program Files\\Git\\unins000.exe\" /SILENT", entry.QuietUninstallString);
        Assert.Equal(InstallerKind.Inno, entry.InstallerKind);
        Assert.Equal(WritableBy.Admin, entry.WritableBy);

        Assert.Null(await client.GetProgramAsync("HKLM|64|NoSuch"));
    }

    [Fact]
    public async Task An_error_with_data_the_client_does_not_know_is_an_error_and_not_the_end_of_the_link()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            if (ScriptedEngine.MethodOf(line) == "programs.get")
                e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32000,\"message\":\"odd\",\"data\":{{\"kind\":\"future_kind\",\"id\":\"not_an_id_kind\"}}}}}}");
            else e.Send(Reply(id, ScriptedEngine.HelloResult()));
        });
        await using var client = engine.Client;
        var error = await Assert.ThrowsAsync<EngineRpcException>(() => client.GetProgramAsync("HKLM|64|X"));
        Assert.Equal("future_kind", error.Kind);
        Assert.Equal("odd", error.Message);
        Assert.Equal("0.1.0", (await client.HelloAsync()).Version);
    }

    [Fact]
    public async Task The_changes_are_asked_before_the_list_and_never_fault_the_start()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            switch (ScriptedEngine.MethodOf(line))
            {
                case "engine.hello": e.Send(Reply(id, ScriptedEngine.HelloResult())); break;
                case "inventory.changes":
                    e.Send(Reply(id, $"{{\"appeared\":[],\"disappeared\":[{{\"program_id\":\"{Hklm}Gone\",\"name\":\"Gone App\"}}]}}"));
                    break;
                case "programs.list":
                    e.Send(Notify("programs.batch", $"{{\"request\":{id},\"rows\":[{Row("Alpha", "Alpha")}]}}"));
                    e.Send(Reply(id, "{\"count\":1}"));
                    break;
            }
        });
        var result = await new EngineLink(() => engine.Client, () => new FakeEngineClient(), sample: false).Startup;

        Assert.Null(result.Error);
        // The engine stores the new list when a list ends, so the changes request has to be written first.
        lock (engine.Requests)
            Assert.Equal(["engine.hello", "inventory.changes", "programs.list"], engine.Requests.Select(ScriptedEngine.MethodOf));
        var changes = await result.Changes!;
        Assert.Equal("Gone App", Assert.Single(changes!.Disappeared).Name);
        Assert.Empty(changes.Appeared);
    }

    [Fact]
    public async Task An_engine_that_cannot_answer_the_changes_still_starts()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            switch (ScriptedEngine.MethodOf(line))
            {
                case "engine.hello": e.Send(Reply(id, ScriptedEngine.HelloResult())); break;
                case "inventory.changes":
                    e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{ScriptedEngine.Compact(ScriptedEngine.Sample("stdio.error.runtime.json"))}}}");
                    break;
                case "programs.list":
                    e.Send(Notify("programs.batch", $"{{\"request\":{id},\"rows\":[{Row("Alpha", "Alpha")}]}}"));
                    e.Send(Reply(id, "{\"count\":1}"));
                    break;
            }
        });
        var result = await new EngineLink(() => engine.Client, () => new FakeEngineClient(), sample: false).Startup;
        Assert.Null(result.Error);
        Assert.Single(result.Inventory.Entries);
        Assert.Null(await result.Changes!);
    }

    [Fact]
    public async Task The_stdio_client_can_start_an_uninstall_through_the_broker()
    {
        using var engine = ScriptedEngine.Healthy();
        await using var client = engine.Client;
        // The engine is live, so the Uninstall click is enabled: it starts the broker, not the sample preview.
        Assert.True(client.CanChangePc);
        var scan = await Assert.ThrowsAsync<InvalidOperationException>(() => client.ScanAsync("x", "x", ScanKind.ScanOnly));
        Assert.StartsWith("Internal error", scan.Message, StringComparison.Ordinal);
    }

    // ---- icons ---------------------------------------------------------------------------------------------

    private sealed class AtlasFile : IDisposable
    {
        public string Directory { get; } = Path.Combine(Path.GetTempPath(), "purge-s1-" + Guid.NewGuid().ToString("N"));

        public IconAtlas Open() => new(Path.Combine(Directory, "icons.atlas"));

        public void Dispose()
        {
            try { System.IO.Directory.Delete(Directory, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>An engine that answers <c>programs.icons</c> with an icon (all 0x40) for every id except those named "bad".</summary>
    private static ScriptedEngine IconEngine() => new((line, e) =>
    {
        if (ScriptedEngine.MethodOf(line) != "programs.icons") return;
        var id = ScriptedEngine.IdOf(line);
        var ids = JsonDocument.Parse(line).RootElement.GetProperty("params").GetProperty("program_ids").EnumerateArray().Select(x => x.GetString()!).ToList();
        var pixels = Convert.ToBase64String(Enumerable.Repeat((byte)0x40, 24 * 24 * 4).ToArray());
        var icons = string.Join(',', ids.Select(p => $"{{\"program_id\":\"{p}\",\"px\":24,\"bgra\":{(p.Contains("bad", StringComparison.Ordinal) ? "null" : $"\"{pixels}\"")}}}"));
        e.Send(Notify("icon.batch", $"{{\"request\":{id},\"icons\":[{icons}]}}"));
        e.Send(Reply(id, $"{{\"count\":{ids.Count}}}"));
    });

    [Fact]
    public async Task Icons_come_from_the_atlas_first_and_only_the_misses_go_to_the_engine()
    {
        using var files = new AtlasFile();
        using var engine = IconEngine();
        await using var client = engine.Client;
        var atlas = files.Open();
        atlas.Put(IconLoader.AtlasPath(Hklm + "Cached"), IconLoader.Stamp("1.0", 5), 24, Enumerable.Repeat((byte)0x11, 24 * 24 * 4).ToArray());

        var delivered = new List<string>();
        var fetched = await IconLoader.LoadAsync(client, atlas,
            [(Hklm + "New", IconLoader.Stamp("1.0", 5)), (Hklm + "Cached", IconLoader.Stamp("1.0", 5)), (Hklm + "bad", IconLoader.Stamp("1.0", 5))],
            (id, icon) => { lock (delivered) delivered.Add(id); Assert.Equal(24, icon.Px); }, CancellationToken.None);

        // The cached icon is delivered before any request; the failed one is never delivered (placeholder tile).
        Assert.Equal([Hklm + "Cached", Hklm + "New"], delivered);
        Assert.Equal(1, fetched);
        var asked = JsonDocument.Parse(Assert.Single(engine.Requests)).RootElement.GetProperty("params").GetProperty("program_ids").EnumerateArray().Select(x => x.GetString());
        Assert.Equal([Hklm + "New", Hklm + "bad"], asked);

        // The atlas file now holds the fetched icon: a fresh atlas serves it, and a changed version asks again.
        var reopened = files.Open();
        Assert.True(reopened.TryGet(IconLoader.AtlasPath(Hklm + "New"), IconLoader.Stamp("1.0", 5), out _));
        Assert.False(reopened.TryGet(IconLoader.AtlasPath(Hklm + "New"), IconLoader.Stamp("2.0", 5), out _));
    }

    [Fact]
    public async Task Icons_are_asked_in_chunks_in_the_order_given()
    {
        using var files = new AtlasFile();
        using var engine = IconEngine();
        await using var client = engine.Client;
        var order = Enumerable.Range(0, IconLoader.Chunk * 2 + 5).Select(i => ($"{Hklm}p{i:D3}", 1L)).ToList();

        await IconLoader.LoadAsync(client, files.Open(), order, (_, _) => { }, CancellationToken.None);

        var chunks = engine.Requests.Select(l => JsonDocument.Parse(l).RootElement.GetProperty("params").GetProperty("program_ids").GetArrayLength()).ToList();
        Assert.Equal([IconLoader.Chunk, IconLoader.Chunk, 5], chunks);
        var first = JsonDocument.Parse(engine.Requests[0]).RootElement.GetProperty("params").GetProperty("program_ids")[0].GetString();
        Assert.Equal(order[0].Item1, first);
    }

    [Fact]
    public async Task Answered_names_cached_ids_and_each_ended_chunk_after_their_icons()
    {
        using var files = new AtlasFile();
        using var engine = IconEngine();
        await using var client = engine.Client;
        var atlas = files.Open();
        atlas.Put(IconLoader.AtlasPath(Hklm + "Cached"), 1L, 24, Enumerable.Repeat((byte)0x11, 24 * 24 * 4).ToArray());
        var events = new List<string>();

        await IconLoader.LoadAsync(client, atlas, [(Hklm + "Cached", 1L), (Hklm + "New", 1L), (Hklm + "bad", 1L)],
            (id, _) => { lock (events) events.Add("icon " + id); }, CancellationToken.None,
            ids => { lock (events) events.Add("answered " + string.Join(",", ids)); });

        // A program the engine has no icon for ("bad") is still answered: it keeps its tile, and the screenful is settled.
        Assert.Equal(["icon " + Hklm + "Cached", "answered " + Hklm + "Cached", "icon " + Hklm + "New", "answered " + Hklm + "New," + Hklm + "bad"], events);
    }

    [Fact]
    public async Task An_engine_that_ends_leaves_the_placeholders_and_does_not_throw()
    {
        using var files = new AtlasFile();
        using var engine = new ScriptedEngine((_, e) => e.End());
        await using var client = engine.Client;
        var delivered = 0;
        var answered = 0;
        var fetched = await IconLoader.LoadAsync(client, files.Open(), [(Hklm + "A", 1L)], (_, _) => delivered++, CancellationToken.None,
            _ => answered++);
        Assert.Equal(0, fetched);
        Assert.Equal(0, delivered);
        // A failed chunk is not settled: the bench reports no icons_visible rather than a time for tiles.
        Assert.Equal(0, answered);
    }

    [Fact]
    public void Premultiplying_scales_the_colour_by_the_alpha()
    {
        var result = IconLoader.Premultiply([200, 100, 50, 128, 10, 20, 30, 255, 99, 99, 99, 0]);
        Assert.Equal([100, 50, 25, 128, 10, 20, 30, 255, 0, 0, 0, 0], result);
    }

    [Fact]
    public void The_atlas_stamp_is_stable_and_follows_version_and_install_time()
    {
        Assert.Equal(IconLoader.Stamp("1.0", 7), IconLoader.Stamp("1.0", 7));
        Assert.NotEqual(IconLoader.Stamp("1.0", 7), IconLoader.Stamp("1.1", 7));
        Assert.NotEqual(IconLoader.Stamp("1.0", 7), IconLoader.Stamp("1.0", 8));
        Assert.NotEqual(IconLoader.Stamp(null, null), IconLoader.Stamp("", 0));
    }

    // ---- list rules ----------------------------------------------------------------------------------------

    private static InventoryEntry Entry(string key, string name, string? parent = null, bool system = false, bool named = true, string? time = null)
    {
        var raw = new Rpc.ProgramRow { ProgramId = Hklm + key, Name = name, Publisher = "Vendor", Version = "1.0", Scope = Rpc.InstallScope.Machine };
        var entry = ProgramEntries.FromRow(raw);
        return entry with { Flags = entry.Flags with { ParentKey = parent, SystemComponent = system, HasDisplayName = named } };
    }

    [Fact]
    public void Children_stay_under_their_parent_in_every_sort_and_an_orphan_sorts_alone()
    {
        var parent = Entry("Zeta", "Zeta Suite");
        var child = Entry("Alpha-Update", "Alpha Update", parent: "Zeta");
        var other = Entry("Beta", "Beta");
        var orphan = Entry("Orphan", "Aardvark", parent: "Missing");
        var all = new[] { child, other, parent, orphan };

        var byName = ProgramRules.Order(all, e => e, e => e.DisplayName, descending: false).Select(e => e.DisplayName).ToList();
        Assert.Equal(["Aardvark", "Beta", "Zeta Suite", "Alpha Update"], byName);

        var descending = ProgramRules.Order(all, e => e, e => e.DisplayName, descending: true).Select(e => e.DisplayName).ToList();
        Assert.Equal(["Zeta Suite", "Alpha Update", "Beta", "Aardvark"], descending);

        // A tab or search that hides the parent shows the child like any other row.
        var shown = new[] { child, other };
        Assert.Equal(["Alpha Update", "Beta"], ProgramRules.Order(shown, e => e, e => e.DisplayName, false).Select(e => e.DisplayName));
    }

    [Fact]
    public void Search_reads_name_publisher_version_and_folder()
    {
        var entry = Entry("A", "Firefox") with { InstallLocation = @"C:\Apps\Fox" };
        Assert.True(ProgramRules.Matches(entry, ""));
        Assert.True(ProgramRules.Matches(entry, "fire"));
        Assert.True(ProgramRules.Matches(entry, "VENDOR"));
        Assert.True(ProgramRules.Matches(entry, "1.0"));
        Assert.True(ProgramRules.Matches(entry, "apps\\fox"));
        Assert.False(ProgramRules.Matches(entry, "chrome"));
    }

    [Fact]
    public void Recent_is_an_app_installed_within_fourteen_days()
    {
        var app = Entry("A", "A");
        var today = new DateTime(2026, 11, 21);
        Assert.True(ProgramRules.Classify(app, today.AddDays(-14), today).IsRecent);
        Assert.False(ProgramRules.Classify(app, today.AddDays(-15), today).IsRecent);
        Assert.False(ProgramRules.Classify(app, null, today).IsRecent);
        Assert.False(ProgramRules.Classify(Entry("S", "S", system: true), today, today).IsRecent);
    }

    [Fact]
    public void A_damaged_install_time_is_no_date()
    {
        var entry = Entry("A", "A") with { InstallTimeEvidence = [new InstallTimeEvidence(InstallTimeSource.ArpInstallDate, ulong.MaxValue)] };
        Assert.Null(ProgramRules.InstallDate(entry));
        var good = entry with { InstallTimeEvidence = [new InstallTimeEvidence(InstallTimeSource.KeyLastWrite, 134076753020000000UL)] };
        Assert.NotNull(ProgramRules.InstallDate(good));
    }

    [Fact]
    public void Sizes_read_in_the_unit_that_fits()
    {
        Assert.Equal("0 B", ProgramRules.FormatSize(0));
        Assert.Contains("MB", ProgramRules.FormatSize(5 * 1024 * 1024));
        Assert.Contains("GB", ProgramRules.FormatSize(3L * 1024 * 1024 * 1024));
    }

    [Fact]
    public async Task The_sample_client_lists_changes_and_sizes_for_the_sample_page()
    {
        await using var fake = new FakeEngineClient();
        Assert.False(fake.CanChangePc);
        Assert.NotEmpty((await fake.GetInventoryChangesAsync()).Disappeared);
        var doc = await fake.ListProgramsAsync();
        var sizes = new List<Rpc.ProgramSize>();
        await fake.MeasureSizesAsync(doc.Entries.Select(e => e.ProgramId).ToList(), sizes.AddRange);
        Assert.NotEmpty(sizes);
    }
}
