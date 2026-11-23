using Purge.Client.Model;
using Purge.Client.Pipeline;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// "Uninstall N" on the Programs page: the ticked programs queued for the Uninstall pipeline one after another, and the
/// program list's columns at narrow widths.
/// </summary>
public sealed class UninstallQueueTests
{
    private static readonly UninstallTarget A = new("HKLM|64|A", "Alpha");
    private static readonly UninstallTarget B = new("HKLM|64|B", "Beta");
    private static readonly UninstallTarget C = new("HKLM|64|C", "Gamma");

    [Fact]
    public void Three_ticked_programs_run_in_order_and_say_where_they_are()
    {
        var queue = new UninstallQueue();

        Assert.Equal(A, queue.Start([A, B, C]));
        Assert.Equal("1 of 3", queue.PositionText);
        Assert.Equal(B, queue.Next);

        Assert.Equal(B, queue.Advance());
        Assert.Equal("2 of 3", queue.PositionText);
        Assert.Equal(C, queue.Next);

        Assert.Equal(C, queue.Advance());
        Assert.Equal("3 of 3", queue.PositionText);
        Assert.Null(queue.Next);

        Assert.Null(queue.Advance());
        Assert.Null(queue.Current);
        Assert.Equal(0, queue.Count);
    }

    [Fact]
    public void A_skipped_program_is_not_run_and_no_longer_counted()
    {
        var queue = new UninstallQueue();
        queue.Start([A, B, C]);

        Assert.Equal(B, queue.SkipNext());

        Assert.Equal(C, queue.Next);
        Assert.Equal("1 of 2", queue.PositionText);
        Assert.Equal(C, queue.Advance());
        Assert.Null(queue.SkipNext());
    }

    [Fact]
    public void One_program_is_no_batch_and_a_repeated_one_runs_once()
    {
        var queue = new UninstallQueue();

        queue.Start([A]);
        Assert.False(queue.IsBatch);
        Assert.Null(queue.PositionText);
        Assert.Null(queue.Next);

        queue.Start([A, A, B]);
        Assert.Equal(2, queue.Count);
        Assert.Null(new UninstallQueue().Start([]));
    }

    [Fact]
    public void A_new_click_replaces_the_queue()
    {
        var queue = new UninstallQueue();
        queue.Start([A, B]);
        queue.Start([C]);

        Assert.Equal(C, queue.Current);
        Assert.Null(queue.Next);
    }

    [Theory]
    [InlineData(2000, true, true, true)]
    [InlineData(ProgramRules.ListChrome + ProgramRules.MinNameWidth + 342, true, true, true)]
    [InlineData(ProgramRules.ListChrome + ProgramRules.MinNameWidth + 341, true, true, false)]
    [InlineData(ProgramRules.ListChrome + ProgramRules.MinNameWidth + 249, true, false, false)]
    [InlineData(ProgramRules.ListChrome + ProgramRules.MinNameWidth + 99, false, false, false)]
    [InlineData(120, false, false, false)]
    public void Narrow_lists_drop_installed_then_leftovers_then_size_and_keep_the_name(double width, bool size, bool leftovers, bool installed)
    {
        Assert.Equal(new ProgramRules.ListColumns(size, leftovers, installed), ProgramRules.FitColumns(width));
    }
}
