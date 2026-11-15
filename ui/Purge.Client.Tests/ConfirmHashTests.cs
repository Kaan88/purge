using Purge.Client.Cli;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>The confirm recipe against the Rust side (crates/purge-exec/src/plan_in/tests.rs).</summary>
public sealed class ConfirmHashTests
{
    /// <summary><c>confirm_recipe_fixed_vector</c>.</summary>
    [Fact]
    public void FixedVectorOfTheExecutor()
    {
        Assert.Equal("2f2400bd148f06ab24831566736224e0608bbd75547ce869857bd1f5d3d53901",
            ConfirmHash.Selection(["c-2", "c-10", "c-1", "c-2"]));
        Assert.Equal("005cd48e39de487e9536e5ab5ff917582763f70d7c04a5614db1d7f57aa43788",
            ConfirmHash.Confirm("10e9da8690be9214c32b5379a6688586b78ff5b221b3877b2f59cfefc3f149b2", ["c-2", "c-10", "c-1", "c-2"]));
    }

    /// <summary>The selection hash of the sandbox-dev round trip's report (Samples\rig-report.json).</summary>
    [Fact]
    public void SelectionOfTheRoundTripReport() =>
        Assert.Equal("a7a45c77edb1657b77f372bb3465bf034582a7e4e8c689d623829033c20d90a7",
            ConfirmHash.Selection(["single", "files.dir"]));

    /// <summary><c>selection_hash_ignores_order_repeats_and_empty_ids</c> and the empty selection.</summary>
    [Fact]
    public void OrderRepeatsAndEmptyIdsDoNotCount()
    {
        Assert.Equal(ConfirmHash.Selection(["b", "a"]), ConfirmHash.Selection(["a", "b", "a", ""]));
        Assert.NotEqual(ConfirmHash.Selection(["a"]), ConfirmHash.Selection(["a", "b"]));
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ConfirmHash.Selection([]));
    }

    /// <summary><c>selection_hash_sorts_by_utf16_code_unit</c>: U+1F600 sorts before U+FF5E.</summary>
    [Fact]
    public void SortsByUtf16CodeUnit() =>
        Assert.Equal(
            Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("\U0001F600\n～"))),
            ConfirmHash.Selection(["～", "\U0001F600"]));

    [Fact]
    public void PlanHashCaseDoesNotMatter() =>
        Assert.Equal(ConfirmHash.Confirm("ABCDEF", ["x"]), ConfirmHash.Confirm("abcdef", ["x"]));
}
