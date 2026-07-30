using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.UnitTests.Msi;

public sealed class MsiDirectoryResolverTests
{
    [Fact]
    public void Resolve_returns_a_plain_display_path_without_filesystem_interpretation()
    {
        var rows = Rows(
            new MsiDirectoryRow("TARGETDIR", null, "root"),
            new MsiDirectoryRow("INSTALLDIR", "TARGETDIR", "invoice\u202Etxt.exe"));

        var result = MsiDirectoryResolver.Resolve("INSTALLDIR", rows, MsiAnalysisLimits.Default);

        result.DisplayPath.Should().Be("root\\invoice.txt.exe");
        result.Status.Should().Be(MsiDirectoryStatus.Complete);
    }

    [Fact]
    public void Resolve_reports_a_self_parent()
    {
        var rows = Rows(new MsiDirectoryRow("A", "A", "alpha"));

        var result = MsiDirectoryResolver.Resolve("A", rows, MsiAnalysisLimits.Default);

        result.Status.Should().Be(MsiDirectoryStatus.SelfParent);
    }

    [Fact]
    public void Resolve_reports_a_two_node_cycle()
    {
        var rows = Rows(
            new MsiDirectoryRow("A", "B", "alpha"),
            new MsiDirectoryRow("B", "A", "bravo"));

        var result = MsiDirectoryResolver.Resolve("A", rows, MsiAnalysisLimits.Default);

        result.Status.Should().Be(MsiDirectoryStatus.Cycle);
    }

    [Fact]
    public void Resolve_reports_a_longer_cycle()
    {
        var rows = Rows(
            new MsiDirectoryRow("A", "B", "alpha"),
            new MsiDirectoryRow("B", "C", "bravo"),
            new MsiDirectoryRow("C", "A", "charlie"));

        var result = MsiDirectoryResolver.Resolve("A", rows, MsiAnalysisLimits.Default);

        result.Status.Should().Be(MsiDirectoryStatus.Cycle);
    }

    [Fact]
    public void Resolve_reports_an_orphan_parent()
    {
        var rows = Rows(new MsiDirectoryRow("A", "MISSING", "alpha"));

        var result = MsiDirectoryResolver.Resolve("A", rows, MsiAnalysisLimits.Default);

        result.Status.Should().Be(MsiDirectoryStatus.Orphan);
    }

    [Fact]
    public void Resolve_allows_a_path_at_depth_256()
    {
        var result = MsiDirectoryResolver.Resolve("D256", LinearRows(256), MsiAnalysisLimits.Default);

        result.Status.Should().Be(MsiDirectoryStatus.Complete);
    }

    [Fact]
    public void Resolve_reports_a_path_at_depth_257()
    {
        var result = MsiDirectoryResolver.Resolve("D257", LinearRows(257), MsiAnalysisLimits.Default);

        result.Status.Should().Be(MsiDirectoryStatus.DepthExceeded);
    }

    [Fact]
    public void Resolve_bounds_the_aggregate_display_path()
    {
        var limits = new MsiAnalysisLimits { MaxTextScalars = 5 };
        var rows = Rows(
            new MsiDirectoryRow("ROOT", null, "abc"),
            new MsiDirectoryRow("CHILD", "ROOT", "def"));

        var result = MsiDirectoryResolver.Resolve("CHILD", rows, limits);

        result.Status.Should().Be(MsiDirectoryStatus.LengthExceeded);
        ScalarCount(result.DisplayPath).Should().BeLessThanOrEqualTo(5);
    }

    [Fact]
    public void Resolve_validates_limits_before_walking_rows()
    {
        var action = () => MsiDirectoryResolver.Resolve(
            "missing", Rows(), new MsiAnalysisLimits { MaxDirectoryDepth = 0 });

        action.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be(nameof(MsiAnalysisLimits.MaxDirectoryDepth));
    }

    private static Dictionary<string, MsiDirectoryRow> Rows(params MsiDirectoryRow[] rows) =>
        rows.ToDictionary(row => row.Key, StringComparer.Ordinal);

    private static Dictionary<string, MsiDirectoryRow> LinearRows(int depth)
    {
        var rows = new Dictionary<string, MsiDirectoryRow>(StringComparer.Ordinal);
        for (var index = 1; index <= depth; index++)
        {
            var key = "D" + index;
            var parent = index == 1 ? null : "D" + (index - 1);
            rows.Add(key, new MsiDirectoryRow(key, parent, "d"));
        }

        return rows;
    }

    private static int ScalarCount(string value) => value.EnumerateRunes().Count();
}
