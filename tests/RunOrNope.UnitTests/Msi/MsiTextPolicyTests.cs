using System.Text;
using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.UnitTests.Msi;

public sealed class MsiTextPolicyTests
{
    [Fact]
    public void Default_limits_are_the_approved_bounded_values()
    {
        var limits = MsiAnalysisLimits.Default;

        limits.MaxTables.Should().Be(256);
        limits.MaxRowsPerTable.Should().Be(8_192);
        limits.MaxTotalRows.Should().Be(32_768);
        limits.MaxFieldsPerRecord.Should().Be(32);
        limits.MaxTextScalars.Should().Be(12_288);
        limits.MaxDirectoryDepth.Should().Be(256);
    }

    [Theory]
    [InlineData(nameof(MsiAnalysisLimits.MaxTables))]
    [InlineData(nameof(MsiAnalysisLimits.MaxRowsPerTable))]
    [InlineData(nameof(MsiAnalysisLimits.MaxTotalRows))]
    [InlineData(nameof(MsiAnalysisLimits.MaxFieldsPerRecord))]
    [InlineData(nameof(MsiAnalysisLimits.MaxTextScalars))]
    [InlineData(nameof(MsiAnalysisLimits.MaxDirectoryDepth))]
    public void Validate_rejects_each_non_positive_limit(string propertyName)
    {
        var limits = propertyName switch
        {
            nameof(MsiAnalysisLimits.MaxTables) => new MsiAnalysisLimits { MaxTables = 0 },
            nameof(MsiAnalysisLimits.MaxRowsPerTable) => new MsiAnalysisLimits { MaxRowsPerTable = -1 },
            nameof(MsiAnalysisLimits.MaxTotalRows) => new MsiAnalysisLimits { MaxTotalRows = 0 },
            nameof(MsiAnalysisLimits.MaxFieldsPerRecord) => new MsiAnalysisLimits { MaxFieldsPerRecord = -1 },
            nameof(MsiAnalysisLimits.MaxTextScalars) => new MsiAnalysisLimits { MaxTextScalars = 0 },
            nameof(MsiAnalysisLimits.MaxDirectoryDepth) => new MsiAnalysisLimits { MaxDirectoryDepth = -1 },
            _ => throw new ArgumentOutOfRangeException(nameof(propertyName)),
        };

        var action = limits.Validate;

        action.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be(propertyName);
    }

    [Fact]
    public void Sanitize_neutralizes_c0_c1_and_bidirectional_controls()
    {
        var result = MsiTextPolicy.Sanitize("a\0b\u0085c\u061Cd\u202Ee\u2066f", 32);

        result.DisplayText.Should().Be("a.b.c.d.e.f");
        result.WasNeutralized.Should().BeTrue();
        result.WasTruncated.Should().BeFalse();
        result.OriginalScalars.Should().Be(11);
    }

    [Fact]
    public void Sanitize_neutralizes_lone_surrogates()
    {
        var high = MsiTextPolicy.Sanitize(string.Concat("x", (char)0xd800, "y"), 8);
        var low = MsiTextPolicy.Sanitize(string.Concat("x", (char)0xdc00, "y"), 8);

        high.DisplayText.Should().Be("x.y");
        high.WasNeutralized.Should().BeTrue();
        high.OriginalScalars.Should().Be(3);
        low.DisplayText.Should().Be("x.y");
        low.WasNeutralized.Should().BeTrue();
        low.OriginalScalars.Should().Be(3);
    }

    [Fact]
    public void Sanitize_preserves_a_valid_surrogate_pair_as_one_scalar()
    {
        var result = MsiTextPolicy.Sanitize("a\U0001F680b", 3);

        result.DisplayText.Should().Be("a\U0001F680b");
        result.WasNeutralized.Should().BeFalse();
        result.WasTruncated.Should().BeFalse();
        result.OriginalScalars.Should().Be(3);
    }

    [Fact]
    public void Sanitize_keeps_exactly_12288_scalars()
    {
        var result = MsiTextPolicy.Sanitize(new string('a', 12_288), 12_288);

        result.DisplayText.Length.Should().Be(12_288);
        result.WasTruncated.Should().BeFalse();
        result.OriginalScalars.Should().Be(12_288);
    }

    [Fact]
    public void Sanitize_truncates_12289_scalars_at_the_ceiling()
    {
        var result = MsiTextPolicy.Sanitize(new string('a', 12_289), 12_288);

        result.DisplayText.Length.Should().Be(12_288);
        result.WasTruncated.Should().BeTrue();
        result.OriginalScalars.Should().Be(12_289);
    }

    [Fact]
    public void Sanitize_never_splits_a_valid_surrogate_pair_at_the_limit()
    {
        var result = MsiTextPolicy.Sanitize("a\U0001F680b", 2);

        result.DisplayText.Should().Be("a\U0001F680");
        result.WasTruncated.Should().BeTrue();
        result.OriginalScalars.Should().Be(3);
        IsWellFormedUnicode(result.DisplayText).Should().BeTrue();
    }

    [Fact]
    public void Sanitize_rejects_a_non_positive_ceiling()
    {
        var action = () => MsiTextPolicy.Sanitize("text", 0);

        action.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be("maxScalars");
    }

    private static bool IsWellFormedUnicode(string value)
    {
        foreach (var rune in value.EnumerateRunes())
        {
            _ = rune.Value;
        }

        return true;
    }
}
