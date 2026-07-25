using AwesomeAssertions;
using RunOrNope.Analyzers.Pe;
using Xunit;

namespace RunOrNope.UnitTests.Pe;

public sealed class ClrMetadataAnalyzerTests
{
    [Fact]
    public void Analyze_NativeSyntheticPe_ReturnsNotManaged()
    {
        var bytes = PeFixture.Create();
        var result = ClrMetadataAnalyzer.Analyze(new MemoryStream(bytes), bytes.Length, new ClrAnalysisLimits());
        result.IsManaged.Should().BeFalse();
        result.Methods.Should().BeEmpty();
    }

    [Fact]
    public void Analyze_CurrentTestAssembly_UsesMetadataWithoutLoadingTarget()
    {
        using var stream = File.OpenRead(typeof(ClrMetadataAnalyzerTests).Assembly.Location);
        var result = ClrMetadataAnalyzer.Analyze(stream, stream.Length, new ClrAnalysisLimits(MaxMethods: 10_000));
        result.IsManaged.Should().BeTrue();
        result.Methods.Should().Contain(m => m.Name == nameof(Analyze_CurrentTestAssembly_UsesMetadataWithoutLoadingTarget));
        result.AssemblyReferences.Should().NotBeEmpty();
    }

    [Fact]
    public void Analyze_MethodLimit_SetsTruncated()
    {
        using var stream = File.OpenRead(typeof(ClrMetadataAnalyzerTests).Assembly.Location);
        var result = ClrMetadataAnalyzer.Analyze(stream, stream.Length, new ClrAnalysisLimits(MaxMethods: 1));
        result.TruncatedByPolicy.Should().BeTrue();
        result.Methods.Should().HaveCount(1);
    }
}
