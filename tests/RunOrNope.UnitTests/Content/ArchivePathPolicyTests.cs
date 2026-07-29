using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.UnitTests.Content;

public sealed class ArchivePathPolicyTests
{
    [Theory]
    [InlineData("../../evil.dll")]
    [InlineData("..\\..\\evil.dll")]
    [InlineData("a/../../../evil.dll")]
    [InlineData("nested/deep/../../../../evil.dll")]
    public void Classify_FlagsTraversalUnderEitherSeparator(string name) =>
        ArchivePathPolicy.Classify(name).Issues.Should().Contain(PathIssue.Traversal);

    [Theory]
    [InlineData("C:\\Windows\\System32\\evil.dll")]
    [InlineData("/etc/passwd")]
    [InlineData("\\\\server\\share\\evil.dll")]
    [InlineData("\\Windows\\evil.dll")]
    public void Classify_FlagsRootedPaths(string name) =>
        ArchivePathPolicy.Classify(name).Issues.Should().Contain(PathIssue.Rooted);

    [Theory]
    [InlineData("CON")]
    [InlineData("NUL.txt")]
    [InlineData("COM1")]
    [InlineData("LPT9.dll")]
    [InlineData("sub/aux.dat")]
    public void Classify_FlagsReservedDeviceNamesWithAndWithoutExtensions(string name) =>
        ArchivePathPolicy.Classify(name).Issues.Should().Contain(PathIssue.DeviceName);

    [Fact]
    public void Classify_FlagsAlternateDataStreamSeparator() =>
        ArchivePathPolicy.Classify("file.txt:hidden").Issues.Should().Contain(PathIssue.AlternateDataStream);

    [Theory]
    [InlineData("trailing.")]
    [InlineData("trailing ")]
    public void Classify_FlagsTrailingDotOrSpace(string name) =>
        ArchivePathPolicy.Classify(name).Issues.Should().Contain(PathIssue.TrailingDotOrSpace);

    [Fact]
    public void Classify_FlagsEmbeddedNullByte()
    {
        var verdict = ArchivePathPolicy.Classify("safe\0.dll");

        verdict.Issues.Should().Contain(PathIssue.ControlCharacter);
        verdict.DisplayName.Should().NotContain("\0");
    }

    [Fact]
    public void Classify_NeutralisesBidirectionalOverrideInDisplayName()
    {
        // The classic extension-spoof: an override renders "exe.txt" as "txt.exe".
        var verdict = ArchivePathPolicy.Classify("invoice\u202Etxt.exe");

        verdict.Issues.Should().Contain(PathIssue.ControlCharacter);
        verdict.DisplayName.Should().NotContain("\u202E");
        // A display name must survive the contract's own string validation.
        Validate(verdict.DisplayName);
    }

    [Fact]
    public void Classify_BoundsAnOverlongName()
    {
        var verdict = ArchivePathPolicy.Classify(new string('a', ContractLimits.MaxStringLength + 100));

        verdict.Issues.Should().Contain(PathIssue.TooLong);
        verdict.DisplayName.Length.Should().BeLessThanOrEqualTo(ArchivePathPolicy.MaxDisplayLength);
        Validate(verdict.DisplayName);
    }

    [Fact]
    public void Classify_EmptyNameIsReportableRatherThanBlank()
    {
        var verdict = ArchivePathPolicy.Classify("");

        verdict.Issues.Should().Contain(PathIssue.Empty);
        verdict.DisplayName.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Classify_LoneSurrogateDoesNotProduceMalformedUnicode()
    {
        // A lone high surrogate would fail the contract's malformed-Unicode check.
        Validate(ArchivePathPolicy.Classify("bad\ud800name.dll").DisplayName);
    }

    [Fact]
    public void Classify_OrdinaryNameIsNotFlagged()
    {
        var verdict = ArchivePathPolicy.Classify("lib/native/helper.dll");

        verdict.IsHostile.Should().BeFalse();
        verdict.DisplayName.Should().Be("lib/native/helper.dll");
    }

    /// <summary>A display name is reported, so it must pass the contract's string rules.</summary>
    private static void Validate(string displayName)
    {
        var artifact = new ArtifactNode(
            "art-0001", displayName, new string('a', 64), 1,
            ArtifactCompleteness.Complete, ["root"]);
        var root = new ArtifactNode(
            "root", string.Empty, new string('b', 64), 1, ArtifactCompleteness.Complete, []);
        ContractValidator.Validate(new ScanResult(
            string.Empty, AnalysisStatus.Complete, ArtifactCompleteness.Complete,
            [root, artifact], [], [], []));
    }
}
