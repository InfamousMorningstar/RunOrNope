using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.UnitTests.Contracts;

public sealed class WorkerResultIntegrityTests
{
    private static readonly string Sha = new('a', 64);

    [Fact]
    public void EnsureRootIdentity_MatchingHashAndSize_DoesNotThrow()
    {
        var act = () => WorkerResultIntegrity.EnsureRootIdentity(RootResult(Sha, 0x800), Sha, 0x800);
        act.Should().NotThrow();
    }

    [Fact]
    public void EnsureRootIdentity_HashComparisonIsCaseInsensitive()
    {
        var act = () => WorkerResultIntegrity.EnsureRootIdentity(RootResult(Sha, 0x800), Sha.ToUpperInvariant(), 0x800);
        act.Should().NotThrow();
    }

    [Fact]
    public void EnsureRootIdentity_HashMismatch_Throws()
    {
        var act = () => WorkerResultIntegrity.EnsureRootIdentity(RootResult(Sha, 0x800), new string('b', 64), 0x800);
        act.Should().Throw<ContractValidationException>().WithMessage("*hash does not match*");
    }

    [Fact]
    public void EnsureRootIdentity_SizeMismatch_Throws()
    {
        var act = () => WorkerResultIntegrity.EnsureRootIdentity(RootResult(Sha, 0x800), Sha, 0x801);
        act.Should().Throw<ContractValidationException>().WithMessage("*size does not match*");
    }

    [Fact]
    public void EnsureRootIdentity_NoRootArtifact_Throws()
    {
        var result = RootResult(Sha, 0x800, id: "not-root");
        var act = () => WorkerResultIntegrity.EnsureRootIdentity(result, Sha, 0x800);
        act.Should().Throw<ContractValidationException>().WithMessage("*no root artifact*");
    }

    [Fact]
    public void EnsureRootIdentity_NoArtifacts_Throws()
    {
        var result = new ScanResult(
            string.Empty, AnalysisStatus.IsolationUnavailable, ArtifactCompleteness.Unavailable,
            ImmutableArray<ArtifactNode>.Empty, ImmutableArray<Observation>.Empty,
            ImmutableArray<CapabilityFinding>.Empty, ImmutableArray<string>.Empty);
        var act = () => WorkerResultIntegrity.EnsureRootIdentity(result, Sha, 0x800);
        act.Should().Throw<ContractValidationException>();
    }

    private static ScanResult RootResult(string sha256, long size, string id = "root") =>
        new(
            string.Empty, AnalysisStatus.Complete, ArtifactCompleteness.Complete,
            ImmutableArray.Create(new ArtifactNode(
                id, string.Empty, sha256, size, ArtifactCompleteness.Complete,
                ImmutableArray<string>.Empty)),
            ImmutableArray<Observation>.Empty, ImmutableArray<CapabilityFinding>.Empty,
            ImmutableArray<string>.Empty);
}
