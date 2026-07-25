using System.Collections.Immutable;
using System.Linq;
using AwesomeAssertions;
using RunOrNope.Analyzers.Pe;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.UnitTests.Pe;

public sealed class PeScanResultMapperTests
{
    private const string Sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void Map_CleanNativePe_IsCompleteWithStructuralObservations()
    {
        var result = PeScanResultMapper.Map(Analysis(), Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        result.Completeness.Should().Be(ArtifactCompleteness.Complete);
        result.Findings.Should().BeEmpty();
        result.Artifacts.Should().ContainSingle()
            .Which.Completeness.Should().Be(ArtifactCompleteness.Complete);
        result.Artifacts[0].Sha256.Should().Be(Sha);
        result.Observations.Select(o => o.Kind).Should()
            .Contain(["pe.image", "pe.section", "pe.entry-point", "pe.trust", "pe.clr", "pe.rich-parser"]);
        result.Observations.Should().Contain(o => o.Kind == "pe.image" && o.Description.Contains("x64"));
        RoundTrip(result);
    }

    [Fact]
    public void Map_ObservationsAreRootSourcedWithDeterministicIds()
    {
        var result = PeScanResultMapper.Map(Analysis(), Sha, 0x800);

        result.Observations.Should().OnlyContain(o => o.Source.ArtifactId == "root");
        result.Observations.Select(o => o.Id).Should().OnlyHaveUniqueItems();
        result.Observations[0].Id.Should().Be("pe-obs-0001");
    }

    [Fact]
    public void Map_UnsupportedBytes_IsUnsupportedWithNoObservations()
    {
        var result = PeScanResultMapper.Unsupported(Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.UnsupportedOrInvalidRootFormat);
        result.Completeness.Should().Be(ArtifactCompleteness.Unsupported);
        result.Observations.Should().BeEmpty();
        result.Artifacts.Should().ContainSingle()
            .Which.Completeness.Should().Be(ArtifactCompleteness.Unsupported);
        RoundTrip(result);
    }

    [Fact]
    public void Malformed_IsIncompleteWithMalformedRoot()
    {
        var result = PeScanResultMapper.Malformed(Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Completeness.Should().Be(ArtifactCompleteness.Malformed);
        result.Observations.Should().BeEmpty();
        result.Artifacts.Should().ContainSingle()
            .Which.Completeness.Should().Be(ArtifactCompleteness.Malformed);
        RoundTrip(result);
    }

    [Fact]
    public void Map_ManagedAssembly_EmitsClrObservation()
    {
        var result = PeScanResultMapper.Map(Analysis(clr: ManagedClr()), Sha, 0x800);

        result.Observations.Should().Contain(o =>
            o.Kind == "pe.clr" && o.Description.Contains("Managed assembly"));
    }

    [Fact]
    public void Map_TrustedSignature_AddsSingleCountervailingFact()
    {
        var result = PeScanResultMapper.Map(
            Analysis(trust: Trust(TrustDisposition.Trusted)), Sha, 0x800);

        result.CountervailingFacts.Should().ContainSingle()
            .Which.Should().Contain("platform trust verified");
    }

    [Fact]
    public void Map_UnsignedFile_HasNoCountervailingFact()
    {
        var result = PeScanResultMapper.Map(
            Analysis(trust: Trust(TrustDisposition.NoSignature)), Sha, 0x800);

        result.CountervailingFacts.Should().BeEmpty();
    }

    [Fact]
    public void Map_Limitations_ForceIncomplete()
    {
        var result = PeScanResultMapper.Map(
            Analysis(limitations: ImmutableArray.Create("Rich parser skipped by byte limit.")),
            Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Completeness.Should().Be(ArtifactCompleteness.TruncatedByPolicy);
        RoundTrip(result);
    }

    [Fact]
    public void Map_TruncatedClrWalk_ForcesIncomplete()
    {
        // Guards the reviewer's constraint: a padded managed binary must not earn a
        // Complete (favorable) verdict by exceeding the CLR walk limits.
        var result = PeScanResultMapper.Map(
            Analysis(clr: ManagedClr(truncated: true)), Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
    }

    [Fact]
    public void Map_OfflineRevocation_ForcesIncomplete()
    {
        var result = PeScanResultMapper.Map(
            Analysis(trust: Trust(TrustDisposition.IndeterminateOffline, revocationIndeterminate: true)),
            Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
    }

    [Fact]
    public void Map_StructuralAnomaly_BecomesObservationButStaysComplete()
    {
        var result = PeScanResultMapper.Map(
            Analysis(anomalies: ImmutableArray.Create("Entry point is outside an executable section.")),
            Sha, 0x800);

        result.Observations.Should().Contain(o => o.Kind == "pe.anomaly");
        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
    }

    [Fact]
    public void Map_HostileManagedNameWithBidiControl_StillValidates()
    {
        var hostileName = "evil" + (char)0x202E + "name";
        var clr = new ClrAnalysisResult(
            true, hostileName, ImmutableArray.Create("System.Runtime"),
            ImmutableArray<ClrMethodObservation>.Empty,
            ImmutableArray<ClrExternalReference>.Empty, false,
            ImmutableArray<string>.Empty);

        var result = PeScanResultMapper.Map(Analysis(clr: clr), Sha, 0x800);

        // Would throw in ContractValidator (bidirectional control) if CleanText did
        // not neutralise it; RoundTrip runs the full contract validation.
        RoundTrip(result);
        result.Observations.Should().Contain(o =>
            o.Kind == "pe.clr" && !o.Description.Contains((char)0x202E));
    }

    private static void RoundTrip(ScanResult result)
    {
        var json = ScanContractJson.Serialize(result);
        var restored = ScanContractJson.Deserialize(json);
        restored.Should().BeEquivalentTo(result);
    }

    private static PeAnalysisResult Analysis(
        ClrAnalysisResult? clr = null,
        AuthenticodeResult? trust = null,
        bool richAgreed = true,
        ImmutableArray<string>? limitations = null,
        ImmutableArray<string>? anomalies = null) =>
        new(
            Layout(anomalies),
            clr ?? NativeClr(),
            trust ?? Trust(TrustDisposition.NoSignature),
            new RichPeSummary(1, 5, 0, 0, false, false,
                ImmutableArray<string>.Empty, ImmutableArray<string>.Empty),
            richAgreed,
            limitations ?? ImmutableArray<string>.Empty);

    private static PeLayout Layout(ImmutableArray<string>? anomalies) =>
        new(
            IsPe32Plus: true,
            Machine: 0x8664,
            EntryPointRva: 0x1000,
            SizeOfHeaders: 0x400,
            Sections: ImmutableArray.Create(
                new PeSection(".text", 0x1000, 0x200, 0x200, 0x200, 0x6000_0020)),
            CertificateOffset: null,
            CertificateLength: 0,
            OverlayOffset: 0,
            OverlayLength: 0,
            StructuralAnomalies: anomalies ?? ImmutableArray<string>.Empty);

    private static ClrAnalysisResult NativeClr() =>
        new(false, null, ImmutableArray<string>.Empty,
            ImmutableArray<ClrMethodObservation>.Empty,
            ImmutableArray<ClrExternalReference>.Empty, false,
            ImmutableArray<string>.Empty);

    private static ClrAnalysisResult ManagedClr(bool truncated = false) =>
        new(true, "Sample", ImmutableArray.Create("System.Runtime"),
            ImmutableArray<ClrMethodObservation>.Empty,
            ImmutableArray<ClrExternalReference>.Empty, truncated,
            ImmutableArray<string>.Empty);

    private static AuthenticodeResult Trust(TrustDisposition disposition, bool revocationIndeterminate = false) =>
        new(0, disposition, revocationIndeterminate, null, null,
            disposition == TrustDisposition.Trusted ? 1 : 0);
}
