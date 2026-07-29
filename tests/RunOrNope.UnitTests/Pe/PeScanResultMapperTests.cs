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

    [Fact]
    public void Map_EmitsImportAndPinvokeObservations()
    {
        var analysis = AnalysisWithEvidence(
            imports: ImmutableArray.Create("kernel32.dll!VirtualAllocEx"),
            externalReferences: ImmutableArray.Create(
                new ClrExternalReference(1, "CryptUnprotectData from crypt32.dll", "P/Invoke implementation", true),
                new ClrExternalReference(2, "Console::WriteLine", "metadata member reference", false)));

        var result = PeScanResultMapper.Map(analysis, Sha, 0x800);

        result.Observations.Should().Contain(o =>
            o.Kind == "pe.import" && o.Description == "kernel32.dll!VirtualAllocEx");
        result.Observations.Should().Contain(o =>
            o.Kind == "pe.pinvoke" && o.Description == "CryptUnprotectData from crypt32.dll (app-called)");
        // A non-P/Invoke member reference is not emitted as evidence.
        result.Observations.Should().NotContain(o => o.Description.Contains("Console::WriteLine"));
        RoundTrip(result);
    }

    [Fact]
    public void Map_ImportsBeyondCap_ForceIncomplete()
    {
        var imports = Enumerable.Range(0, 5000)
            .Select(index => $"module.dll!Api{index}")
            .ToImmutableArray();

        var result = PeScanResultMapper.Map(
            AnalysisWithEvidence(imports, ImmutableArray<ClrExternalReference>.Empty), Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Observations.Count(o => o.Kind == "pe.import").Should().Be(4096);
    }

    [Fact]
    public void Map_NativeImageWithNoReadableImports_IsIncomplete()
    {
        // A native image with an entry point that exposes no readable import names has
        // had its imports stripped or resolves them at run time. The enabled checks
        // cannot see what it calls, so this must not read as a complete analysis.
        var result = PeScanResultMapper.Map(
            AnalysisWithEvidence(ImmutableArray<string>.Empty, ImmutableArray<ClrExternalReference>.Empty),
            Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Observations.Should().Contain(o => o.Kind == "pe.import-visibility");
        RoundTrip(result);
    }

    [Fact]
    public void Map_OrdinalDominatedImports_IsIncomplete()
    {
        // Ordinal imports carry no name for a rule to match.
        var imports = ImmutableArray.Create(
            "kernel32.dll!CreateFileW", "mystery.dll!#1", "mystery.dll!#2", "mystery.dll!#3");

        var result = PeScanResultMapper.Map(
            AnalysisWithEvidence(imports, ImmutableArray<ClrExternalReference>.Empty), Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Observations.Should().Contain(o =>
            o.Kind == "pe.import-visibility" && o.Description.Contains("ordinal"));
        RoundTrip(result);
    }

    [Fact]
    public void Map_ReadableImports_StayComplete()
    {
        var imports = ImmutableArray.Create(
            "kernel32.dll!CreateFileW", "kernel32.dll!ReadFile", "mfc42.dll!#1");

        var result = PeScanResultMapper.Map(
            AnalysisWithEvidence(imports, ImmutableArray<ClrExternalReference>.Empty), Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        result.Observations.Should().NotContain(o => o.Kind == "pe.import-visibility");
    }

    [Fact]
    public void Map_ResourceOnlyLibrary_StaysCompleteWithoutImports()
    {
        // No entry point means no code, so there is nothing for a stripped import table
        // to be hiding. Flagging these would be noise, not honesty.
        var analysis = AnalysisWithEvidence(
            ImmutableArray<string>.Empty, ImmutableArray<ClrExternalReference>.Empty,
            entryPointRva: 0);

        var result = PeScanResultMapper.Map(analysis, Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        result.Observations.Should().NotContain(o => o.Kind == "pe.import-visibility");
    }

    [Fact]
    public void Map_ManagedAssemblyWithoutNativeImports_StaysComplete()
    {
        // A managed assembly's native import table is a runtime stub; its capability
        // evidence comes from P/Invokes, so import poverty is expected, not evasion.
        var analysis = AnalysisWithEvidence(
            ImmutableArray<string>.Empty,
            ImmutableArray.Create(
                new ClrExternalReference(1, "CryptUnprotectData from crypt32.dll", "P/Invoke implementation", true)));

        var result = PeScanResultMapper.Map(analysis, Sha, 0x800);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        result.Observations.Should().NotContain(o => o.Kind == "pe.import-visibility");
    }

    private static PeAnalysisResult AnalysisWithEvidence(
        ImmutableArray<string> imports,
        ImmutableArray<ClrExternalReference> externalReferences,
        uint entryPointRva = 0x1000)
    {
        var clr = new ClrAnalysisResult(
            externalReferences.Length > 0, "Sample", ImmutableArray<string>.Empty,
            ImmutableArray<ClrMethodObservation>.Empty, externalReferences, false,
            ImmutableArray<string>.Empty);
        return new PeAnalysisResult(
            Layout(null, entryPointRva), clr, Trust(TrustDisposition.NoSignature),
            new RichPeSummary(1, imports.Length, 0, 0, false, false, imports, ImmutableArray<string>.Empty),
            RichParserAgreed: true, ImmutableArray<string>.Empty);
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
            // Readable named imports, as a real native image has: an empty inventory is
            // itself a completeness signal and must not be the default fixture shape.
            new RichPeSummary(1, 2, 0, 0, false, false,
                ImmutableArray.Create("kernel32.dll!CreateFileW", "kernel32.dll!ReadFile"),
                ImmutableArray<string>.Empty),
            richAgreed,
            limitations ?? ImmutableArray<string>.Empty);

    private static PeLayout Layout(ImmutableArray<string>? anomalies, uint entryPointRva = 0x1000) =>
        new(
            IsPe32Plus: true,
            Machine: 0x8664,
            EntryPointRva: entryPointRva,
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
