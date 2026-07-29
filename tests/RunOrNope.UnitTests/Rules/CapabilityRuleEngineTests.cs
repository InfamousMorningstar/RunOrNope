using System.Collections.Immutable;
using System.Linq;
using AwesomeAssertions;
using RunOrNope.Contracts;
using RunOrNope.Rules;
using Xunit;

namespace RunOrNope.UnitTests.Rules;

public sealed class CapabilityRuleEngineTests
{
    [Fact]
    public void Evaluate_InjectionCluster_EmitsSingleFindingCitingMatchedImports()
    {
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("root-obs-0002", "kernel32.dll!WriteProcessMemory"),
            Import("root-obs-0003", "kernel32.dll!CreateRemoteThread"));

        var findings = EvaluateRoot(observations);

        findings.Should().ContainSingle();
        var finding = findings[0];
        finding.Family.Should().Be(RiskFamily.ProcessManipulation);
        finding.EvidenceStatus.Should().Be(EvidenceStatus.StrongStructuralEvidence);
        finding.ApplicationLinkage.Should().Be(ApplicationLinkage.Unknown);
        finding.Reachability.Should().Be(Reachability.Referenced);
        finding.ObservationIds.Should().Equal("root-obs-0001", "root-obs-0002", "root-obs-0003");
        Validate(observations, findings);
    }

    [Fact]
    public void Evaluate_InjectionWithoutExecutionPrimitive_EmitsNoFinding()
    {
        // The required core is present but nothing in the any-of set can execute the
        // written bytes; allocate-and-write alone is an ordinary patcher or debugger.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("root-obs-0002", "kernel32.dll!WriteProcessMemory"));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_InjectionWithoutAllocation_EmitsNoFinding()
    {
        // Three APIs from the injection cluster, but VirtualAllocEx is absent, so the
        // required core is incomplete. Loose N-of counting would overmatch here.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!WriteProcessMemory"),
            Import("root-obs-0002", "kernel32.dll!CreateRemoteThread"),
            Import("root-obs-0003", "kernel32.dll!QueueUserAPC"));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_KeyStatePollingWithoutHook_EmitsNoKeyloggingFinding()
    {
        // Games and hotkey handlers poll key state constantly. Without the hook that
        // is the rule's required core, this must not be reported as keystroke capture.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "user32.dll!GetAsyncKeyState"),
            Import("root-obs-0002", "user32.dll!GetKeyState"));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_SingleWeakApi_FiresAtApiPresenceTier()
    {
        var observations = ImmutableArray.Create(Import("root-obs-0001", "kernel32.dll!IsDebuggerPresent"));

        var findings = EvaluateRoot(observations);

        findings.Should().ContainSingle();
        findings[0].Family.Should().Be(RiskFamily.DefenseEvasion);
        findings[0].EvidenceStatus.Should().Be(EvidenceStatus.ApiOrLibraryPresenceOnly);
        // Presence-only rules stay informational so they cannot, alone or together,
        // push an ordinary program past the caution threshold.
        findings[0].Severity.Should().Be(Severity.Informational);
    }

    [Fact]
    public void Evaluate_ManagedPInvoke_TriggersDpapiCredentialAccess()
    {
        var observations = ImmutableArray.Create(new Observation(
            "root-obs-0001", "pe.pinvoke", "CryptUnprotectData from crypt32.dll (app-called)",
            ParserConfidence.High, new SourceLocation("root", null, null)));

        var findings = EvaluateRoot(observations);

        findings.Should().ContainSingle();
        findings[0].Family.Should().Be(RiskFamily.CredentialAccess);
        findings[0].ObservationIds.Should().Equal("root-obs-0001");
    }

    [Fact]
    public void Evaluate_MatchesAnsiWideSuffixedImports()
    {
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "user32.dll!SetWindowsHookExW"),
            Import("root-obs-0002", "user32.dll!GetAsyncKeyState"));

        var findings = EvaluateRoot(observations);

        findings.Should().ContainSingle(finding => finding.Family == RiskFamily.Surveillance);
    }

    [Fact]
    public void Evaluate_IsDeterministicAndOrderedByRule()
    {
        // Imports that trigger anti-debugging (rule 7) and network (rule 9); the
        // findings must appear in rule order regardless of observation order.
        var observations = ImmutableArray.Create(
            Import("root-obs-0002", "ws2_32.dll!connect"),
            Import("root-obs-0001", "kernel32.dll!IsDebuggerPresent"));

        var first = EvaluateRoot(observations);
        var second = EvaluateRoot(observations);

        first.Select(f => f.Family).Should().Equal(RiskFamily.DefenseEvasion, RiskFamily.NetworkCommunication);
        second.Should().BeEquivalentTo(first);
    }

    [Fact]
    public void Evaluate_CreateRemoteThreadExVariant_MatchesInjectionCluster()
    {
        // The Ex suffix is a distinct export, not an ANSI/Wide variant, so it only
        // matches when the rule names it explicitly.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("root-obs-0002", "kernel32.dll!WriteProcessMemory"),
            Import("root-obs-0003", "kernel32.dll!CreateRemoteThreadEx"));

        EvaluateRoot(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.ProcessManipulation);
    }

    [Fact]
    public void Evaluate_ZwPrefixedQuery_TriggersAntiDebugging()
    {
        // ntdll exports both the Nt- and Zw-prefixed forms of the same routine.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "ntdll.dll!ZwQueryInformationProcess"));

        EvaluateRoot(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.DefenseEvasion);
    }

    [Fact]
    public void Evaluate_GdiDoubleBuffering_EmitsNoScreenCaptureFinding()
    {
        // BitBlt onto a compatible bitmap is the standard double-buffered painting
        // idiom. Without a screen or window device context as the blit source, this is
        // ordinary custom-control drawing, not surveillance.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "gdi32.dll!BitBlt"),
            Import("root-obs-0002", "gdi32.dll!CreateCompatibleBitmap"));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_BlitFromWindowDeviceContext_EmitsScreenCaptureFinding()
    {
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "gdi32.dll!BitBlt"),
            Import("root-obs-0002", "gdi32.dll!CreateCompatibleBitmap"),
            Import("root-obs-0003", "user32.dll!GetWindowDC"));

        EvaluateRoot(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.Surveillance);
    }

    [Fact]
    public void Evaluate_LoadLibraryExOnlyResolver_EmitsDynamicApiFinding()
    {
        // The reason dynamic-api-resolution is keyed on GetProcAddress with an any-of
        // loader set: LoadLibrary plus A/W cannot reach LoadLibraryExW.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!GetProcAddress"),
            Import("root-obs-0002", "kernel32.dll!LoadLibraryExW"));

        EvaluateRoot(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.Obfuscation);
    }

    [Fact]
    public void Evaluate_PartialAndRule_EmitsNoFinding()
    {
        // service-install is a pure AND; half of it must not fire.
        var observations = ImmutableArray.Create(Import("root-obs-0001", "advapi32.dll!OpenSCManagerW"));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_SameApiFromTwoModules_EmitsOneFindingCitingBoth()
    {
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!IsDebuggerPresent"),
            Import("root-obs-0002", "api-ms-win-core-debug-l1-1-0.dll!IsDebuggerPresent"));

        var findings = EvaluateRoot(observations);

        findings.Should().ContainSingle();
        findings[0].ObservationIds.Should().Equal("root-obs-0001", "root-obs-0002");
    }

    [Fact]
    public void Evaluate_PInvokeNameSpoofingSeparator_DoesNotMatchTargetedApi()
    {
        // The entry-point name is attacker-controlled managed metadata and is joined to
        // the module with " from ". A name that embeds the separator must not be able to
        // impersonate an API the rules target.
        var observations = ImmutableArray.Create(new Observation(
            "root-obs-0001", "pe.pinvoke", "CryptUnprotectData from crypt32.dll from hostile.dll",
            ParserConfidence.High, new SourceLocation("root", null, null)));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void RuleIds_AreUniqueAndNonEmpty()
    {
        var ids = CapabilityRuleSet.Default.Select(rule => rule.Id).ToArray();

        ids.Should().OnlyHaveUniqueItems();
        ids.Should().AllSatisfy(id => id.Should().NotBeNullOrWhiteSpace());
    }

    [Fact]
    public void Evaluate_NoImportObservations_EmitsNoFindings()
    {
        var observations = ImmutableArray.Create(new Observation(
            "root-obs-0001", "pe.image", "PE32+ image, machine x64 (0x8664).",
            ParserConfidence.High, new SourceLocation("root", null, null)));

        EvaluateRoot(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_ClusterSplitAcrossArtifacts_EmitsNoFinding()
    {
        // The allocation half is in the root, the execution half in a bundled DLL.
        // Combining them would both break the contract's single-artifact provenance rule
        // and accuse two innocent files of jointly being an injector.
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("root-obs-0002", "kernel32.dll!WriteProcessMemory"),
            Import("art-0001-obs-0001", "kernel32.dll!CreateRemoteThread", "art-0001"));

        var artifacts = ImmutableArray.Create(RootArtifact, Nested("art-0001", ApplicationLinkage.Dependency));
        var findings = CapabilityRuleEngine.Evaluate(observations, artifacts);

        findings.Should().BeEmpty();
        ValidateGraph(artifacts, observations, findings);
    }

    [Fact]
    public void Evaluate_ClusterInsideNestedArtifact_TakesThatArtifactsLinkage()
    {
        var observations = ImmutableArray.Create(
            Import("root-obs-0001", "kernel32.dll!GetProcAddress"),
            Import("root-obs-0002", "kernel32.dll!LoadLibraryW"),
            Import("art-0001-obs-0001", "kernel32.dll!VirtualAllocEx", "art-0001"),
            Import("art-0001-obs-0002", "kernel32.dll!WriteProcessMemory", "art-0001"),
            Import("art-0001-obs-0003", "kernel32.dll!CreateRemoteThread", "art-0001"));

        var artifacts = ImmutableArray.Create(RootArtifact, Nested("art-0001", ApplicationLinkage.Dependency));
        var findings = CapabilityRuleEngine.Evaluate(observations, artifacts);

        // Root fires the weak dynamic-resolution rule; the nested DLL fires injection.
        findings.Should().HaveCount(2);
        findings[0].Title.Should().Be("Resolves APIs at runtime");
        findings[0].ApplicationLinkage.Should().Be(ApplicationLinkage.Unknown);

        var injection = findings[1];
        injection.Family.Should().Be(RiskFamily.ProcessManipulation);
        injection.ApplicationLinkage.Should().Be(ApplicationLinkage.Dependency);
        injection.ObservationIds.Should().Equal(
            "art-0001-obs-0001", "art-0001-obs-0002", "art-0001-obs-0003");
        ValidateGraph(artifacts, observations, findings);
    }

    [Fact]
    public void Evaluate_OrdersByArtifactThenRule()
    {
        var observations = ImmutableArray.Create(
            Import("art-0002-obs-0001", "kernel32.dll!IsDebuggerPresent", "art-0002"),
            Import("root-obs-0001", "kernel32.dll!IsDebuggerPresent"),
            Import("art-0001-obs-0001", "kernel32.dll!IsDebuggerPresent", "art-0001"));

        var artifacts = ImmutableArray.Create(
            RootArtifact,
            Nested("art-0001", ApplicationLinkage.Dependency),
            Nested("art-0002", ApplicationLinkage.Dependency));

        var findings = CapabilityRuleEngine.Evaluate(observations, artifacts);

        // Artifact order drives output order, not the order observations arrived in.
        findings.Select(finding => finding.ObservationIds[0]).Should()
            .Equal("root-obs-0001", "art-0001-obs-0001", "art-0002-obs-0001");
    }

    [Fact]
    public void Evaluate_ObservationForAnUnknownArtifact_IsIgnored()
    {
        // An observation whose artifact is absent has no linkage to attribute a finding
        // to, and the contract would reject it. Silently dropping beats inventing one.
        var observations = ImmutableArray.Create(
            Import("ghost-obs-0001", "kernel32.dll!VirtualAllocEx", "art-0404"),
            Import("ghost-obs-0002", "kernel32.dll!WriteProcessMemory", "art-0404"),
            Import("ghost-obs-0003", "kernel32.dll!CreateRemoteThread", "art-0404"));

        CapabilityRuleEngine.Evaluate(observations, ImmutableArray.Create(RootArtifact))
            .Should().BeEmpty();
    }

    private static ArtifactNode Nested(string id, ApplicationLinkage linkage) =>
        new(id, id, new string('b', 64), 0x200, ArtifactCompleteness.Complete,
            ImmutableArray.Create("root"), linkage);

    private static void ValidateGraph(
        ImmutableArray<ArtifactNode> artifacts,
        ImmutableArray<Observation> observations,
        ImmutableArray<CapabilityFinding> findings)
    {
        ContractValidator.Validate(new ScanResult(
            string.Empty, AnalysisStatus.Complete, ArtifactCompleteness.Complete,
            artifacts, observations, findings, ImmutableArray<string>.Empty));
    }

    private static readonly ArtifactNode RootArtifact = new(
        "root", string.Empty, new string('a', 64), 0x1000,
        ArtifactCompleteness.Complete, ImmutableArray<string>.Empty, ApplicationLinkage.Unknown);

    /// <summary>Evaluates against a single Unknown-linkage root, the shape of a flat PE scan.</summary>
    private static ImmutableArray<CapabilityFinding> EvaluateRoot(ImmutableArray<Observation> observations) =>
        CapabilityRuleEngine.Evaluate(observations, ImmutableArray.Create(RootArtifact));

    private static Observation Import(string id, string moduleBangApi, string artifactId = "root") =>
        new(id, "pe.import", moduleBangApi, ParserConfidence.High, new SourceLocation(artifactId, null, null));

    private static void Validate(
        ImmutableArray<Observation> observations, ImmutableArray<CapabilityFinding> findings)
    {
        var root = new ArtifactNode(
            "root", string.Empty, new string('a', 64), 0x1000,
            ArtifactCompleteness.Complete, ImmutableArray<string>.Empty, ApplicationLinkage.Unknown);
        var result = new ScanResult(
            string.Empty, AnalysisStatus.Complete, ArtifactCompleteness.Complete,
            ImmutableArray.Create(root), observations, findings, ImmutableArray<string>.Empty);
        ContractValidator.Validate(result);
    }
}
