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
            Import("pe-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("pe-obs-0002", "kernel32.dll!WriteProcessMemory"),
            Import("pe-obs-0003", "kernel32.dll!CreateRemoteThread"));

        var findings = CapabilityRuleEngine.Evaluate(observations);

        findings.Should().ContainSingle();
        var finding = findings[0];
        finding.Family.Should().Be(RiskFamily.ProcessManipulation);
        finding.EvidenceStatus.Should().Be(EvidenceStatus.StrongStructuralEvidence);
        finding.ApplicationLinkage.Should().Be(ApplicationLinkage.Unknown);
        finding.Reachability.Should().Be(Reachability.Referenced);
        finding.ObservationIds.Should().Equal("pe-obs-0001", "pe-obs-0002", "pe-obs-0003");
        Validate(observations, findings);
    }

    [Fact]
    public void Evaluate_InjectionWithoutExecutionPrimitive_EmitsNoFinding()
    {
        // The required core is present but nothing in the any-of set can execute the
        // written bytes; allocate-and-write alone is an ordinary patcher or debugger.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("pe-obs-0002", "kernel32.dll!WriteProcessMemory"));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_InjectionWithoutAllocation_EmitsNoFinding()
    {
        // Three APIs from the injection cluster, but VirtualAllocEx is absent, so the
        // required core is incomplete. Loose N-of counting would overmatch here.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "kernel32.dll!WriteProcessMemory"),
            Import("pe-obs-0002", "kernel32.dll!CreateRemoteThread"),
            Import("pe-obs-0003", "kernel32.dll!QueueUserAPC"));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_KeyStatePollingWithoutHook_EmitsNoKeyloggingFinding()
    {
        // Games and hotkey handlers poll key state constantly. Without the hook that
        // is the rule's required core, this must not be reported as keystroke capture.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "user32.dll!GetAsyncKeyState"),
            Import("pe-obs-0002", "user32.dll!GetKeyState"));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_SingleWeakApi_FiresAtApiPresenceTier()
    {
        var observations = ImmutableArray.Create(Import("pe-obs-0001", "kernel32.dll!IsDebuggerPresent"));

        var findings = CapabilityRuleEngine.Evaluate(observations);

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
            "pe-obs-0001", "pe.pinvoke", "CryptUnprotectData from crypt32.dll (app-called)",
            ParserConfidence.High, new SourceLocation("root", null, null)));

        var findings = CapabilityRuleEngine.Evaluate(observations);

        findings.Should().ContainSingle();
        findings[0].Family.Should().Be(RiskFamily.CredentialAccess);
        findings[0].ObservationIds.Should().Equal("pe-obs-0001");
    }

    [Fact]
    public void Evaluate_MatchesAnsiWideSuffixedImports()
    {
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "user32.dll!SetWindowsHookExW"),
            Import("pe-obs-0002", "user32.dll!GetAsyncKeyState"));

        var findings = CapabilityRuleEngine.Evaluate(observations);

        findings.Should().ContainSingle(finding => finding.Family == RiskFamily.Surveillance);
    }

    [Fact]
    public void Evaluate_IsDeterministicAndOrderedByRule()
    {
        // Imports that trigger anti-debugging (rule 7) and network (rule 9); the
        // findings must appear in rule order regardless of observation order.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0002", "ws2_32.dll!connect"),
            Import("pe-obs-0001", "kernel32.dll!IsDebuggerPresent"));

        var first = CapabilityRuleEngine.Evaluate(observations);
        var second = CapabilityRuleEngine.Evaluate(observations);

        first.Select(f => f.Family).Should().Equal(RiskFamily.DefenseEvasion, RiskFamily.NetworkCommunication);
        second.Should().BeEquivalentTo(first);
    }

    [Fact]
    public void Evaluate_CreateRemoteThreadExVariant_MatchesInjectionCluster()
    {
        // The Ex suffix is a distinct export, not an ANSI/Wide variant, so it only
        // matches when the rule names it explicitly.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "kernel32.dll!VirtualAllocEx"),
            Import("pe-obs-0002", "kernel32.dll!WriteProcessMemory"),
            Import("pe-obs-0003", "kernel32.dll!CreateRemoteThreadEx"));

        CapabilityRuleEngine.Evaluate(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.ProcessManipulation);
    }

    [Fact]
    public void Evaluate_ZwPrefixedQuery_TriggersAntiDebugging()
    {
        // ntdll exports both the Nt- and Zw-prefixed forms of the same routine.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "ntdll.dll!ZwQueryInformationProcess"));

        CapabilityRuleEngine.Evaluate(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.DefenseEvasion);
    }

    [Fact]
    public void Evaluate_GdiDoubleBuffering_EmitsNoScreenCaptureFinding()
    {
        // BitBlt onto a compatible bitmap is the standard double-buffered painting
        // idiom. Without a screen or window device context as the blit source, this is
        // ordinary custom-control drawing, not surveillance.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "gdi32.dll!BitBlt"),
            Import("pe-obs-0002", "gdi32.dll!CreateCompatibleBitmap"));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_BlitFromWindowDeviceContext_EmitsScreenCaptureFinding()
    {
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "gdi32.dll!BitBlt"),
            Import("pe-obs-0002", "gdi32.dll!CreateCompatibleBitmap"),
            Import("pe-obs-0003", "user32.dll!GetWindowDC"));

        CapabilityRuleEngine.Evaluate(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.Surveillance);
    }

    [Fact]
    public void Evaluate_LoadLibraryExOnlyResolver_EmitsDynamicApiFinding()
    {
        // The reason dynamic-api-resolution is keyed on GetProcAddress with an any-of
        // loader set: LoadLibrary plus A/W cannot reach LoadLibraryExW.
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "kernel32.dll!GetProcAddress"),
            Import("pe-obs-0002", "kernel32.dll!LoadLibraryExW"));

        CapabilityRuleEngine.Evaluate(observations)
            .Should().ContainSingle(finding => finding.Family == RiskFamily.Obfuscation);
    }

    [Fact]
    public void Evaluate_PartialAndRule_EmitsNoFinding()
    {
        // service-install is a pure AND; half of it must not fire.
        var observations = ImmutableArray.Create(Import("pe-obs-0001", "advapi32.dll!OpenSCManagerW"));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
    }

    [Fact]
    public void Evaluate_SameApiFromTwoModules_EmitsOneFindingCitingBoth()
    {
        var observations = ImmutableArray.Create(
            Import("pe-obs-0001", "kernel32.dll!IsDebuggerPresent"),
            Import("pe-obs-0002", "api-ms-win-core-debug-l1-1-0.dll!IsDebuggerPresent"));

        var findings = CapabilityRuleEngine.Evaluate(observations);

        findings.Should().ContainSingle();
        findings[0].ObservationIds.Should().Equal("pe-obs-0001", "pe-obs-0002");
    }

    [Fact]
    public void Evaluate_PInvokeNameSpoofingSeparator_DoesNotMatchTargetedApi()
    {
        // The entry-point name is attacker-controlled managed metadata and is joined to
        // the module with " from ". A name that embeds the separator must not be able to
        // impersonate an API the rules target.
        var observations = ImmutableArray.Create(new Observation(
            "pe-obs-0001", "pe.pinvoke", "CryptUnprotectData from crypt32.dll from hostile.dll",
            ParserConfidence.High, new SourceLocation("root", null, null)));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
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
            "pe-obs-0001", "pe.image", "PE32+ image, machine x64 (0x8664).",
            ParserConfidence.High, new SourceLocation("root", null, null)));

        CapabilityRuleEngine.Evaluate(observations).Should().BeEmpty();
    }

    private static Observation Import(string id, string moduleBangApi) =>
        new(id, "pe.import", moduleBangApi, ParserConfidence.High, new SourceLocation("root", null, null));

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
