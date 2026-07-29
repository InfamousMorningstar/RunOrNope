using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
using Xunit;
using static RunOrNope.UnitTests.Content.TestContainerProvider;

namespace RunOrNope.UnitTests.Content;

public sealed class ArtifactGraphBuilderTests
{
    [Fact]
    public void Build_FlatContainer_ProducesOneNodePerEntry()
    {
        var alpha = Leaf("alpha");
        var beta = Leaf("beta");
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("alpha.dll", alpha), Entry("beta.dll", beta));

        var graph = Build(root, provider);

        graph.Artifacts.Select(artifact => artifact.Id).Should().Equal("root", "art-0001", "art-0002");
        graph.Artifacts[1].Name.Should().Be("alpha.dll");
        graph.Artifacts[1].ParentIds.Should().Equal("root");
        graph.Incomplete.Should().BeFalse();
        ValidateGraph(graph);
    }

    [Fact]
    public void Build_SamePayloadUnderTwoPaths_IsOneNodeWithTwoParents()
    {
        var shared = Leaf("shared-payload");
        var left = Leaf("left-container");
        var right = Leaf("right-container");
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("left", left), Entry("right", right))
            .Register(left, Entry("shared.dll", shared))
            .Register(right, Entry("copy.dll", shared));

        var graph = Build(root, provider);

        var sharedNodes = graph.Artifacts.Where(a => a.Sha256 == Sha(shared)).ToArray();
        sharedNodes.Should().ContainSingle();
        sharedNodes[0].ParentIds.Should().HaveCount(2);
        graph.Observations.Should().Contain(o => o.Kind == "artifact.duplicate");
        ValidateGraph(graph);
    }

    [Fact]
    public void Build_ContainerEmbeddingItself_Terminates()
    {
        // Identity deduplication is the cycle guard: the self-reference hashes to a node
        // that already exists, so the edge is recorded and the walk does not recurse.
        var root = Leaf("self-referential");
        var provider = new TestContainerProvider().Register(root, Entry("me.zip", root));

        var graph = Build(root, provider);

        graph.Artifacts.Should().ContainSingle();
        graph.Artifacts[0].Id.Should().Be("root");
        graph.Artifacts[0].ParentIds.Should().Equal("root");
        graph.Observations.Should().Contain(o => o.Kind == "artifact.duplicate");
    }

    [Fact]
    public void Build_IsDeterministicAcrossRuns()
    {
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("a", Leaf("a")), Entry("b", Leaf("b")), Entry("c", Leaf("c")));

        var first = Build(root, provider);
        var second = Build(root, provider);

        first.Artifacts.Select(a => (a.Id, a.Sha256))
            .Should().Equal(second.Artifacts.Select(a => (a.Id, a.Sha256)));
        first.Observations.Select(o => o.Id).Should().Equal(second.Observations.Select(o => o.Id));
    }

    [Fact]
    public void Build_HostileNameIsReportedButContentIsStillAnalysed()
    {
        // The core promise of the path policy: a nasty name changes what is *said*, never
        // whether the payload is looked at. Ignoring it would be favourable-on-absence.
        var payload = Leaf("payload-bytes");
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("../../../Windows/System32/evil.dll", payload));

        var graph = Build(root, provider);

        graph.Artifacts.Should().HaveCount(2);
        graph.Artifacts[1].Sha256.Should().Be(Sha(payload));
        graph.Observations.Should().Contain(o => o.Kind == "artifact.hostile-name");
        ValidateGraph(graph);
    }

    [Fact]
    public void Build_CaseOnlyNameCollision_IsReported()
    {
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("Setup.dll", Leaf("one")), Entry("setup.dll", Leaf("two")));

        var graph = Build(root, provider);

        // Two distinct payloads, but one filename once written to a Windows filesystem.
        graph.Artifacts.Should().HaveCount(3);
        graph.Observations.Count(o => o.Kind == "artifact.hostile-name").Should().Be(1);
    }

    [Fact]
    public void Build_DeclaredSizeDisagreeingWithDelivery_IsReported()
    {
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Claiming("liar.dll", declaredSize: 4L << 30, content: Leaf("tiny")));

        var graph = Build(root, provider);

        graph.Observations.Should().Contain(o => o.Kind == "artifact.size-mismatch");
        // Sized by what arrived, never by what was claimed.
        graph.Artifacts[1].Size.Should().Be(4);
        ValidateGraph(graph);
    }

    [Fact]
    public void Build_NestedContainers_RecurseAndRecordParents()
    {
        var inner = Leaf("inner-payload");
        var middle = Leaf("middle-container");
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("middle.zip", middle))
            .Register(middle, Entry("inner.dll", inner));

        var graph = Build(root, provider);

        graph.Artifacts.Should().HaveCount(3);
        graph.Artifacts[2].ParentIds.Should().Equal("art-0001");
        ValidateGraph(graph);
    }

    [Fact]
    public void Build_ObservationIdsAreArtifactScopedAndUnique()
    {
        var root = Leaf("root-container");
        var middle = Leaf("middle-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("middle.zip", middle))
            .Register(middle, Entry("leaf.dll", Leaf("leaf")));

        var graph = Build(root, provider);

        graph.Observations.Select(o => o.Id).Should().OnlyHaveUniqueItems();
        graph.Observations.Should().AllSatisfy(o =>
            o.Id.Should().StartWith(o.Source.ArtifactId + "-obs-"));
    }

    [Fact]
    public void Build_GraphRoundTripsThroughTheContractSerializer()
    {
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Entry("a.dll", Leaf("a")), Entry("b.dll", Leaf("b")));

        var graph = Build(root, provider);
        var result = ToScanResult(graph);

        var restored = ScanContractJson.Deserialize(ScanContractJson.Serialize(result));
        restored.Artifacts.Should().HaveCount(result.Artifacts.Length);
    }

    [Fact]
    public void Build_TruncatedNestedArtifact_WithholdsTheDisposition()
    {
        // The fail-closed property end to end. A container the walk could not finish must
        // never read as "few material static concerns" — the most favourable result
        // available — precisely because nothing incriminating was found in what was seen.
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Endless("huge.bin", 4L << 30, 4L << 30));

        var graph = Build(root, provider);
        var verdict = VerdictEngine.Evaluate(ToScanResult(graph));

        graph.Incomplete.Should().BeTrue();
        verdict.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        verdict.RiskDisposition.Should().BeNull("an unfinished walk yields no disposition");
    }

    [Fact]
    public void Build_CompleteWalkWithNothingNotable_IsAllowedToBeFavourable()
    {
        // The counterpart: withholding must be caused by incompleteness, not by default.
        var root = Leaf("root-container");
        var provider = new TestContainerProvider().Register(root, Entry("readme.txt", Leaf("hello")));

        var graph = Build(root, provider);
        var verdict = VerdictEngine.Evaluate(ToScanResult(graph));

        graph.Incomplete.Should().BeFalse();
        verdict.RiskDisposition.Should().Be(RiskDisposition.FewMaterialStaticConcerns);
    }

    internal static ArtifactGraph Build(byte[] root, IContainerProvider provider, ExtractionBudget? budget = null) =>
        ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

    internal static ScanResult ToScanResult(ArtifactGraph graph) => new(
        string.Empty,
        graph.Incomplete ? AnalysisStatus.Incomplete : AnalysisStatus.Complete,
        graph.Incomplete ? ArtifactCompleteness.TruncatedByPolicy : ArtifactCompleteness.Complete,
        graph.Artifacts, graph.Observations, [], []);

    internal static void ValidateGraph(ArtifactGraph graph) =>
        ContractValidator.Validate(ToScanResult(graph));
}
