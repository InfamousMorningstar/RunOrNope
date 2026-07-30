using System.Collections.Immutable;
using System.IO;
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

    [Fact]
    public void Build_NotRecognizedBytes_RemainAnOrdinaryCompleteLeaf()
    {
        var root = Leaf("ordinary-bytes");

        var graph = Build(root, new TestContainerProvider());

        graph.Artifacts.Should().ContainSingle();
        graph.Artifacts[0].Completeness.Should().Be(ArtifactCompleteness.Complete);
        graph.Incomplete.Should().BeFalse();
    }

    [Fact]
    public void Build_UnrecognizedResultWithPayload_IsNormalizedToAnOrdinaryLeaf()
    {
        var hiddenPayload = Leaf("unrecognized-hidden-payload");
        var child = Leaf("unrecognized-child");
        var root = Leaf("unrecognized-root");
        var unrecognized = new ContainerReadResult(
            false,
            ArtifactCompleteness.Malformed,
            ImmutableArray.Create(Entry("../../../hidden.dll", hiddenPayload)),
            ImmutableArray.Create(new ArtifactObservationFact(
                "container.malformed", "This fact must be ignored for unrecognized bytes.",
                ParserConfidence.High)));
        var rawRootProvider = new TestContainerProvider().Register(root, unrecognized);
        var nestedProvider = new TestContainerProvider()
            .Register(root, Entry("child.bin", child))
            .Register(child, unrecognized);

        var rawRootGraph = Build(root, rawRootProvider);
        var nestedGraph = Build(root, nestedProvider);

        rawRootGraph.Artifacts.Should().ContainSingle();
        rawRootGraph.Artifacts[0].Completeness.Should().Be(ArtifactCompleteness.Complete);
        rawRootGraph.Incomplete.Should().BeFalse();
        rawRootGraph.Observations.Should().BeEmpty();
        nestedGraph.Artifacts.Should().HaveCount(2);
        nestedGraph.Artifacts.Should().AllSatisfy(artifact =>
            artifact.Completeness.Should().Be(ArtifactCompleteness.Complete));
        nestedGraph.Incomplete.Should().BeFalse();
        nestedGraph.Observations.Should().NotContain(observation =>
            observation.Kind == "container.malformed" || observation.Kind == "artifact.hostile-name");
    }

    [Fact]
    public void Build_RootContainerInput_PreservesRecognizedMalformedCompleteness()
    {
        var root = new RootContainerInput(
            new ArtifactNode("root", string.Empty, Sha(Leaf("malformed-root")), 0,
                ArtifactCompleteness.Malformed, ImmutableArray<string>.Empty),
            ImmutableArray<ContainerEntry>.Empty,
            ImmutableArray.Create(new ArtifactObservationFact(
                "container.malformed", "Recognized header; directory is unreadable.",
                ParserConfidence.High)));

        var graph = ArtifactGraphBuilder.Build(root, new TestContainerProvider());

        graph.Incomplete.Should().BeTrue();
        graph.Artifacts.Single().Completeness.Should().Be(ArtifactCompleteness.Malformed);
        graph.Observations.Should().Contain(observation => observation.Kind == "container.malformed");
    }

    [Theory]
    [InlineData(ArtifactCompleteness.Malformed)]
    [InlineData(ArtifactCompleteness.Encrypted)]
    [InlineData(ArtifactCompleteness.Unsupported)]
    [InlineData(ArtifactCompleteness.TruncatedByPolicy)]
    public void Build_RecognizedIncompleteNestedContainer_MarksTheArtifactAndParentIncomplete(
        ArtifactCompleteness completeness)
    {
        var child = Leaf("recognized-incomplete-child");
        var root = Leaf("recognized-incomplete-root");
        var result = ContainerReadResult.Recognized(
            completeness,
            ImmutableArray<ContainerEntry>.Empty,
            ImmutableArray.Create(new ArtifactObservationFact(
                "container.incomplete", "Recognized container could not be completely inspected.",
                ParserConfidence.High)));
        var provider = new TestContainerProvider()
            .Register(root, Entry("child.container", child))
            .Register(child, result);

        var graph = Build(root, provider);

        graph.Incomplete.Should().BeTrue();
        graph.Artifacts.Should().HaveCount(2);
        graph.Artifacts.Should().AllSatisfy(artifact => artifact.Completeness.Should().Be(completeness));
        graph.Observations.Should().Contain(observation =>
            observation.Kind == "container.incomplete" && observation.Source.ArtifactId == "art-0001");
    }

    [Fact]
    public void Build_EntryStreamUnavailable_MarksTheParentUnavailableAndAddsAnObservation()
    {
        var root = Leaf("unavailable-entry-root");
        var provider = new TestContainerProvider().Register(
            root,
            new ContainerEntry("unreadable.bin", 1, 1, () => throw new IOException("fixture read failure")));

        var graph = Build(root, provider);

        graph.Incomplete.Should().BeTrue();
        graph.Artifacts.Should().ContainSingle();
        graph.Artifacts[0].Completeness.Should().Be(ArtifactCompleteness.Unavailable);
        graph.Observations.Should().Contain(observation =>
            observation.Kind == "artifact.unavailable" && observation.Source.ArtifactId == "root");
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
