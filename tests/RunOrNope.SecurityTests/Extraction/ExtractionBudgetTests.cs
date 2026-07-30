using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Contracts;
using Xunit;
// The provider is compiled into this project from the unit tests via a linked Compile
// item, so it keeps its original namespace here.
using RunOrNope.UnitTests.Content;
using static RunOrNope.UnitTests.Content.TestContainerProvider;

namespace RunOrNope.SecurityTests.Extraction;

/// <summary>
/// The ceilings that keep a hostile container from consuming the host. Every case must
/// degrade to <see cref="ArtifactCompleteness.TruncatedByPolicy"/> — never an exception,
/// and never a favourable result.
/// </summary>
public sealed class ExtractionBudgetTests
{
    [Fact]
    public void DeduplicatedEntries_AreStillChargedToTheBudget()
    {
        // The anti-evasion property. Identity deduplication keeps one node, but if the
        // budget only charged unique content a container could repeat one payload for
        // unlimited free expansion — the very trick deduplication looks like it stops.
        var payload = Leaf("repeated-payload");
        var root = Leaf("root-container");
        var entries = Enumerable.Range(0, 5_000)
            .Select(index => Entry($"copy-{index}.dll", payload))
            .ToArray();
        var provider = new TestContainerProvider().Register(root, entries);
        var budget = new ExtractionBudget();

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        graph.Artifacts.Should().HaveCount(2, "identical content deduplicates to one node");
        budget.EntriesCharged.Should().Be(5_000, "every logical entry is charged");
        graph.Artifacts[1].ParentIds.Should().Equal("root");
    }

    [Fact]
    public void RepeatedLargePayload_TripsTheTotalByteCeiling()
    {
        // Ten thousand copies of a megabyte: trivial to describe, 10 GiB to expand.
        var root = Leaf("bomb-container");
        var entries = Enumerable.Range(0, 10_000)
            .Select(index => Endless($"copy-{index}.bin", 1 << 20, 1 << 20))
            .ToArray();
        var provider = new TestContainerProvider().Register(root, entries);
        var budget = new ExtractionBudget();

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        budget.Stops.Should().Contain(BudgetLimit.TotalExpandedBytes);
        budget.TotalExpandedBytes.Should()
            .BeLessThan(budget.Ceilings.MaxTotalExpandedBytes + (1 << 20), "the stop is prompt");
        AssertTruncated(graph);
    }

    [Fact]
    public void SingleOversizedEntry_TripsTheArtifactByteCeiling()
    {
        var root = Leaf("root-container");
        var provider = new TestContainerProvider()
            .Register(root, Endless("huge.bin", 4L << 30, 4L << 30));
        var budget = new ExtractionBudget();

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        budget.Stops.Should().Contain(BudgetLimit.ArtifactBytes);
        AssertTruncated(graph);
    }

    [Fact]
    public void HighlyCompressibleEntry_TripsTheExpansionRatioCeiling()
    {
        var root = Leaf("root-container");
        // One kilobyte compressed claiming to expand to sixty-four megabytes.
        var provider = new TestContainerProvider()
            .Register(root, Endless("bomb.bin", 64 << 20, 64 << 20, compressedSize: 1024));
        var budget = new ExtractionBudget();

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        budget.Stops.Should().Contain(BudgetLimit.ExpansionRatio);
        AssertTruncated(graph);
    }

    [Fact]
    public void NestingBeyondMaxDepth_StopsTheWalk()
    {
        var ceilings = new ExtractionCeilings { MaxDepth = 3 };
        var budget = new ExtractionBudget(ceilings);

        // A chain of containers one level deeper than the ceiling allows.
        var provider = new TestContainerProvider();
        var levels = Enumerable.Range(0, 6).Select(i => Leaf($"level-{i}")).ToArray();
        for (var i = 0; i < levels.Length - 1; i++)
            provider.Register(levels[i], Entry($"level-{i + 1}.zip", levels[i + 1]));

        var graph = ArtifactGraphBuilder.Build(levels[0], Sha(levels[0]), provider, budget);

        budget.Stops.Should().Contain(BudgetLimit.Depth);
        AssertTruncated(graph);
    }

    [Fact]
    public void ContainerClaimingTooManyEntries_StopsAtTheEntryCeiling()
    {
        var ceilings = new ExtractionCeilings { MaxEntriesPerContainer = 64 };
        var budget = new ExtractionBudget(ceilings);
        var root = Leaf("root-container");
        var provider = new TestContainerProvider().Register(
            root,
            [.. Enumerable.Range(0, 5_000).Select(i => Entry($"e-{i}.dat", Leaf($"payload-{i}")))]);

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        budget.Stops.Should().Contain(BudgetLimit.EntriesPerContainer);
        // Enumeration is lazy: the ceiling bounds work, not just the reported result.
        budget.EntriesCharged.Should().BeLessThanOrEqualTo(65);
        AssertTruncated(graph);
    }

    [Fact]
    public void ArtifactCeiling_StaysBelowTheContractLimit()
    {
        var ceilings = new ExtractionCeilings { MaxArtifacts = 32 };
        var budget = new ExtractionBudget(ceilings);
        var root = Leaf("root-container");
        var provider = new TestContainerProvider().Register(
            root,
            [.. Enumerable.Range(0, 500).Select(i => Entry($"e-{i}.dat", Leaf($"payload-{i}")))]);

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        budget.Stops.Should().Contain(BudgetLimit.Artifacts);
        graph.Artifacts.Length.Should().BeLessThanOrEqualTo(ceilings.MaxArtifacts);
        graph.Artifacts.Length.Should().BeLessThan(ContractLimits.MaxArtifacts);
        AssertTruncated(graph);
    }

    [Fact]
    public void RootBeyondTheArtifactCeiling_IsTruncatedEvenWhenItHasNoEntries()
    {
        var budget = new ExtractionBudget(new ExtractionCeilings { MaxArtifacts = 0 });
        var root = Leaf("ordinary-root");

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), new TestContainerProvider(), budget);

        budget.Stops.Should().Contain(BudgetLimit.Artifacts);
        AssertTruncated(graph);
    }

    [Fact]
    public void DefaultCeilingsSitBelowTheContractLimits()
    {
        // A graph built right up to the budget must still validate at the boundary.
        ExtractionCeilings.Default.MaxArtifacts.Should().BeLessThan(ContractLimits.MaxArtifacts);
    }

    [Fact]
    public void EntryDeclaringLessThanItDelivers_IsBoundedByBytesNotTheClaim()
    {
        var root = Leaf("root-container");
        // Claims a kilobyte, streams four gigabytes. Trusting the claim would be fatal.
        var provider = new TestContainerProvider()
            .Register(root, Endless("understated.bin", declaredSize: 1024, totalBytes: 4L << 30));
        var budget = new ExtractionBudget();

        var graph = ArtifactGraphBuilder.Build(root, Sha(root), provider, budget);

        budget.Stops.Should().NotBeEmpty();
        budget.TotalExpandedBytes.Should().BeLessThan(4L << 30);
        AssertTruncated(graph);
    }

    /// <summary>
    /// Every ceiling ends the same way: a truncated graph that the contract accepts and
    /// that can never be reported as a complete analysis.
    /// </summary>
    private static void AssertTruncated(ArtifactGraph graph)
    {
        graph.Incomplete.Should().BeTrue();
        graph.Artifacts.Should().Contain(a => a.Completeness == ArtifactCompleteness.TruncatedByPolicy);

        var result = new ScanResult(
            string.Empty, AnalysisStatus.Incomplete, ArtifactCompleteness.TruncatedByPolicy,
            graph.Artifacts, graph.Observations, [], []);
        ContractValidator.Validate(result);
        graph.Observations.Should().Contain(o => o.Kind == "artifact.truncated");
    }
}
