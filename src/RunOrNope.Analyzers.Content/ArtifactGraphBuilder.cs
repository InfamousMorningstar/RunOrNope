using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using RunOrNope.Contracts;

namespace RunOrNope.Analyzers.Content;

/// <summary>
/// Walks a sample's nested content into a deduplicated artifact graph.
///
/// The graph is a DAG rather than a tree: nodes are identified by SHA-256, so the same
/// bytes reached by two paths are one node carrying both parents. That is also what makes
/// the walk cycle-safe by construction — a container embedding its own bytes hashes to a
/// node that already exists, so the builder records the edge and does not recurse.
///
/// No sample-controlled string ever reaches a filesystem API here: content is held in
/// memory, bounded by <see cref="ExtractionCeilings.MaxArtifactBytes"/>, and entry names
/// are classified for display only.
/// </summary>
public static class ArtifactGraphBuilder
{
    private const int ReadChunkBytes = 64 * 1024;
    private const string UnavailableDescription =
        "The container or one of its entries could not be read; content beyond the failure was not examined.";

    /// <summary>
    /// Compatibility adapter for callers that begin with raw root bytes. The root is
    /// initially complete, then receives the provider's single read result before the
    /// graph walk begins.
    /// </summary>
    public static ArtifactGraph Build(
        ReadOnlyMemory<byte> rootContent,
        string rootSha256,
        IContainerProvider provider,
        ExtractionBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(rootSha256);
        ArgumentNullException.ThrowIfNull(provider);

        var root = new ArtifactNode(
            ScanArtifacts.RootId, string.Empty, rootSha256, rootContent.Length,
            ArtifactCompleteness.Complete, ImmutableArray<string>.Empty);
        var read = ReadContainer(provider, rootContent);
        var rootInput = new RootContainerInput(
            root with { Completeness = read.Completeness },
            read.Entries,
            read.Observations);

        return Build(rootInput, provider, budget);
    }

    public static ArtifactGraph Build(
        RootContainerInput rootInput,
        IContainerProvider provider,
        ExtractionBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(rootInput);
        ArgumentNullException.ThrowIfNull(rootInput.Root);
        ArgumentNullException.ThrowIfNull(provider);
        budget ??= new ExtractionBudget();

        var artifacts = new List<ArtifactNode> { rootInput.Root };
        var observations = ImmutableArray.CreateBuilder<Observation>();
        var sequences = new Dictionary<string, int>(StringComparer.Ordinal);
        var bySha = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            [rootInput.Root.Sha256] = 0,
        };
        var byId = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [rootInput.Root.Id] = 0,
        };
        AddFacts(observations, sequences, rootInput.Root.Id, rootInput.Observations);

        if (!budget.ChargeArtifact())
        {
            MergeCompletenessAndPropagate(
                artifacts, byId, 0, ArtifactCompleteness.TruncatedByPolicy);
            AddTruncation(observations, sequences, rootInput.Root.Id, budget, BudgetLimit.Artifacts);
            return new ArtifactGraph([.. artifacts], observations.ToImmutable(), true);
        }

        var queue = new Queue<(int Index, ImmutableArray<ContainerEntry> Entries, int Depth)>();
        if (!rootInput.Entries.IsDefaultOrEmpty)
            queue.Enqueue((0, rootInput.Entries, 0));

        while (queue.Count > 0)
        {
            var (containerIndex, entries, depth) = queue.Dequeue();
            var containerId = artifacts[containerIndex].Id;

            if (budget.Exhausted)
            {
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, ArtifactCompleteness.TruncatedByPolicy);
                AddTruncation(observations, sequences, containerId, budget, null);
                continue;
            }

            if (!budget.AllowsDepth(depth + 1))
            {
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, ArtifactCompleteness.TruncatedByPolicy);
                AddTruncation(observations, sequences, containerId, budget, BudgetLimit.Depth);
                continue;
            }

            WalkContainer(
                entries, containerIndex, containerId, depth,
                artifacts, observations, sequences, bySha, byId, queue, budget, provider);
        }

        var incomplete = budget.Exhausted
            || artifacts.Exists(artifact => artifact.Completeness != ArtifactCompleteness.Complete);

        return new ArtifactGraph([.. artifacts], observations.ToImmutable(), incomplete);
    }

    private static void WalkContainer(
        ImmutableArray<ContainerEntry> entries,
        int containerIndex,
        string containerId,
        int depth,
        List<ArtifactNode> artifacts,
        ImmutableArray<Observation>.Builder observations,
        Dictionary<string, int> sequences,
        Dictionary<string, int> bySha,
        Dictionary<string, int> byId,
        Queue<(int Index, ImmutableArray<ContainerEntry> Entries, int Depth)> queue,
        ExtractionBudget budget,
        IContainerProvider provider)
    {
        // Names already claimed in this container, to spot collisions that differ only
        // by case — two such entries are one file on Windows and two in the archive.
        var claimedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entryIndex = 0;

        foreach (var entry in entries)
        {
            if (entry is null) continue;

            if (!budget.ChargeEntry(entryIndex++))
            {
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, ArtifactCompleteness.TruncatedByPolicy);
                AddTruncation(observations, sequences, containerId, budget, BudgetLimit.EntriesPerContainer);
                return;
            }

            var verdict = ArchivePathPolicy.Classify(entry.ClaimedName);
            if (verdict.IsHostile)
            {
                Add(observations, sequences, containerId, "artifact.hostile-name",
                    $"Entry '{verdict.DisplayName}' has an unsafe claimed name: {verdict.Describe()}. " +
                    "The name was not used to locate anything; its content was still analysed.",
                    ParserConfidence.High);
            }

            if (!claimedNames.Add(verdict.DisplayName))
            {
                Add(observations, sequences, containerId, "artifact.hostile-name",
                    $"Entry '{verdict.DisplayName}' collides with an earlier entry in the same " +
                    "container when compared case-insensitively.",
                    ParserConfidence.High);
            }

            if (!TryReadBounded(entry, budget, out var bytes, out var truncated))
            {
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, ArtifactCompleteness.Unavailable);
                AddUnavailable(observations, sequences, containerId);
                return;
            }

            if (entry.DeclaredSize >= 0 && entry.DeclaredSize != bytes.Length && !truncated)
            {
                Add(observations, sequences, containerId, "artifact.size-mismatch",
                    $"Entry '{verdict.DisplayName}' declared {entry.DeclaredSize} bytes but delivered " +
                    $"{bytes.Length}.",
                    ParserConfidence.High);
            }

            var sha = Convert.ToHexStringLower(SHA256.HashData(bytes));

            if (bySha.TryGetValue(sha, out var existing))
            {
                // Same bytes, another path: one node, an extra parent edge. This is also
                // what terminates a container that embeds itself.
                artifacts[existing] = AddParent(artifacts[existing], containerId);
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, artifacts[existing].Completeness);
                Add(observations, sequences, containerId, "artifact.duplicate",
                    $"Entry '{verdict.DisplayName}' has content already seen as " +
                    $"'{artifacts[existing].Id}'; it is recorded once with both parents.",
                    ParserConfidence.High);
                continue;
            }

            if (!budget.ChargeArtifact())
            {
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, ArtifactCompleteness.TruncatedByPolicy);
                AddTruncation(observations, sequences, containerId, budget, BudgetLimit.Artifacts);
                return;
            }

            var id = "art-" + artifacts.Count.ToString("D4", CultureInfo.InvariantCulture);
            var node = new ArtifactNode(
                id, verdict.DisplayName, sha, bytes.Length,
                truncated ? ArtifactCompleteness.TruncatedByPolicy : ArtifactCompleteness.Complete,
                ImmutableArray.Create(containerId));

            artifacts.Add(node);
            bySha[sha] = artifacts.Count - 1;
            byId[id] = artifacts.Count - 1;

            Add(observations, sequences, containerId, "artifact.nested",
                $"Contains '{verdict.DisplayName}' ({bytes.Length} bytes, {id}).",
                ParserConfidence.High);

            if (truncated)
            {
                MergeCompletenessAndPropagate(
                    artifacts, byId, containerIndex, ArtifactCompleteness.TruncatedByPolicy);
                AddTruncation(observations, sequences, containerId, budget, null);
                return;
            }

            var read = ReadContainer(provider, bytes);
            AddFacts(observations, sequences, id, read.Observations);
            MergeCompletenessAndPropagate(artifacts, byId, artifacts.Count - 1, read.Completeness);

            if (read.IsRecognized)
                queue.Enqueue((artifacts.Count - 1, read.Entries, depth + 1));
        }
    }

    private static ContainerReadResult ReadContainer(IContainerProvider provider, ReadOnlyMemory<byte> content)
    {
        try
        {
            return provider.Read(content);
        }
        catch (IOException)
        {
            return UnavailableResult();
        }
        catch (InvalidDataException)
        {
            return UnavailableResult();
        }
        catch (OverflowException)
        {
            return UnavailableResult();
        }
        catch (UnauthorizedAccessException)
        {
            return UnavailableResult();
        }
    }

    private static ContainerReadResult UnavailableResult() =>
        ContainerReadResult.Recognized(
            ArtifactCompleteness.Unavailable,
            ImmutableArray<ContainerEntry>.Empty,
            ImmutableArray.Create(new ArtifactObservationFact(
                "artifact.unavailable", UnavailableDescription, ParserConfidence.High)));

    /// <summary>
    /// Reads an entry in chunks, charging the budget as bytes arrive. The declared size
    /// is never used to size a buffer: an entry claiming 4 GiB stops at a ceiling rather
    /// than at its own claim.
    /// </summary>
    private static bool TryReadBounded(
        ContainerEntry entry,
        ExtractionBudget budget,
        out byte[] bytes,
        out bool truncated)
    {
        try
        {
            (bytes, truncated) = ReadBounded(entry, budget);
            return true;
        }
        catch (IOException)
        {
        }
        catch (InvalidDataException)
        {
        }
        catch (OverflowException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        bytes = [];
        truncated = false;
        return false;
    }

    private static (byte[] Bytes, bool Truncated) ReadBounded(ContainerEntry entry, ExtractionBudget budget)
    {
        using var stream = entry.Open();
        var buffer = ArrayPool<byte>.Shared.Rent(ReadChunkBytes);
        var collected = new List<byte>();
        var truncated = false;
        try
        {
            long total = 0;
            while (true)
            {
                var read = stream.Read(buffer, 0, ReadChunkBytes);
                if (read <= 0) break;
                total += read;
                if (!budget.ChargeBytes(read, total, entry.CompressedSize))
                {
                    truncated = true;
                    break;
                }
                collected.AddRange(buffer.AsSpan(0, read));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return ([.. collected], truncated);
    }

    private static ArtifactNode AddParent(ArtifactNode node, string parentId) =>
        node.ParentIds.Contains(parentId, StringComparer.Ordinal)
            ? node
            : node with { ParentIds = node.ParentIds.Add(parentId) };

    private static void MergeCompletenessAndPropagate(
        List<ArtifactNode> artifacts,
        Dictionary<string, int> byId,
        int index,
        ArtifactCompleteness completeness)
    {
        var pending = new Queue<(int Index, ArtifactCompleteness Completeness)>();
        pending.Enqueue((index, completeness));

        while (pending.Count > 0)
        {
            var (currentIndex, incoming) = pending.Dequeue();
            var current = artifacts[currentIndex];
            var merged = MoreIncomplete(current.Completeness, incoming);
            if (merged == current.Completeness) continue;

            artifacts[currentIndex] = current with { Completeness = merged };
            foreach (var parentId in current.ParentIds)
            {
                if (byId.TryGetValue(parentId, out var parentIndex))
                    pending.Enqueue((parentIndex, merged));
            }
        }
    }

    private static ArtifactCompleteness MoreIncomplete(
        ArtifactCompleteness left,
        ArtifactCompleteness right) =>
        CompletenessRank(left) >= CompletenessRank(right) ? left : right;

    private static int CompletenessRank(ArtifactCompleteness completeness) => completeness switch
    {
        ArtifactCompleteness.Complete => 0,
        ArtifactCompleteness.TruncatedByPolicy => 1,
        ArtifactCompleteness.Unsupported => 2,
        ArtifactCompleteness.Encrypted => 3,
        ArtifactCompleteness.Malformed => 4,
        ArtifactCompleteness.Unavailable => 5,
        _ => throw new ArgumentOutOfRangeException(nameof(completeness)),
    };

    private static void AddFacts(
        ImmutableArray<Observation>.Builder observations,
        Dictionary<string, int> sequences,
        string artifactId,
        ImmutableArray<ArtifactObservationFact> facts)
    {
        foreach (var fact in facts)
            Add(observations, sequences, artifactId, fact.Kind, fact.Description,
                fact.ParserConfidence, fact.Offset, fact.Region);
    }

    private static void AddUnavailable(
        ImmutableArray<Observation>.Builder observations,
        Dictionary<string, int> sequences,
        string artifactId) =>
        Add(observations, sequences, artifactId, "artifact.unavailable",
            UnavailableDescription, ParserConfidence.High);

    private static void AddTruncation(
        ImmutableArray<Observation>.Builder observations,
        Dictionary<string, int> sequences,
        string artifactId,
        ExtractionBudget budget,
        BudgetLimit? limit)
    {
        var which = limit is { } value
            ? ExtractionBudget.Describe(value)
            : string.Join(", ", budget.Stops.Select(ExtractionBudget.Describe));
        Add(observations, sequences, artifactId, "artifact.truncated",
            $"The walk stopped at a policy ceiling ({(which.Length == 0 ? "an extraction ceiling" : which)}); " +
            "content beyond it was not examined.",
            ParserConfidence.High);
    }

    private static void Add(
        ImmutableArray<Observation>.Builder observations,
        Dictionary<string, int> sequences,
        string artifactId,
        string kind,
        string description,
        ParserConfidence confidence,
        long? offset = null,
        string? region = null)
    {
        sequences.TryGetValue(artifactId, out var sequence);
        sequences[artifactId] = ++sequence;
        var id = artifactId + "-obs-" + sequence.ToString("D4", CultureInfo.InvariantCulture);
        observations.Add(new Observation(
            id, kind, description, confidence, new SourceLocation(artifactId, offset, region)));
    }
}
