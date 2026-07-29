using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
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

    public static ArtifactGraph Build(
        ReadOnlyMemory<byte> rootContent,
        string rootSha256,
        IContainerProvider provider,
        ExtractionBudget? budget = null)
    {
        ArgumentNullException.ThrowIfNull(rootSha256);
        ArgumentNullException.ThrowIfNull(provider);
        budget ??= new ExtractionBudget();

        var artifacts = new List<ArtifactNode>();
        var observations = ImmutableArray.CreateBuilder<Observation>();
        var sequences = new Dictionary<string, int>(StringComparer.Ordinal);

        // SHA-256 -> index into `artifacts`, the deduplication and cycle guard in one.
        var bySha = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        var root = new ArtifactNode(
            ScanArtifacts.RootId, string.Empty, rootSha256, rootContent.Length,
            ArtifactCompleteness.Complete, ImmutableArray<string>.Empty);
        artifacts.Add(root);
        bySha[rootSha256] = 0;
        budget.ChargeArtifact();

        var queue = new Queue<(int Index, ReadOnlyMemory<byte> Content, int Depth)>();
        queue.Enqueue((0, rootContent, 0));

        while (queue.Count > 0)
        {
            var (containerIndex, content, depth) = queue.Dequeue();
            var containerId = artifacts[containerIndex].Id;

            if (budget.Exhausted)
            {
                MarkTruncated(artifacts, containerIndex);
                continue;
            }

            var entries = provider.TryEnumerate(content);
            if (entries is null) continue;

            if (!budget.AllowsDepth(depth + 1))
            {
                MarkTruncated(artifacts, containerIndex);
                AddTruncation(observations, sequences, containerId, budget, BudgetLimit.Depth);
                continue;
            }

            WalkContainer(
                entries, containerIndex, containerId, depth,
                artifacts, observations, sequences, bySha, queue, budget, provider);
        }

        var incomplete = budget.Exhausted
            || artifacts.Exists(artifact => artifact.Completeness != ArtifactCompleteness.Complete);

        return new ArtifactGraph([.. artifacts], observations.ToImmutable(), incomplete);
    }

    private static void WalkContainer(
        IEnumerable<ContainerEntry> entries,
        int containerIndex,
        string containerId,
        int depth,
        List<ArtifactNode> artifacts,
        ImmutableArray<Observation>.Builder observations,
        Dictionary<string, int> sequences,
        Dictionary<string, int> bySha,
        Queue<(int, ReadOnlyMemory<byte>, int)> queue,
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
                MarkTruncated(artifacts, containerIndex);
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

            var (bytes, truncated) = ReadBounded(entry, budget);
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
                Add(observations, sequences, containerId, "artifact.duplicate",
                    $"Entry '{verdict.DisplayName}' has content already seen as " +
                    $"'{artifacts[existing].Id}'; it is recorded once with both parents.",
                    ParserConfidence.High);
                continue;
            }

            if (!budget.ChargeArtifact())
            {
                MarkTruncated(artifacts, containerIndex);
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

            Add(observations, sequences, containerId, "artifact.nested",
                $"Contains '{verdict.DisplayName}' ({bytes.Length} bytes, {id}).",
                ParserConfidence.High);

            if (truncated)
            {
                // The budget is spent. Grinding through the container's remaining entries
                // would burn time to produce nothing but more truncated stubs.
                MarkTruncated(artifacts, containerIndex);
                AddTruncation(observations, sequences, containerId, budget, null);
                return;
            }

            // Only recurse into content the provider recognises; everything else is a leaf.
            if (provider.TryEnumerate(bytes) is not null)
                queue.Enqueue((artifacts.Count - 1, bytes, depth + 1));
        }
    }

    /// <summary>
    /// Reads an entry in chunks, charging the budget as bytes arrive. The declared size
    /// is never used to size a buffer: an entry claiming 4 GiB stops at a ceiling rather
    /// than at its own claim.
    /// </summary>
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

    private static void MarkTruncated(List<ArtifactNode> artifacts, int index)
    {
        if (artifacts[index].Completeness == ArtifactCompleteness.Complete)
            artifacts[index] = artifacts[index] with { Completeness = ArtifactCompleteness.TruncatedByPolicy };
    }

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
        ParserConfidence confidence)
    {
        sequences.TryGetValue(artifactId, out var sequence);
        sequences[artifactId] = ++sequence;
        var id = artifactId + "-obs-" + sequence.ToString("D4", CultureInfo.InvariantCulture);
        observations.Add(new Observation(
            id, kind, description, confidence, new SourceLocation(artifactId, null, null)));
    }
}
