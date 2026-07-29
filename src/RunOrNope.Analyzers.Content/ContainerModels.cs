using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Analyzers.Content;

/// <summary>
/// One entry as a container claims it. <see cref="DeclaredSize"/> and
/// <see cref="ClaimedName"/> are attacker-controlled and are never trusted: the name is
/// classified for display only, and the size is compared against the bytes actually
/// delivered rather than used to reserve or bound anything.
/// </summary>
public sealed record ContainerEntry(string ClaimedName, long DeclaredSize, long CompressedSize, Func<Stream> Open);

/// <summary>
/// Recognises a container format and lists what it claims to hold. Implementations are
/// lazy: the walk stops pulling entries once a ceiling is reached, so a directory
/// claiming millions of entries costs only the ones actually examined.
/// </summary>
public interface IContainerProvider
{
    /// <summary>Entries when the bytes are a recognised container, otherwise <c>null</c>.</summary>
    IEnumerable<ContainerEntry>? TryEnumerate(ReadOnlyMemory<byte> content);
}

/// <summary>The artifact DAG and the observations describing how it was built.</summary>
public sealed record ArtifactGraph(
    ImmutableArray<ArtifactNode> Artifacts,
    ImmutableArray<Observation> Observations,
    bool Incomplete);
