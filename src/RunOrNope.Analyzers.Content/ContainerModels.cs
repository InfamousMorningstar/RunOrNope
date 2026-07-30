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

public sealed record ArtifactObservationFact(
    string Kind,
    string Description,
    ParserConfidence ParserConfidence,
    long? Offset = null,
    string? Region = null);

public sealed record ContainerReadResult(
    bool IsRecognized,
    ArtifactCompleteness Completeness,
    ImmutableArray<ContainerEntry> Entries,
    ImmutableArray<ArtifactObservationFact> Observations)
{
    public static ContainerReadResult NotRecognized { get; } =
        new(false, ArtifactCompleteness.Complete,
            ImmutableArray<ContainerEntry>.Empty,
            ImmutableArray<ArtifactObservationFact>.Empty);

    public static ContainerReadResult Recognized(
        ArtifactCompleteness completeness,
        ImmutableArray<ContainerEntry> entries,
        ImmutableArray<ArtifactObservationFact> observations) =>
        new(true, completeness, entries, observations);
}

public sealed record RootContainerInput(
    ArtifactNode Root,
    ImmutableArray<ContainerEntry> Entries,
    ImmutableArray<ArtifactObservationFact> Observations);

/// <summary>
/// Recognises a container format and returns a bounded description of what it claims to
/// hold. The result carries recognition and completeness separately so a malformed or
/// encrypted container can never be mistaken for an ordinary leaf.
/// </summary>
public interface IContainerProvider
{
    ContainerReadResult Read(ReadOnlyMemory<byte> content);
}

/// <summary>The artifact DAG and the observations describing how it was built.</summary>
public sealed record ArtifactGraph(
    ImmutableArray<ArtifactNode> Artifacts,
    ImmutableArray<Observation> Observations,
    bool Incomplete);
