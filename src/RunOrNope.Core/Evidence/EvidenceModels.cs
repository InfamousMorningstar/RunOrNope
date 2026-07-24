using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Core.Evidence;

public static class EvidenceCollections
{
    public static ImmutableArray<T> Freeze<T>(IEnumerable<T> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return values.ToImmutableArray();
    }
}
