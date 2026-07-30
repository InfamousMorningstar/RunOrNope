using System.Text;

namespace RunOrNope.Analyzers.Msi;

/// <summary>Resolves MSI directory keys to display-only strings without filesystem access.</summary>
public static class MsiDirectoryResolver
{
    public static MsiDirectoryResolution Resolve(
        string key,
        IReadOnlyDictionary<string, MsiDirectoryRow> rows,
        MsiAnalysisLimits limits)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var segments = new List<string>();
        var currentKey = key;
        var status = MsiDirectoryStatus.Complete;

        while (true)
        {
            if (!rows.TryGetValue(currentKey, out var row) || row is null)
            {
                status = MsiDirectoryStatus.Orphan;
                break;
            }

            if (!seen.Add(currentKey))
            {
                status = MsiDirectoryStatus.Cycle;
                break;
            }

            var text = MsiTextPolicy.Sanitize(row.DefaultDirectory, limits.MaxTextScalars);
            segments.Add(text.DisplayText);
            if (text.WasTruncated)
                status = MsiDirectoryStatus.LengthExceeded;

            if (string.IsNullOrEmpty(row.ParentKey)) break;
            if (StringComparer.Ordinal.Equals(currentKey, row.ParentKey))
            {
                status = MsiDirectoryStatus.SelfParent;
                break;
            }

            if (seen.Count >= limits.MaxDirectoryDepth)
            {
                status = MsiDirectoryStatus.DepthExceeded;
                break;
            }

            currentKey = row.ParentKey;
        }

        segments.Reverse();
        var path = BuildBoundedPath(segments, limits.MaxTextScalars, ref status);
        return new MsiDirectoryResolution(path, status);
    }

    private static string BuildBoundedPath(
        IEnumerable<string> segments,
        int maxScalars,
        ref MsiDirectoryStatus status)
    {
        var builder = new StringBuilder();
        var scalars = 0;
        var isFirst = true;
        foreach (var segment in segments)
        {
            if (!isFirst && !TryAppend(builder, "\\", maxScalars, ref scalars))
            {
                status = MsiDirectoryStatus.LengthExceeded;
                break;
            }

            if (!TryAppend(builder, segment, maxScalars, ref scalars))
            {
                status = MsiDirectoryStatus.LengthExceeded;
                break;
            }

            isFirst = false;
        }

        return builder.ToString();
    }

    private static bool TryAppend(StringBuilder builder, string value, int maxScalars, ref int scalars)
    {
        foreach (var rune in value.EnumerateRunes())
        {
            if (scalars >= maxScalars) return false;
            builder.Append(rune.ToString());
            scalars++;
        }

        return true;
    }
}
