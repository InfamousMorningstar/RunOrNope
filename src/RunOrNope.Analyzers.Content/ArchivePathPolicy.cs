using System.Buffers;
using System.Collections.Immutable;
using System.Text;

namespace RunOrNope.Analyzers.Content;

/// <summary>Why a container's claimed entry name is not safe to repeat verbatim.</summary>
public enum PathIssue
{
    Empty,
    Traversal,
    Rooted,
    DeviceName,
    AlternateDataStream,
    ControlCharacter,
    TrailingDotOrSpace,
    TooLong,
}

/// <summary>
/// A claimed entry name reduced to something safe to display, plus what was wrong with
/// it. <see cref="DisplayName"/> is never used to locate a file — see
/// <see cref="ArchivePathPolicy"/>.
/// </summary>
public sealed record ArchivePathVerdict(string DisplayName, ImmutableArray<PathIssue> Issues)
{
    public bool IsHostile => !Issues.IsEmpty;

    public string Describe() => string.Join(", ", Issues.Select(Description));

    private static string Description(PathIssue issue) => issue switch
    {
        PathIssue.Empty => "the name is empty",
        PathIssue.Traversal => "it contains parent-directory traversal",
        PathIssue.Rooted => "it is an absolute, drive-rooted, or UNC path",
        PathIssue.DeviceName => "it names a reserved DOS device",
        PathIssue.AlternateDataStream => "it contains an alternate-data-stream separator",
        PathIssue.ControlCharacter => "it contains control or bidirectional characters",
        PathIssue.TrailingDotOrSpace => "it ends in a dot or space",
        PathIssue.TooLong => "it exceeds the reportable length",
        _ => "it is malformed",
    };
}

/// <summary>
/// Classifies the names a container claims for its entries.
///
/// This policy governs <b>display and identity only</b>. Nothing here decides where
/// bytes are read from or written to: the walk never passes a sample-controlled string
/// to a filesystem API, so a traversal sequence in an entry name is a fact to report,
/// not an escape to prevent. A hostile name never suppresses analysis of the content —
/// refusing to look at a payload because its name was ugly is exactly the
/// favourable-on-absence failure the project forbids.
/// </summary>
public static class ArchivePathPolicy
{
    /// <summary>Bounded well below the contract's string ceiling; names are for reading.</summary>
    public const int MaxDisplayLength = 260;

    private static readonly SearchValues<char> Separators = SearchValues.Create("/\\");

    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static ArchivePathVerdict Classify(string? claimedName)
    {
        var issues = new SortedSet<PathIssue>();
        var raw = claimedName ?? string.Empty;

        if (raw.Length == 0) issues.Add(PathIssue.Empty);
        if (raw.Length > MaxDisplayLength) issues.Add(PathIssue.TooLong);

        // Both separators are examined regardless of platform: a container authored on
        // one convention is routinely read on the other, and a name that is inert under
        // one reading can be a traversal under the other.
        var segments = raw.Split(['/', '\\'], StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (segment == "..") issues.Add(PathIssue.Traversal);

            var trimmed = segment.TrimEnd(' ', '.');
            if (trimmed.Length != segment.Length && segment.Length > 0)
                issues.Add(PathIssue.TrailingDotOrSpace);

            // Windows resolves a device name whether or not an extension follows it.
            var stem = trimmed.Split('.')[0];
            if (ReservedDeviceNames.Contains(stem)) issues.Add(PathIssue.DeviceName);

            if (segment.Contains(':')) issues.Add(PathIssue.AlternateDataStream);
        }

        if (IsRooted(raw)) issues.Add(PathIssue.Rooted);

        foreach (var character in raw)
        {
            if (IsUnsafeCharacter(character))
            {
                issues.Add(PathIssue.ControlCharacter);
                break;
            }
        }

        return new ArchivePathVerdict(Sanitize(raw), [.. issues]);
    }

    private static bool IsRooted(string raw)
    {
        if (raw.Length == 0) return false;
        if (Separators.Contains(raw[0])) return true;                       // "/x" and "\\server\share"
        return raw.Length >= 2 && raw[1] == ':' && char.IsAsciiLetter(raw[0]); // "C:\x"
    }

    /// <summary>
    /// Control characters, bidirectional overrides, and lone surrogates become '.', so a
    /// claimed name can be shown in a report without reordering the text around it or
    /// tripping the contract's malformed-Unicode check.
    /// </summary>
    private static string Sanitize(string raw)
    {
        if (raw.Length == 0) return "(unnamed)";

        var builder = new StringBuilder(Math.Min(raw.Length, MaxDisplayLength));
        var appended = 0;
        for (var index = 0; index < raw.Length && appended < MaxDisplayLength; index++, appended++)
        {
            var character = raw[index];
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 < raw.Length && char.IsLowSurrogate(raw[index + 1]))
                {
                    builder.Append(character).Append(raw[index + 1]);
                    index++;
                    continue;
                }
                builder.Append('.');
                continue;
            }
            builder.Append(IsUnsafeCharacter(character) || char.IsLowSurrogate(character) ? '.' : character);
        }

        return builder.Length == 0 ? "(unnamed)" : builder.ToString();
    }

    private static bool IsUnsafeCharacter(char character) =>
        char.IsControl(character)
        || character is '\u202A' or '\u202B' or '\u202C' or '\u202D' or '\u202E'
            or '\u2066' or '\u2067' or '\u2068' or '\u2069'
            or '\u200E' or '\u200F';
}
