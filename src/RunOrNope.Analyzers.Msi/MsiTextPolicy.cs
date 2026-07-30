using System.Text;

namespace RunOrNope.Analyzers.Msi;

/// <summary>Converts installer-controlled text into bounded, well-formed display text.</summary>
public static class MsiTextPolicy
{
    public static MsiTextResult Sanitize(string? text, int maxScalars)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxScalars);

        text ??= string.Empty;
        var display = new StringBuilder(Math.Min(text.Length, maxScalars));
        var originalScalars = 0;
        var displayedScalars = 0;
        var neutralized = false;
        var truncated = false;

        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            var isPair = char.IsHighSurrogate(character)
                && index + 1 < text.Length
                && char.IsLowSurrogate(text[index + 1]);
            var unsafeScalar = !isPair && (char.IsSurrogate(character) || IsUnsafe(character));

            originalScalars++;
            if (displayedScalars >= maxScalars)
            {
                truncated = true;
                if (unsafeScalar) neutralized = true;
                if (isPair) index++;
                continue;
            }

            if (unsafeScalar)
            {
                display.Append('.');
                neutralized = true;
            }
            else if (isPair)
            {
                display.Append(character);
                display.Append(text[++index]);
            }
            else
            {
                display.Append(character);
            }

            displayedScalars++;
        }

        return new MsiTextResult(display.ToString(), neutralized, truncated, originalScalars);
    }

    private static bool IsUnsafe(char character) =>
        character <= '\u001f'
        || character is >= '\u007f' and <= '\u009f'
        || character is '\u061c' or '\u200e' or '\u200f'
            or '\u202a' or '\u202b' or '\u202c' or '\u202d' or '\u202e'
            or '\u2066' or '\u2067' or '\u2068' or '\u2069';
}
