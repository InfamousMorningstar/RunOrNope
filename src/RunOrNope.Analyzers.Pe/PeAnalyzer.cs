using System.Collections.Immutable;
using AsmResolver.PE;

namespace RunOrNope.Analyzers.Pe;

public sealed class PeAnalyzer(IAuthenticodeTrustBackend? trustBackend = null) : IArtifactAnalyzer
{
    private readonly AuthenticodeVerifier _trust = new(trustBackend ?? new WindowsAuthenticodeTrustBackend());

    public async ValueTask<PeAnalysisResult> AnalyzeAsync(
        ArtifactInput input,
        AnalysisContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();
        var layout = MinimalPeReader.Parse(input.Content, input.Length, cancellationToken);
        input.Content.Position = 0;
        var clr = ClrMetadataAnalyzer.Analyze(input.Content, input.Length, new ClrAnalysisLimits());
        input.Content.Position = 0;
        var trust = await _trust.VerifyAsync(input.Content, cancellationToken).ConfigureAwait(false);

        var limitations = ImmutableArray.CreateBuilder<string>();
        var richAgreed = false;
        var richSummary = new RichPeSummary(0, 0, 0, 0, false, false, [], []);
        if (context.MaximumRichParserBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(context));
        if (input.Length > context.MaximumRichParserBytes || input.Length > int.MaxValue)
        {
            limitations.Add("AsmResolver analysis skipped because the bounded rich-parser byte limit was reached.");
        }
        else
        {
            var bytes = new byte[checked((int)input.Length)];
            input.Content.Position = 0;
            ReadExact(input.Content, bytes);
            try
            {
                // AsmResolver is a second, independently maintained interpretation. It is
                // never given a path and therefore cannot reopen or load the submitted image.
                var image = PEImage.FromBytes(bytes);
                richAgreed = (ushort)image.MachineType == layout.Machine;
                var imports = image.Imports
                    .SelectMany(module => module.Symbols.Select(symbol =>
                        BoundText(module.Name ?? "<unnamed-module>") + "!" + BoundText(symbol.Name ?? "#" + symbol.Ordinal)))
                    .Take(10_000)
                    .ToImmutableArray();
                var exports = image.Exports?.Entries
                    .Select(entry => BoundText(entry.Name ?? "#" + entry.Ordinal))
                    .Take(10_000)
                    .ToImmutableArray() ?? [];
                richSummary = new(
                    image.Imports.Count,
                    image.Imports.Sum(module => module.Symbols.Count),
                    image.Exports?.Entries.Count ?? 0,
                    image.DebugData.Count,
                    image.Resources is not null,
                    image.TlsDirectory is not null,
                    imports,
                    exports);
                if (imports.Length == 10_000 || exports.Length == 10_000)
                    limitations.Add("Rich import or export inventory reached its bounded item limit.");
                if (!richAgreed)
                    limitations.Add("Independent PE parsers disagreed on the machine type.");
            }
            catch (Exception exception) when (exception is BadImageFormatException or ArgumentException)
            {
                limitations.Add("AsmResolver rejected a file accepted by the minimal structural reader.");
            }
        }

        return new(layout, clr, trust, richSummary, richAgreed, limitations.ToImmutable());
    }

    private static void ReadExact(Stream stream, Span<byte> bytes)
    {
        var read = 0;
        while (read < bytes.Length)
        {
            var count = stream.Read(bytes[read..]);
            if (count == 0) throw new PeFormatException("Artifact stream ended before its declared length.");
            read += count;
        }
    }

    private static string BoundText(string text) =>
        text.Length <= 1_024 ? text : text[..1_024];
}
