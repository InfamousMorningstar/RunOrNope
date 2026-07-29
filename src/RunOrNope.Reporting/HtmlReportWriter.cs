using System.Globalization;
using System.Text;
using RunOrNope.Contracts;

namespace RunOrNope.Reporting;

public static class HtmlReportWriter
{
    private const string Csp = "default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; " +
        "font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; form-action 'none'; " +
        "base-uri 'none'; style-src 'unsafe-inline'";
    private static readonly UTF8Encoding Utf8WithoutBom = new(false, true);
    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static byte[] Write(ScanResult result, ReportOptions? options = null)
    {
        ContractValidator.Validate(result);
        var envelope = JsonReportWriter.CreateEnvelope(result, options ?? ReportOptions.Default);
        var scan = envelope.ScanResult;
        var builder = new StringBuilder();
        builder.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<meta http-equiv=\"Content-Security-Policy\" content=\"")
            .Append(Csp)
            .Append("\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
            .Append("<title>RunOrNope static analysis report</title><style>")
            .Append("body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#18212b}")
            .Append("h1,h2,h3{line-height:1.2}section{border-top:1px solid #ccd3da;padding:1rem 0}")
            .Append("table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:.4rem;border-bottom:1px solid #e3e7eb}")
            .Append("code{overflow-wrap:anywhere}.warning{padding:.8rem;background:#fff2cc;border:1px solid #d6a700}")
            .Append("</style></head><body><header><h1>RunOrNope static analysis report</h1><p>Sample: <code>");
        SafeText.Append(builder, scan.SampleName);
        builder.Append("</code></p></header>");

        if (envelope.Privacy.Warning is { } warning)
        {
            builder.Append("<p class=\"warning\">");
            SafeText.Append(builder, warning);
            builder.Append("</p>");
        }

        builder.Append("<section><h2>Summary</h2><dl><dt>Analysis status</dt><dd>");
        SafeText.Append(builder, Display(envelope.Verdict.AnalysisStatus));
        builder.Append("</dd><dt>Completeness</dt><dd>");
        SafeText.Append(builder, Display(scan.Completeness));
        builder.Append("</dd><dt>Risk disposition</dt><dd>");
        SafeText.Append(builder, envelope.Verdict.RiskDisposition is null ? "Withheld" : Display(envelope.Verdict.RiskDisposition.Value));
        builder.Append("</dd><dt>Score</dt><dd>")
            .Append(envelope.Verdict.Score.ToString(CultureInfo.InvariantCulture))
            .Append("</dd></dl></section><section><h2>Reproducibility</h2><dl><dt>Report schema</dt><dd>");
        SafeText.Append(builder, envelope.SchemaVersion);
        builder.Append("</dd><dt>Rules</dt><dd>");
        SafeText.Append(builder, envelope.Reproducibility.RulesVersion);
        builder.Append("</dd><dt>Scoring</dt><dd>");
        SafeText.Append(builder, envelope.Reproducibility.ScoringVersion);
        builder.Append("</dd><dt>Thresholds</dt><dd>");
        SafeText.Append(builder, envelope.Reproducibility.ThresholdVersion);
        builder.Append("</dd><dt>Evidence mode</dt><dd>");
        SafeText.Append(builder, Display(envelope.Privacy.EvidenceMode));
        builder.Append("</dd></dl></section>");

        AppendArtifacts(builder, scan);
        AppendFindings(builder, scan);
        AppendObservations(builder, scan);
        AppendStrings(builder, "Countervailing facts", scan.CountervailingFacts);
        builder.Append("</body></html>");
        return Utf8WithoutBom.GetBytes(builder.ToString());
    }

    public static string SuggestFileName(string sampleName)
    {
        ArgumentNullException.ThrowIfNull(sampleName);
        var leaf = sampleName.Replace('\\', '/');
        leaf = leaf[(leaf.LastIndexOf('/') + 1)..];
        var builder = new StringBuilder();
        var scalarCount = 0;
        foreach (var rune in leaf.EnumerateRunes())
        {
            if (scalarCount >= 120) break;
            var invalid = Rune.IsControl(rune) || rune.Value is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*';
            builder.Append(invalid ? "_" : rune.ToString());
            scalarCount++;
        }
        var stem = builder.ToString().TrimEnd(' ', '.');
        if (stem.Length == 0) stem = "sample";
        var deviceStem = stem.Split('.')[0];
        if (ReservedNames.Contains(deviceStem))
            stem = deviceStem + "_" + stem[deviceStem.Length..];
        return stem + ".runornope.html";
    }

    private static void AppendArtifacts(StringBuilder builder, ScanResult scan)
    {
        builder.Append("<section><h2>Artifacts</h2>");
        if (scan.Artifacts.IsEmpty) { builder.Append("<p>None reported</p></section>"); return; }
        builder.Append("<table><thead><tr><th>Name</th><th>SHA-256</th><th>Size</th><th>Completeness</th></tr></thead><tbody>");
        foreach (var artifact in scan.Artifacts)
        {
            builder.Append("<tr><td>"); SafeText.Append(builder, artifact.Name);
            builder.Append("</td><td><code>"); SafeText.Append(builder, artifact.Sha256);
            builder.Append("</code></td><td>").Append(artifact.Size.ToString(CultureInfo.InvariantCulture));
            builder.Append("</td><td>"); SafeText.Append(builder, Display(artifact.Completeness)); builder.Append("</td></tr>");
        }
        builder.Append("</tbody></table></section>");
    }

    private static void AppendFindings(StringBuilder builder, ScanResult scan)
    {
        builder.Append("<section><h2>Capability findings</h2>");
        if (scan.Findings.IsEmpty) { builder.Append("<p>None reported</p></section>"); return; }
        foreach (var finding in scan.Findings)
        {
            builder.Append("<article><h3>"); SafeText.Append(builder, finding.Title);
            builder.Append("</h3><p>"); SafeText.Append(builder, finding.PotentialImpact);
            builder.Append("</p><p>Evidence: "); SafeText.Append(builder, string.Join(", ", finding.ObservationIds));
            builder.Append("</p>");
            AppendList(builder, "Benign explanations", finding.BenignExplanations);
            AppendList(builder, "Limitations", finding.Limitations);
            builder.Append("</article>");
        }
        builder.Append("</section>");
    }

    private static void AppendObservations(StringBuilder builder, ScanResult scan)
    {
        builder.Append("<section><h2>Observations</h2>");
        if (scan.Observations.IsEmpty) { builder.Append("<p>None reported</p></section>"); return; }
        foreach (var observation in scan.Observations)
        {
            builder.Append("<article><h3>"); SafeText.Append(builder, observation.Id);
            builder.Append("</h3><p>"); SafeText.Append(builder, observation.Description);
            builder.Append("</p><p>Kind: "); SafeText.Append(builder, observation.Kind);
            builder.Append("; artifact: "); SafeText.Append(builder, observation.Source.ArtifactId);
            builder.Append("</p></article>");
        }
        builder.Append("</section>");
    }

    private static void AppendStrings(StringBuilder builder, string heading, IReadOnlyCollection<string> values)
    {
        builder.Append("<section><h2>"); SafeText.Append(builder, heading); builder.Append("</h2>");
        AppendList(builder, null, values);
        builder.Append("</section>");
    }

    private static void AppendList(StringBuilder builder, string? heading, IReadOnlyCollection<string> values)
    {
        if (heading is not null) { builder.Append("<h4>"); SafeText.Append(builder, heading); builder.Append("</h4>"); }
        if (values.Count == 0) { builder.Append("<p>None reported</p>"); return; }
        builder.Append("<ul>");
        foreach (var value in values) { builder.Append("<li>"); SafeText.Append(builder, value); builder.Append("</li>"); }
        builder.Append("</ul>");
    }

    private static string Display<T>(T value) where T : struct, Enum => value.ToString();
}
