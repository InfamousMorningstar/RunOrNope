using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Rules;

/// <summary>
/// Deterministically matches the curated capability rules against the import and
/// P/Invoke observations of a scan, producing evidence-cited capability findings.
/// Depends only on the contract types; it never parses sample bytes.
/// </summary>
public static class CapabilityRuleEngine
{
    public const string RulesVersion = "capability-rules-1";

    private const string ImportKind = "pe.import";
    private const string PInvokeKind = "pe.pinvoke";

    public static ImmutableArray<CapabilityFinding> Evaluate(ImmutableArray<Observation> observations)
    {
        if (observations.IsDefaultOrEmpty)
            return ImmutableArray<CapabilityFinding>.Empty;

        // Upper-invariant API name -> the observation ids that evidence it.
        var apiObservations = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var observation in observations)
        {
            var api = ExtractApiName(observation);
            if (api is null) continue;
            if (!apiObservations.TryGetValue(api, out var ids))
                apiObservations[api] = ids = new SortedSet<string>(StringComparer.Ordinal);
            ids.Add(observation.Id);
        }
        if (apiObservations.Count == 0)
            return ImmutableArray<CapabilityFinding>.Empty;

        var findings = ImmutableArray.CreateBuilder<CapabilityFinding>();
        foreach (var rule in CapabilityRuleSet.Default)
        {
            var matchedIds = new SortedSet<string>(StringComparer.Ordinal);

            // Every API in the required core must be present.
            var coreMatched = true;
            foreach (var required in rule.RequiredAllApis.IsDefault
                ? ImmutableArray<string>.Empty
                : rule.RequiredAllApis)
            {
                if (!CollectMatches(apiObservations, required, matchedIds))
                {
                    coreMatched = false;
                    break;
                }
            }

            if (!coreMatched)
                continue;

            // When the rule offers alternatives, at least one must also be present.
            // Every alternative that is present is collected, so the finding cites all
            // of its supporting evidence rather than only the first match.
            if (!rule.AnyOfApis.IsDefaultOrEmpty)
            {
                var anyMatched = false;
                foreach (var alternative in rule.AnyOfApis)
                    anyMatched |= CollectMatches(apiObservations, alternative, matchedIds);

                if (!anyMatched)
                    continue;
            }

            // A rule with no APIs at all would otherwise match vacuously, and the
            // contract requires every finding to cite at least one observation.
            if (matchedIds.Count == 0)
                continue;

            findings.Add(new CapabilityFinding(
                rule.Title, rule.PotentialImpact, rule.Family, rule.EvidenceStatus,
                ParserConfidence.High, rule.EvidenceConfidence, rule.Severity,
                ApplicationLinkage.Unknown, Reachability.Referenced,
                [.. matchedIds], rule.BenignExplanations,
                ImmutableArray<string>.Empty, rule.RecommendedAction));
        }

        return findings.ToImmutable();
    }

    /// <summary>
    /// Adds every observation evidencing <paramref name="required"/> to
    /// <paramref name="into"/>, returning whether the API was present at all.
    /// </summary>
    private static bool CollectMatches(
        Dictionary<string, SortedSet<string>> apiObservations, string required, SortedSet<string> into)
    {
        // Match the base name and its ANSI/Wide (A/W) variants, which is how most
        // Win32 entry points are actually imported (e.g. SetWindowsHookExW).
        // This expansion covers charset variants ONLY. Distinct exports that merely
        // share a prefix — the Ex/2 suffixes and ntdll's Zw- aliases — are separate
        // entry points and must be listed by name in the rule.
        ReadOnlySpan<string> candidates = [required, required + "A", required + "W"];
        var matched = false;
        foreach (var candidate in candidates)
        {
            if (apiObservations.TryGetValue(candidate.ToUpperInvariant(), out var ids))
            {
                matched = true;
                foreach (var id in ids)
                    into.Add(id);
            }
        }

        return matched;
    }

    private static string? ExtractApiName(Observation observation)
    {
        var text = observation.Description;
        switch (observation.Kind)
        {
            case ImportKind:
            {
                // "module.dll!Api" -> "Api"
                var bang = text.LastIndexOf('!');
                if (bang < 0 || bang == text.Length - 1) return null;
                return text[(bang + 1)..].ToUpperInvariant();
            }
            case PInvokeKind:
            {
                // "Api from module.dll" (optionally " (app-called)") -> "Api".
                // The entry-point name is attacker-controlled managed metadata, so take
                // the LAST separator as the import path does: a name that embeds
                // " from " then degrades to a non-matching token instead of
                // impersonating the API it prefixes.
                var from = text.LastIndexOf(" from ", StringComparison.Ordinal);
                var api = (from < 0 ? text : text[..from]).Trim();
                return api.Length == 0 ? null : api.ToUpperInvariant();
            }
            default:
                return null;
        }
    }
}
