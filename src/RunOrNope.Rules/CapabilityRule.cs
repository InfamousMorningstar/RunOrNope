using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Rules;

/// <summary>
/// A code-defined, capa-style capability rule. It fires when <b>every</b> API in
/// <see cref="RequiredAllApis"/> is present <b>and</b> (when <see cref="AnyOfApis"/>
/// is non-empty) at least one API in <see cref="AnyOfApis"/> is present, among the
/// analysed imports and P/Invokes. This required-core-plus-any-of shape prevents
/// loose N-of matching (e.g. "several thread-creation APIs" being mistaken for
/// process injection when no memory is allocated or written). Import presence is not
/// proof of use, so every rule carries an honest evidence tier and benign
/// explanations.
/// </summary>
public sealed record CapabilityRule(
    string Id,
    string Title,
    string PotentialImpact,
    RiskFamily Family,
    Severity Severity,
    EvidenceStatus EvidenceStatus,
    EvidenceConfidence EvidenceConfidence,
    RecommendedAction RecommendedAction,
    ImmutableArray<string> RequiredAllApis,
    ImmutableArray<string> AnyOfApis,
    ImmutableArray<string> BenignExplanations);
