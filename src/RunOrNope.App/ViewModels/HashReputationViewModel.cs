using RunOrNope.App.Services;

namespace RunOrNope.App.ViewModels;

public sealed record HashReputationViewModel(
    HashReputationStatus Status,
    string Message,
    int Malicious,
    int Suspicious,
    int Harmless,
    int Undetected,
    DateTimeOffset? LastAnalysisUtc)
{
    public static HashReputationViewModel Empty { get; } =
        new(HashReputationStatus.Skipped, "Not looked up.", 0, 0, 0, 0, null);

    public static HashReputationViewModel From(HashReputationResult result)
    {
        var message = result.Status switch
        {
            HashReputationStatus.Found => "VirusTotal returned a report. The static verdict is unchanged.",
            HashReputationStatus.NotFound => "VirusTotal has no report for this SHA-256. This is not evidence that the file is safe.",
            HashReputationStatus.Skipped => "Lookup skipped. The static verdict is unchanged.",
            _ => "External reputation could not be retrieved. The static verdict is unchanged.",
        };
        return new(result.Status, message, result.Malicious, result.Suspicious,
            result.Harmless, result.Undetected, result.LastAnalysisUtc);
    }
}
