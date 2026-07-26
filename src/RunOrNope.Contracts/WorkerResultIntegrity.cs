using System.Linq;

namespace RunOrNope.Contracts;

/// <summary>Well-known artifact identifiers assigned by the analyzers.</summary>
public static class ScanArtifacts
{
    /// <summary>Identifier the analyzers assign to the submitted root artifact.</summary>
    public const string RootId = "root";
}

/// <summary>
/// Confirms a result returned by the untrusted worker is bound to the exact sample
/// the broker submitted. The worker computes the root identity itself, so the broker
/// must independently verify it — against a hash it computes from its own sample
/// handle — before trusting any part of the result. Any mismatch throws, and the
/// broker maps that to a fail-closed isolation failure.
/// </summary>
public static class WorkerResultIntegrity
{
    public static void EnsureRootIdentity(ScanResult result, string expectedSha256, long expectedSize)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(expectedSha256);

        if (result.Artifacts.IsDefaultOrEmpty)
            throw new ContractValidationException(
                "The worker result has no root artifact to bind to the sample.");

        var root = result.Artifacts.FirstOrDefault(artifact => artifact.Id == ScanArtifacts.RootId)
            ?? throw new ContractValidationException("The worker result has no root artifact.");

        if (!string.Equals(root.Sha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new ContractValidationException(
                "The worker result hash does not match the submitted sample.");

        if (root.Size != expectedSize)
            throw new ContractValidationException(
                "The worker result size does not match the submitted sample.");
    }
}
