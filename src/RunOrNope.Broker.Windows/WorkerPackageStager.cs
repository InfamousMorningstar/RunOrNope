using System.Security.Cryptography;

namespace RunOrNope.Broker.Windows;

internal static class WorkerPackageStager
{
    internal static string Stage(
        string sourceRoot, string destinationRoot, WorkerPackageManifest manifest)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationRoot);
        ArgumentNullException.ThrowIfNull(manifest);
        var heldSources = new List<FileStream>();
        try
        {
            foreach (var entry in manifest.Document.Files)
            {
                var sourcePath = Path.Combine(sourceRoot, entry.Name);
                var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    128 * 1024, FileOptions.SequentialScan);
                heldSources.Add(source);
                if (source.Length != entry.Size ||
                    !HashMatches(source, entry.Sha256))
                    throw new IsolationUnavailableException(
                        $"Packaged worker file '{entry.Name}' failed authenticated hash verification.");
                source.Position = 0;
                var destinationPath = Path.Combine(destinationRoot, entry.Name);
                using (var destination = new FileStream(destinationPath, FileMode.CreateNew,
                           FileAccess.Write, FileShare.Read, 128 * 1024, FileOptions.WriteThrough))
                {
                    source.CopyTo(destination);
                    destination.Flush(flushToDisk: true);
                }
                using var staged = new FileStream(destinationPath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 128 * 1024, FileOptions.SequentialScan);
                if (staged.Length != entry.Size || !HashMatches(staged, entry.Sha256))
                    throw new IsolationUnavailableException(
                        $"Staged worker file '{entry.Name}' failed post-copy verification.");
            }
            return Path.Combine(destinationRoot, manifest.Document.EntryPoint);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            throw new IsolationUnavailableException("The authenticated worker package could not be staged.", exception);
        }
        finally
        {
            foreach (var source in heldSources) source.Dispose();
        }
    }

    private static bool HashMatches(Stream stream, string expected)
    {
        stream.Position = 0;
        var actual = SHA256.HashData(stream);
        var expectedBytes = Convert.FromHexString(expected);
        return expectedBytes.Length == 32 &&
               CryptographicOperations.FixedTimeEquals(actual, expectedBytes);
    }
}
