using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RunOrNope.Broker.Windows;

internal sealed record WorkerPackageFile(string Name, string Sha256, long Size);

internal sealed record WorkerPackageDocument(
    int FormatVersion, string PackageVersion, string EntryPoint,
    ImmutableArray<WorkerPackageFile> Files);

internal sealed class WorkerPackageManifest
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private WorkerPackageManifest(WorkerPackageDocument document) => Document = document;

    internal WorkerPackageDocument Document { get; }

    internal static WorkerPackageManifest Authenticate(
        ReadOnlySpan<byte> manifestJson, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> trustedPublicKey)
    {
        if (manifestJson.Length is 0 or > 4 * 1024 * 1024 || signature.Length is 0 or > 1024)
            throw new IsolationUnavailableException("The worker package manifest is outside its size limits.");
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(trustedPublicKey, out var consumed);
        if (consumed != trustedPublicKey.Length ||
            !verifier.VerifyData(manifestJson, signature, HashAlgorithmName.SHA256))
            throw new IsolationUnavailableException("The worker package manifest signature is invalid.");
        WorkerPackageDocument document;
        try
        {
            document = JsonSerializer.Deserialize<WorkerPackageDocument>(manifestJson, JsonOptions)
                ?? throw new IsolationUnavailableException("The worker package manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new IsolationUnavailableException("The worker package manifest JSON is invalid.", exception);
        }
        Validate(document);
        return new(document);
    }

    internal static byte[] Serialize(WorkerPackageDocument document)
    {
        Validate(document);
        return JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
    }

    private static void Validate(WorkerPackageDocument document)
    {
        if (document.FormatVersion != 1 || string.IsNullOrWhiteSpace(document.PackageVersion) ||
            document.PackageVersion.Length > 128)
            throw new IsolationUnavailableException("The worker package manifest version is unsupported.");
        ValidateName(document.EntryPoint);
        if (document.Files.IsDefaultOrEmpty || document.Files.Length > 512)
            throw new IsolationUnavailableException("The worker package file list is invalid.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in document.Files)
        {
            ValidateName(file.Name);
            if (!names.Add(file.Name) || file.Size < 0 ||
                file.Sha256.Length != 64 || !file.Sha256.All(Uri.IsHexDigit))
                throw new IsolationUnavailableException("A worker package file entry is invalid.");
        }
        if (!names.Contains(document.EntryPoint))
            throw new IsolationUnavailableException("The worker entry point is not in the authenticated file list.");
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 240 ||
            name != Path.GetFileName(name) || name.Contains(':') ||
            name is "." or "..")
            throw new IsolationUnavailableException("A worker package filename is unsafe.");
    }
}
