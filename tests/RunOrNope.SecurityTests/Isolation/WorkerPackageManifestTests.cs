using System.Collections.Immutable;
using System.Security.Cryptography;
using RunOrNope.Broker.Windows;
using Xunit;
using RunOrNope.Contracts;
using System.Security.Principal;

namespace RunOrNope.SecurityTests.Isolation;

public sealed class WorkerPackageManifestTests
{
    private static readonly string[] ReplacementTargets =
        ["RunOrNope.Worker.exe", "RunOrNope.Contracts.dll"];
    [Fact]
    public void Authentic_manifest_is_accepted_and_tampering_is_rejected()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var document = new WorkerPackageDocument(1, "test", "worker.exe",
            ImmutableArray.Create(new WorkerPackageFile("worker.exe", new string('a', 64), 12)));
        var json = WorkerPackageManifest.Serialize(document);
        var signature = signer.SignData(json, HashAlgorithmName.SHA256);
        var publicKey = signer.ExportSubjectPublicKeyInfo();

        var manifest = WorkerPackageManifest.Authenticate(json, signature, publicKey);
        Assert.Equal(document.FormatVersion, manifest.Document.FormatVersion);
        Assert.Equal(document.PackageVersion, manifest.Document.PackageVersion);
        Assert.Equal(document.EntryPoint, manifest.Document.EntryPoint);
        Assert.Equal(document.Files, manifest.Document.Files);

        json[^1] ^= 1;
        Assert.Throws<IsolationUnavailableException>(
            () => WorkerPackageManifest.Authenticate(json, signature, publicKey));
    }

    [Theory]
    [InlineData("../worker.exe")]
    [InlineData("folder/worker.exe")]
    [InlineData(@"C:\worker.exe")]
    [InlineData("..")]
    [InlineData("CON")]
    [InlineData("nul.dll")]
    [InlineData("COM1.exe")]
    [InlineData("LPT9.txt")]
    [InlineData("worker.exe.")]
    [InlineData("worker.exe ")]
    [InlineData("work*.exe")]
    [InlineData("work?.exe")]
    [InlineData("work\".exe")]
    [InlineData("work\u0001.exe")]
    [InlineData("café.dll")]
    public void Unsafe_package_names_are_rejected(string name)
    {
        var document = new WorkerPackageDocument(1, "test", name,
            ImmutableArray.Create(new WorkerPackageFile(name, new string('a', 64), 12)));

        Assert.Throws<IsolationUnavailableException>(
            () => WorkerPackageManifest.Serialize(document));
    }

    [Fact]
    public void Manifest_authentication_requires_p256_fixed_width_signature()
    {
        var document = new WorkerPackageDocument(1, "test", "worker.exe",
            ImmutableArray.Create(new WorkerPackageFile("worker.exe", new string('a', 64), 12)));
        var json = WorkerPackageManifest.Serialize(document);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<IsolationUnavailableException>(() => WorkerPackageManifest.Authenticate(
            json, p384.SignData(json, HashAlgorithmName.SHA256),
            p384.ExportSubjectPublicKeyInfo()));
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<IsolationUnavailableException>(() => WorkerPackageManifest.Authenticate(
            json, new byte[63], p256.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void Stager_rejects_file_replacement_or_hash_mismatch()
    {
        var source = Directory.CreateTempSubdirectory("runornope-source-");
        var destination = Directory.CreateTempSubdirectory("runornope-destination-");
        try
        {
            File.WriteAllText(Path.Combine(source.FullName, "worker.exe"), "tampered");
            var document = new WorkerPackageDocument(1, "test", "worker.exe",
                ImmutableArray.Create(new WorkerPackageFile(
                    "worker.exe", new string('0', 64), new FileInfo(
                        Path.Combine(source.FullName, "worker.exe")).Length)));
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var json = WorkerPackageManifest.Serialize(document);
            var manifest = WorkerPackageManifest.Authenticate(
                json, signer.SignData(json, HashAlgorithmName.SHA256),
                signer.ExportSubjectPublicKeyInfo());

            Assert.Throws<IsolationUnavailableException>(
                () => WorkerPackageStager.Stage(source.FullName, destination.FullName, manifest,
                    WindowsIdentity.GetCurrent().User!));
            Assert.Empty(destination.EnumerateFiles());
        }
        finally
        {
            source.Delete(true);
            destination.Delete(true);
        }
    }

    [Fact]
    public async Task Staged_entrypoint_and_dependency_cannot_be_replaced_during_launch()
    {
        var (root, manifest) = WorkerEscapeTests.CreateAuthenticatedPackageForTests(
            "RunOrNope.Worker", "RunOrNope.Worker.exe");
        var attempts = 0;
        string? stagedPackage = null;
        var broker = new WorkerBroker(root, manifest,
            attemptPackageReplacementForTesting: package =>
            {
                stagedPackage = package;
                foreach (var name in ReplacementTargets)
                {
                    var path = Path.Combine(package, name);
                    AssertReplacementDenied(() => File.WriteAllBytes(path, [0x4d, 0x5a]));
                    AssertReplacementDenied(() => File.Move(path, path + ".replaced"));
                    attempts += 2;
                }
            });
        var sample = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(sample, [1], TestContext.Current.CancellationToken);
            using var handle = File.OpenHandle(sample, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            var result = await broker.AnalyzeAsync(handle,
                new ScanRequest(sample, ScanMode.Quick), TestContext.Current.CancellationToken);
            Assert.Equal(AnalysisStatus.Incomplete, result.AnalysisStatus);
            Assert.Equal(4, attempts);
            Assert.NotNull(stagedPackage);
            Assert.False(Directory.Exists(stagedPackage));
        }
        finally { File.Delete(sample); }
    }

    private static void AssertReplacementDenied(Action action)
    {
        var exception = Record.Exception(action);
        Assert.True(exception is IOException or UnauthorizedAccessException,
            $"Expected replacement denial, got {exception?.GetType().FullName ?? "no exception"}.");
    }
}
