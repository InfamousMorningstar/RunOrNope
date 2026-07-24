using System.Collections.Immutable;
using System.Security.Cryptography;
using RunOrNope.Broker.Windows;
using Xunit;

namespace RunOrNope.SecurityTests.Isolation;

public sealed class WorkerPackageManifestTests
{
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
    public void Unsafe_package_names_are_rejected(string name)
    {
        var document = new WorkerPackageDocument(1, "test", name,
            ImmutableArray.Create(new WorkerPackageFile(name, new string('a', 64), 12)));

        Assert.Throws<IsolationUnavailableException>(
            () => WorkerPackageManifest.Serialize(document));
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
                () => WorkerPackageStager.Stage(source.FullName, destination.FullName, manifest));
            Assert.Empty(destination.EnumerateFiles());
        }
        finally
        {
            source.Delete(true);
            destination.Delete(true);
        }
    }
}
