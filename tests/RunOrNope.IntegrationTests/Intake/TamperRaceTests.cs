using RunOrNope.Intake;
using Xunit;

namespace RunOrNope.IntegrationTests.Intake;

public sealed class TamperRaceTests
{
    [Fact]
    public async Task RejectsDirectoryInput()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try
        {
            await Assert.ThrowsAsync<IntakeRejectedException>(() => SafeFileIntake.OpenAsync(
                path, new IntakePolicy(1024), TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(path); }
    }

    [Fact]
    public async Task RejectsFinalComponentReparsePoint()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var target = Path.Combine(root, "target.exe");
        var link = Path.Combine(root, "link.exe");
        try
        {
            await File.WriteAllBytesAsync(target, [0x4d, 0x5a], TestContext.Current.CancellationToken);
            File.CreateSymbolicLink(link, target);
            await Assert.ThrowsAsync<IntakeRejectedException>(
                () => SafeFileIntake.OpenAsync(link, new IntakePolicy(1024), TestContext.Current.CancellationToken));
        }
        finally
        {
            if (File.Exists(link)) File.Delete(link);
            if (File.Exists(target)) File.Delete(target);
            Directory.Delete(root);
        }
    }

    [Fact]
    public async Task RejectsAncestorDirectorySymlinkWithoutFollowingIt()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "target");
        var link = Path.Combine(root, "link");
        Directory.CreateDirectory(target);
        Directory.CreateDirectory(root);
        var sample = Path.Combine(target, "sample.exe");
        try
        {
            await File.WriteAllBytesAsync(sample, new byte[128], TestContext.Current.CancellationToken);
            Directory.CreateSymbolicLink(link, target);
            await Assert.ThrowsAsync<IntakeRejectedException>(() => SafeFileIntake.OpenAsync(
                Path.Combine(link, "sample.exe"), new IntakePolicy(1024), TestContext.Current.CancellationToken));
        }
        finally
        {
            if (Directory.Exists(link)) Directory.Delete(link);
            if (File.Exists(sample)) File.Delete(sample);
            if (Directory.Exists(target)) Directory.Delete(target);
            if (Directory.Exists(root)) Directory.Delete(root);
        }
    }

    [Fact]
    public async Task ExistingWriterPreventsAcquisition()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        await File.WriteAllBytesAsync(path, new byte[8 * 1024 * 1024], TestContext.Current.CancellationToken);
        try
        {
            await using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            await Assert.ThrowsAsync<IntakeRejectedException>(() =>
                SafeFileIntake.OpenAsync(path, new IntakePolicy(16 * 1024 * 1024, 4096), TestContext.Current.CancellationToken));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task OwnedLeasePreventsReplacementAndGrowth()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var replacement = path + ".new";
        await File.WriteAllBytesAsync(path, new byte[128], TestContext.Current.CancellationToken);
        await File.WriteAllBytesAsync(replacement, new byte[128], TestContext.Current.CancellationToken);
        try
        {
            using var lease = await SafeFileIntake.OpenAsync(
                path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
            Assert.Throws<IOException>(() => File.Open(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            var replacementFailure = Record.Exception(() => File.Move(replacement, path, overwrite: true));
            Assert.True(replacementFailure is IOException or UnauthorizedAccessException);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
            if (File.Exists(replacement)) File.Delete(replacement);
        }
    }
}
