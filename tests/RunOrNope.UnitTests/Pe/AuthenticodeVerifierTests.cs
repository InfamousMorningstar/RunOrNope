using FluentAssertions;
using RunOrNope.Analyzers.Pe;
using Xunit;

namespace RunOrNope.UnitTests.Pe;

public sealed class AuthenticodeVerifierTests
{
    [Fact]
    public async Task VerifyAsync_AlwaysRequestsOfflineNonInteractiveStrictPolicy()
    {
        var backend = new RecordingTrustBackend(new(0, TrustDisposition.Trusted, false, null, null));
        var verifier = new AuthenticodeVerifier(backend);
        var result = await verifier.VerifyAsync(new MemoryStream(PeFixture.Create()), CancellationToken.None);
        backend.Request.Should().NotBeNull();
        backend.Request!.CacheOnly.Should().BeTrue();
        backend.Request.NetworkRetrievalDisabled.Should().BeTrue();
        backend.Request.StrictPadding.Should().BeTrue();
        result.Disposition.Should().Be(TrustDisposition.Trusted);
    }

    [Fact]
    public async Task VerifyAsync_OfflineRevocationUnknown_RemainsIndeterminate()
    {
        var backend = new RecordingTrustBackend(new(unchecked((int)0x80092013), TrustDisposition.IndeterminateOffline, true, null, null));
        var result = await new AuthenticodeVerifier(backend)
            .VerifyAsync(new MemoryStream(PeFixture.Create()), CancellationToken.None);
        result.Disposition.Should().Be(TrustDisposition.IndeterminateOffline);
        result.RevocationIndeterminate.Should().BeTrue();
        result.NativeStatus.Should().Be(unchecked((int)0x80092013));
    }

    [Fact]
    public void ValidateCertificateTable_NonZeroAlignmentPadding_IsRejected()
    {
        var bytes = PeFixture.Create();
        Array.Resize(ref bytes, bytes.Length + 16);
        BitConverter.GetBytes(0x400u).CopyTo(bytes, 0x128);
        BitConverter.GetBytes(16u).CopyTo(bytes, 0x12c);
        BitConverter.GetBytes(9u).CopyTo(bytes, 0x400);
        BitConverter.GetBytes((ushort)0x200).CopyTo(bytes, 0x404);
        BitConverter.GetBytes((ushort)2).CopyTo(bytes, 0x406);
        bytes[0x409] = 1;
        var layout = MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        var act = () => AuthenticodeVerifier.ValidateCertificateTable(new MemoryStream(bytes), layout);
        act.Should().Throw<PeFormatException>().WithMessage("*padding*");
    }

    [Fact]
    public async Task WindowsBackend_BenignTestHost_ReturnsExactPlatformStatus()
    {
        if (!OperatingSystem.IsWindows() || Environment.ProcessPath is null) return;
        await using var stream = File.OpenRead(Environment.ProcessPath);
        var result = await new WindowsAuthenticodeTrustBackend()
            .VerifyAsync(stream, new AuthenticodePolicy(), CancellationToken.None);
        result.Disposition.Should().NotBe(TrustDisposition.PlatformUnavailable);
        result.CatalogContext.Should().Be("embedded-file-handle");
    }

    private sealed class RecordingTrustBackend(AuthenticodeResult result) : IAuthenticodeTrustBackend
    {
        public AuthenticodePolicy? Request { get; private set; }
        public ValueTask<AuthenticodeResult> VerifyAsync(Stream stream, AuthenticodePolicy policy, CancellationToken cancellationToken)
        { Request = policy; return ValueTask.FromResult(result); }
    }
}
