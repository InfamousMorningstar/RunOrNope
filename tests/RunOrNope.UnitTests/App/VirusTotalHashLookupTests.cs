using System.Net;
using System.Text;
using AwesomeAssertions;
using RunOrNope.App.Services;
using Xunit;

namespace RunOrNope.UnitTests.App;

public sealed class VirusTotalHashLookupTests
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ValidJson = """
        {"data":{"id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "attributes":{"last_analysis_stats":{"malicious":3,"suspicious":2,"harmless":7,"undetected":50},
        "last_analysis_date":1700000000}}}
        """;

    [Fact]
    public async Task LookupAsync_SendsOnlyHashWithHeaderAndMapsBoundedStats()
    {
        HttpRequestMessage? captured = null;
        var handler = new StubHandler(request =>
        {
            captured = request;
            return Response(HttpStatusCode.OK, ValidJson);
        });
        using var client = new HttpClient(handler) { BaseAddress = VirusTotalHashLookup.ApiBaseUri };
        var lookup = new VirusTotalHashLookup(client);

        var result = await lookup.LookupAsync(Sha.ToUpperInvariant(), "session-key", TestContext.Current.CancellationToken);

        captured!.Method.Should().Be(HttpMethod.Get);
        captured.RequestUri.Should().Be(new Uri($"{VirusTotalHashLookup.ApiBaseUri}files/{Sha}"));
        captured.RequestUri!.Query.Should().BeEmpty();
        captured.Headers.GetValues("x-apikey").Should().Equal("session-key");
        captured.Content.Should().BeNull();
        result.Should().Be(new HashReputationResult(
            HashReputationStatus.Found, Sha, 3, 2, 7, 50,
            DateTimeOffset.FromUnixTimeSeconds(1700000000)));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, HashReputationStatus.NotFound)]
    [InlineData(HttpStatusCode.Unauthorized, HashReputationStatus.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden, HashReputationStatus.Unauthorized)]
    [InlineData(HttpStatusCode.TooManyRequests, HashReputationStatus.RateLimited)]
    [InlineData(HttpStatusCode.ServiceUnavailable, HashReputationStatus.ServiceUnavailable)]
    [InlineData(HttpStatusCode.Found, HashReputationStatus.Failed)]
    public async Task LookupAsync_MapsStatusWithoutParsingOrFollowing(
        HttpStatusCode status, HashReputationStatus expected)
    {
        var requests = 0;
        var handler = new StubHandler(_ =>
        {
            requests++;
            var response = Response(status, "server secret");
            response.Headers.Location = new Uri("http://127.0.0.1/leak");
            return response;
        });
        using var client = new HttpClient(handler) { BaseAddress = VirusTotalHashLookup.ApiBaseUri };

        var result = await new VirusTotalHashLookup(client)
            .LookupAsync(Sha, "key", TestContext.Current.CancellationToken);

        result.Status.Should().Be(expected);
        requests.Should().Be(1);
    }

    [Theory]
    [InlineData("short", "key")]
    [InlineData(Sha, "")]
    [InlineData(Sha, "key\rleak")]
    [InlineData(Sha, "key\nleak")]
    public async Task LookupAsync_RejectsInvalidInputBeforeSend(string sha, string key)
    {
        var requests = 0;
        using var client = new HttpClient(new StubHandler(_ => { requests++; return Response(HttpStatusCode.OK, ValidJson); }))
            { BaseAddress = VirusTotalHashLookup.ApiBaseUri };

        var call = async () => await new VirusTotalHashLookup(client).LookupAsync(sha, key, CancellationToken.None);

        await call.Should().ThrowAsync<ArgumentException>();
        requests.Should().Be(0);
    }

    [Theory]
    [InlineData("""{"data":{"id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":0,"undetected":0}}}}""")]
    [InlineData("""{"data":{"id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","attributes":{"last_analysis_stats":{"malicious":-1,"suspicious":0,"harmless":0,"undetected":0}}}}""")]
    [InlineData("{}")]
    public async Task LookupAsync_RejectsUnusableJson(string json)
    {
        using var client = new HttpClient(new StubHandler(_ => Response(HttpStatusCode.OK, json)))
            { BaseAddress = VirusTotalHashLookup.ApiBaseUri };

        var result = await new VirusTotalHashLookup(client).LookupAsync(Sha, "key", CancellationToken.None);

        result.Status.Should().Be(HashReputationStatus.InvalidResponse);
    }

    [Fact]
    public async Task LookupAsync_RejectsOversizedBody()
    {
        using var client = new HttpClient(new StubHandler(_ =>
            Response(HttpStatusCode.OK, new string('x', VirusTotalHashLookup.MaxResponseBytes + 1))))
            { BaseAddress = VirusTotalHashLookup.ApiBaseUri };

        var result = await new VirusTotalHashLookup(client).LookupAsync(Sha, "key", CancellationToken.None);

        result.Status.Should().Be(HashReputationStatus.InvalidResponse);
    }

    private static HttpResponseMessage Response(HttpStatusCode status, string content) =>
        new(status) { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
