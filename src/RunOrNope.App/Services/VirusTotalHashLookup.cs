using System.Net;
using System.Net.Http;
using System.IO;
using System.Text.Json;

namespace RunOrNope.App.Services;

public sealed class VirusTotalHashLookup : IHashReputationLookup
{
    private readonly HttpClient _client;
    public static readonly Uri ApiBaseUri = new("https://www.virustotal.com/api/v3/");
    public const int MaxResponseBytes = 1024 * 1024;

    public VirusTotalHashLookup(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (client.BaseAddress != ApiBaseUri)
            throw new ArgumentException("The VirusTotal API base address is invalid.", nameof(client));
        _client = client;
    }

    public static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
        };
        return new HttpClient(handler)
        {
            BaseAddress = ApiBaseUri,
            Timeout = TimeSpan.FromSeconds(15),
        };
    }

    public async Task<HashReputationResult> LookupAsync(
        string sha256, string apiKey, CancellationToken cancellationToken)
    {
        var normalizedHash = ValidateSha256(sha256);
        ValidateApiKey(apiKey);

        using var request = new HttpRequestMessage(HttpMethod.Get, $"files/{normalizedHash}");
        request.Headers.TryAddWithoutValidation("x-apikey", apiKey);
        try
        {
            using var response = await _client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            var mapped = MapStatus(response.StatusCode);
            if (mapped != HashReputationStatus.Found)
                return Empty(mapped, normalizedHash);
            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
                return Empty(HashReputationStatus.InvalidResponse, normalizedHash);

            var bytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            return Parse(bytes, normalizedHash);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Empty(HashReputationStatus.ServiceUnavailable, normalizedHash);
        }
        catch (HttpRequestException)
        {
            return Empty(HashReputationStatus.Failed, normalizedHash);
        }
        catch (InvalidDataException)
        {
            return Empty(HashReputationStatus.InvalidResponse, normalizedHash);
        }
        catch (IOException)
        {
            return Empty(HashReputationStatus.Failed, normalizedHash);
        }
    }

    private static string ValidateSha256(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        if (sha256.Length != 64 || !sha256.All(static character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f'
                    or >= 'A' and <= 'F'))
            throw new ArgumentException("A valid SHA-256 is required.", nameof(sha256));
        return sha256.ToLowerInvariant();
    }

    private static void ValidateApiKey(string apiKey)
    {
        ArgumentNullException.ThrowIfNull(apiKey);
        if (apiKey.Length == 0 || apiKey.Contains('\r') || apiKey.Contains('\n'))
            throw new ArgumentException("A valid API key is required.", nameof(apiKey));
    }

    private static HashReputationStatus MapStatus(HttpStatusCode status) => status switch
    {
        HttpStatusCode.OK => HashReputationStatus.Found,
        HttpStatusCode.NotFound => HashReputationStatus.NotFound,
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => HashReputationStatus.Unauthorized,
        HttpStatusCode.TooManyRequests => HashReputationStatus.RateLimited,
        HttpStatusCode.RequestTimeout or HttpStatusCode.InternalServerError or
            HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or
            HttpStatusCode.GatewayTimeout => HashReputationStatus.ServiceUnavailable,
        _ => HashReputationStatus.Failed,
    };

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content, CancellationToken cancellationToken)
    {
        await using var source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (destination.Length > MaxResponseBytes - read)
                throw new InvalidDataException("The response exceeds its size limit.");
            destination.Write(buffer, 0, read);
        }
        return destination.ToArray();
    }

    private static HashReputationResult Parse(byte[] json, string expectedHash)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
            var data = document.RootElement.GetProperty("data");
            var id = data.GetProperty("id").GetString();
            if (!StringComparer.OrdinalIgnoreCase.Equals(id, expectedHash))
                return Empty(HashReputationStatus.InvalidResponse, expectedHash);
            var attributes = data.GetProperty("attributes");
            var stats = attributes.GetProperty("last_analysis_stats");
            if (!TryCount(stats, "malicious", out var malicious) ||
                !TryCount(stats, "suspicious", out var suspicious) ||
                !TryCount(stats, "harmless", out var harmless) ||
                !TryCount(stats, "undetected", out var undetected))
                return Empty(HashReputationStatus.InvalidResponse, expectedHash);

            DateTimeOffset? lastAnalysis = null;
            if (attributes.TryGetProperty("last_analysis_date", out var date))
            {
                if (!date.TryGetInt64(out var seconds)) return Empty(HashReputationStatus.InvalidResponse, expectedHash);
                try { lastAnalysis = DateTimeOffset.FromUnixTimeSeconds(seconds); }
                catch (ArgumentOutOfRangeException) { return Empty(HashReputationStatus.InvalidResponse, expectedHash); }
            }
            return new(HashReputationStatus.Found, expectedHash,
                malicious, suspicious, harmless, undetected, lastAnalysis);
        }
        catch (JsonException)
        {
            return Empty(HashReputationStatus.InvalidResponse, expectedHash);
        }
        catch (InvalidOperationException)
        {
            return Empty(HashReputationStatus.InvalidResponse, expectedHash);
        }
        catch (KeyNotFoundException)
        {
            return Empty(HashReputationStatus.InvalidResponse, expectedHash);
        }
    }

    private static bool TryCount(JsonElement stats, string name, out int count)
    {
        count = 0;
        return stats.TryGetProperty(name, out var value) &&
               value.TryGetInt32(out count) && count >= 0;
    }

    private static HashReputationResult Empty(HashReputationStatus status, string sha256) =>
        new(status, sha256, 0, 0, 0, 0, null);
}
