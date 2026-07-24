using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RunOrNope.Worker;

public sealed class WorkerProtocolException(string message, Exception? inner = null) : IOException(message, inner);

public sealed record WorkerRequestEnvelope(int Version, string Mode, long SampleSize);
public sealed record WorkerResponseEnvelope(int Version, string ResultJson);

public static class WorkerProtocol
{
    public const int CurrentVersion = 1;
    public const int MaxFrameBytes = 32 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static async ValueTask WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (payload.Length > MaxFrameBytes) throw new WorkerProtocolException("Frame exceeds the protocol limit.");
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var prefix = new byte[sizeof(int)];
        await ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length < 0 || length > MaxFrameBytes)
            throw new WorkerProtocolException("Frame length is outside the protocol limit.");
        var payload = GC.AllocateUninitializedArray<byte>(length);
        await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    public static async ValueTask<string> ReadUtf8FrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var payload = await ReadFrameAsync(stream, cancellationToken).ConfigureAwait(false);
        try { return StrictUtf8.GetString(payload); }
        catch (DecoderFallbackException exception)
        {
            throw new WorkerProtocolException("Frame is not valid UTF-8.", exception);
        }
    }

    public static ValueTask WriteJsonFrameAsync<T>(Stream stream, T value, CancellationToken token)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return WriteFrameAsync(stream, payload, token);
    }

    public static async ValueTask<T> ReadJsonFrameAsync<T>(Stream stream, CancellationToken token)
    {
        var payload = await ReadFrameAsync(stream, token).ConfigureAwait(false);
        try
        {
            var reader = new Utf8JsonReader(payload, new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });
            var value = JsonSerializer.Deserialize<T>(ref reader, JsonOptions)
                ?? throw new WorkerProtocolException("A JSON value is required.");
            if (reader.Read()) throw new WorkerProtocolException("Trailing JSON data is not allowed.");
            return value;
        }
        catch (JsonException exception)
        {
            throw new WorkerProtocolException("The JSON frame is invalid.", exception);
        }
    }

    public static async ValueTask<WorkerRequestEnvelope> ReadRequestAsync(Stream stream, CancellationToken token)
    {
        var request = await ReadJsonFrameAsync<WorkerRequestEnvelope>(stream, token).ConfigureAwait(false);
        if (request.Version != CurrentVersion) throw new WorkerProtocolException("Unsupported protocol version.");
        if (request.Mode is not ("quick" or "deep")) throw new WorkerProtocolException("Unsupported scan mode.");
        if (request.SampleSize < 0) throw new WorkerProtocolException("Invalid sample size.");
        return request;
    }

    private static async ValueTask ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        try
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer[offset..], token).ConfigureAwait(false);
                if (read == 0) throw new WorkerProtocolException("Frame ended before its declared length.");
                offset += read;
            }
        }
        catch (EndOfStreamException exception)
        {
            throw new WorkerProtocolException("Frame ended before its declared length.", exception);
        }
    }
}
