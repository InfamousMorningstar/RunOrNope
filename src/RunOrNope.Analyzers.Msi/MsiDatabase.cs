using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RunOrNope.Analyzers.Content;

namespace RunOrNope.Analyzers.Msi;

internal interface IMsiDatabaseReader : IDisposable
{
    ImmutableArray<string> EnumerateTables(
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken);

    IEnumerable<MsiRow> Query(
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> parameters,
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken);

    ImmutableArray<MsiSummaryProperty> ReadSummary(
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken);

    Stream OpenStream(
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> keyParameters);
}

internal interface IMsiDatabaseFactory
{
    IMsiDatabaseReader OpenReadOnly(string path);
}

internal sealed class MsiDatabaseFactory : IMsiDatabaseFactory
{
    public IMsiDatabaseReader OpenReadOnly(string path) => MsiDatabase.OpenReadOnly(path);
}

internal sealed class MsiDatabase : IMsiDatabaseReader
{
    private const uint ErrorSuccess = 0;
    private const uint ErrorMoreData = 234;
    private const uint ErrorNoMoreItems = 259;
    private const int MsiNullInteger = int.MinValue;
    private const uint VariantEmpty = 0;
    private const uint VariantI2 = 2;
    private const uint VariantI4 = 3;
    private const uint VariantLpstr = 30;
    private const uint VariantLpwstr = 31;
    private const int StreamBufferSize = 64 * 1024;
    private readonly SafeMsiDatabaseHandle handle;
    private bool disposed;

    private MsiDatabase(SafeMsiDatabaseHandle handle)
    {
        this.handle = handle;
    }

    internal static MsiDatabase OpenReadOnly(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return new MsiDatabase(OpenNativeReadOnly(path));
    }

    private static SafeMsiDatabaseHandle OpenNativeReadOnly(string path)
    {
        SafeMsiDatabaseHandle database;
        var status = MsiOpenDatabaseW(path, default, out database);
        if (status != ErrorSuccess)
        {
            database?.Dispose();
            throw new MsiDatabaseException("open database read-only", status);
        }

        return database;
    }

    public ImmutableArray<string> EnumerateTables(
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken)
    {
        var names = ImmutableArray.CreateBuilder<string>();
        foreach (var row in Query(MsiTables.Tables, [], limits, cancellationToken))
        {
            if (names.Count >= limits.MaxTables)
            {
                throw new MsiDataIncompleteException("MSI table inventory exceeded the configured table limit.");
            }

            var value = row.Fields[0];
            if (!value.IsComplete || value.Text is null)
            {
                throw new MsiDataIncompleteException(
                    value.IncompleteReason ?? "An MSI table name was unreadable.");
            }
            names.Add(value.Text.DisplayText);
        }
        return names.ToImmutable();
    }

    public IEnumerable<MsiRow> Query(
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> parameters,
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(limits);
        ThrowIfDisposed();
        limits.Validate();
        if (!parameters.IsDefaultOrEmpty)
        {
            throw new ArgumentException(
                "Native query parameters are not accepted; fixed queries are filtered in managed code.",
                nameof(parameters));
        }
        if (definition.Columns.Length == 0 || definition.Columns.Length > limits.MaxFieldsPerRecord)
        {
            throw new MsiDataIncompleteException(
                "MSI table schema exceeded the configured field limit.");
        }

        return QueryRows(definition, limits, cancellationToken);
    }

    internal IEnumerable<T> Query<T>(
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> parameters,
        MsiAnalysisLimits limits,
        Func<MsiRow, T> mapper,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mapper);
        foreach (var row in Query(definition, parameters, limits, cancellationToken))
        {
            yield return mapper(row);
        }
    }

    private IEnumerable<MsiRow> QueryRows(
        MsiTableDefinition definition,
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken)
    {
        using var view = OpenView(definition.Query);
        Check(MsiViewExecute(view, nint.Zero), "execute fixed query");

        var rowCount = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = MsiViewFetch(view, out var record);
            if (status == ErrorNoMoreItems)
            {
                record?.Dispose();
                yield break;
            }
            if (status != ErrorSuccess)
            {
                record?.Dispose();
                throw new MsiDatabaseException("fetch query row", status);
            }

            using (record)
            {
                if (rowCount++ >= limits.MaxRowsPerTable)
                {
                    throw new MsiDataIncompleteException(
                        $"MSI table {definition.Name} exceeded the configured row limit.");
                }
                yield return ReadRow(record, definition, limits);
            }
        }
    }

    public ImmutableArray<MsiSummaryProperty> ReadSummary(
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ThrowIfDisposed();
        limits.Validate();
        Check(
            MsiGetSummaryInformationW(handle, null, 0, out var summary),
            "open summary information");
        using (summary)
        {
            var properties = ImmutableArray.CreateBuilder<MsiSummaryProperty>();
            for (var propertyId = 1; propertyId <= 19; propertyId++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var property = ReadSummaryProperty(summary, propertyId, limits);
                if (property is not null) properties.Add(property);
            }
            return properties.ToImmutable();
        }
    }

    public Stream OpenStream(
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> keyParameters) =>
        OpenStream(definition, keyParameters, new ExtractionBudget(), CancellationToken.None);

    internal Stream OpenStream(
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> keyParameters,
        ExtractionBudget budget,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(budget);
        ThrowIfDisposed();
        var streamIndex = -1;
        for (var index = 0; index < definition.Columns.Length; index++)
        {
            if (definition.Columns[index].Type != MsiColumnType.Stream) continue;
            streamIndex = index;
            break;
        }
        if (streamIndex < 0)
        {
            throw new ArgumentException("The fixed table definition has no stream column.", nameof(definition));
        }
        if (keyParameters.IsDefault || keyParameters.Length != streamIndex)
        {
            throw new ArgumentException("Every key field before the stream must be supplied.", nameof(keyParameters));
        }

        using var view = OpenView(definition.Query);
        Check(MsiViewExecute(view, nint.Zero), "execute fixed stream query");
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = MsiViewFetch(view, out var record);
            if (status == ErrorNoMoreItems)
            {
                record?.Dispose();
                throw new MsiDataIncompleteException(
                    $"The requested stream was absent from MSI table {definition.Name}.");
            }
            if (status != ErrorSuccess)
            {
                record?.Dispose();
                throw new MsiDatabaseException("fetch stream row", status);
            }

            using (record)
            {
                if (!KeysMatch(record, definition, keyParameters, cancellationToken)) continue;
                return ReadStream(record, checked((uint)streamIndex + 1), budget, cancellationToken);
            }
        }
    }

    internal static MsiTextReadResult ReadText(MsiStringRead reader, int maxScalars)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxScalars);

        uint reportedLength = 0;
        var firstStatus = reader(null, ref reportedLength);
        if (firstStatus != ErrorSuccess && firstStatus != ErrorMoreData)
        {
            throw new MsiDatabaseException("measure MSI string", firstStatus);
        }
        return ReadTextAfterMeasurement(reader, maxScalars, reportedLength);
    }

    private static MsiTextReadResult ReadTextAfterMeasurement(
        MsiStringRead reader,
        int maxScalars,
        uint reportedLength)
    {
        if (reportedLength == 0)
        {
            return new MsiTextReadResult(
                MsiTextPolicy.Sanitize(string.Empty, maxScalars), true, null);
        }

        var boundedLength = Math.Min(reportedLength, checked((uint)maxScalars));
        var buffer = new StringBuilder(checked((int)boundedLength + 1));
        var secondLength = checked(boundedLength + 1);
        var secondStatus = reader(buffer, ref secondLength);
        var text = MsiTextPolicy.Sanitize(buffer.ToString(), maxScalars);

        if (reportedLength > checked((uint)maxScalars))
        {
            return new MsiTextReadResult(
                text with
                {
                    WasTruncated = true,
                    OriginalScalars = Math.Max(text.OriginalScalars, checked((int)reportedLength)),
                },
                false,
                "MSI text exceeded the configured scalar limit.");
        }
        if (secondStatus == ErrorMoreData || secondLength > reportedLength)
        {
            return new MsiTextReadResult(
                text with { WasTruncated = true },
                false,
                "MSI text changed while it was being retrieved.");
        }
        if (secondStatus != ErrorSuccess)
        {
            throw new MsiDatabaseException("read MSI string", secondStatus);
        }
        if (secondLength < reportedLength)
        {
            return new MsiTextReadResult(
                text,
                false,
                "MSI text became shorter while it was being retrieved.");
        }

        return new MsiTextReadResult(text, true, null);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        handle.Dispose();
    }

    private static MsiRow ReadRow(
        SafeMsiRecordHandle record,
        MsiTableDefinition definition,
        MsiAnalysisLimits limits)
    {
        var fieldCount = MsiRecordGetFieldCount(record);
        if (fieldCount != definition.Columns.Length)
        {
            throw new MsiDataIncompleteException(
                $"MSI query for {definition.Name} returned {fieldCount} fields; " +
                $"{definition.Columns.Length} were required.");
        }

        var fields = ImmutableArray.CreateBuilder<MsiRecordValue>(definition.Columns.Length);
        for (var index = 0; index < definition.Columns.Length; index++)
        {
            fields.Add(ReadValue(record, checked((uint)index + 1), definition.Columns[index], limits));
        }
        return new MsiRow(fields.MoveToImmutable());
    }

    private static MsiRecordValue ReadValue(
        SafeMsiRecordHandle record,
        uint field,
        MsiColumnDefinition column,
        MsiAnalysisLimits limits)
    {
        if (MsiRecordIsNull(record, field))
        {
            if (!column.IsNullable)
            {
                return new MsiRecordValue(
                    MsiValueKind.Null,
                    null,
                    null,
                    null,
                    false,
                    $"Required MSI field {column.Name} was null.");
            }
            return new MsiRecordValue(MsiValueKind.Null, null, null, null);
        }

        return column.Type switch
        {
            MsiColumnType.Integer => ReadInteger(record, field, column),
            MsiColumnType.String => ReadString(record, field, limits),
            MsiColumnType.Stream => new MsiRecordValue(
                MsiValueKind.Stream, null, null, MsiRecordDataSize(record, field)),
            _ => throw new MsiDataIncompleteException("Unknown MSI column type."),
        };
    }

    private static MsiRecordValue ReadInteger(
        SafeMsiRecordHandle record,
        uint field,
        MsiColumnDefinition column)
    {
        var value = MsiRecordGetInteger(record, field);
        return value == MsiNullInteger
            ? new MsiRecordValue(
                MsiValueKind.Null,
                null,
                null,
                null,
                false,
                $"MSI integer field {column.Name} could not be read.")
            : new MsiRecordValue(MsiValueKind.Integer, value, null, null);
    }

    private static MsiRecordValue ReadString(
        SafeMsiRecordHandle record,
        uint field,
        MsiAnalysisLimits limits)
    {
        uint Reader(StringBuilder? buffer, ref uint length) =>
            MsiRecordGetStringW(record, field, buffer, ref length);
        var result = ReadText(Reader, limits.MaxTextScalars);
        return new MsiRecordValue(
            MsiValueKind.String,
            null,
            result.Text,
            null,
            result.IsComplete,
            result.IncompleteReason);
    }

    private static MsiSummaryProperty? ReadSummaryProperty(
        SafeMsiSummaryHandle summary,
        int propertyId,
        MsiAnalysisLimits limits)
    {
        uint dataType = 0;
        var integer = 0;
        uint length = 0;
        var status = MsiSummaryInfoGetPropertyW(
            summary,
            checked((uint)propertyId),
            out dataType,
            out integer,
            nint.Zero,
            null,
            ref length);
        if (status != ErrorSuccess && status != ErrorMoreData)
        {
            throw new MsiDatabaseException($"read summary property {propertyId}", status);
        }
        if (dataType == VariantEmpty) return null;
        if (dataType is VariantI2 or VariantI4)
        {
            var value = new MsiRecordValue(MsiValueKind.Integer, integer, null, null);
            return new MsiSummaryProperty(propertyId, value, true, null);
        }
        if (dataType is VariantLpstr or VariantLpwstr)
        {
            uint Reader(StringBuilder? buffer, ref uint bufferLength)
            {
                var readStatus = MsiSummaryInfoGetPropertyW(
                    summary,
                    checked((uint)propertyId),
                    out dataType,
                    out integer,
                    nint.Zero,
                    buffer,
                    ref bufferLength);
                return readStatus;
            }
            var read = ReadTextAfterMeasurement(Reader, limits.MaxTextScalars, length);
            var value = new MsiRecordValue(
                MsiValueKind.String,
                null,
                read.Text,
                null,
                read.IsComplete,
                read.IncompleteReason);
            return new MsiSummaryProperty(
                propertyId, value, read.IsComplete, read.IncompleteReason);
        }

        var unsupported = new MsiRecordValue(
            MsiValueKind.Null,
            null,
            null,
            null,
            false,
            $"Summary property {propertyId} used unsupported variant type {dataType}.");
        return new MsiSummaryProperty(
            propertyId, unsupported, false, unsupported.IncompleteReason);
    }

    private static bool KeysMatch(
        SafeMsiRecordHandle record,
        MsiTableDefinition definition,
        ImmutableArray<MsiRecordValue> keys,
        CancellationToken cancellationToken)
    {
        for (var index = 0; index < keys.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var actual = ReadValue(
                record,
                checked((uint)index + 1),
                definition.Columns[index],
                MsiAnalysisLimits.Default);
            if (!actual.IsComplete || !EqualsValue(actual, keys[index])) return false;
        }
        return true;
    }

    private static bool EqualsValue(MsiRecordValue left, MsiRecordValue right) =>
        left.Kind == right.Kind
        && left.Integer == right.Integer
        && string.Equals(
            left.Text?.DisplayText,
            right.Text?.DisplayText,
            StringComparison.Ordinal);

    private static MemoryStream ReadStream(
        SafeMsiRecordHandle record,
        uint field,
        ExtractionBudget budget,
        CancellationToken cancellationToken)
    {
        var output = new MemoryStream();
        var buffer = new byte[StreamBufferSize];
        long total = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var requested = checked((uint)buffer.Length);
            Check(MsiRecordReadStream(record, field, buffer, ref requested), "read MSI stream");
            if (requested == 0) break;
            output.Write(buffer, 0, checked((int)requested));
            total += requested;
            if (!budget.ChargeBytes(requested, total, 0))
            {
                output.Dispose();
                throw new MsiDataIncompleteException(
                    "MSI stream exceeded the configured extraction budget.");
            }
        }
        output.Position = 0;
        return output;
    }

    private SafeMsiViewHandle OpenView(string fixedQuery)
    {
        Check(MsiDatabaseOpenViewW(handle, fixedQuery, out var view), "open fixed query");
        return view;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }

    private static void Check(uint status, string operation)
    {
        if (status != ErrorSuccess) throw new MsiDatabaseException(operation, status);
    }

    internal delegate uint MsiStringRead(StringBuilder? buffer, ref uint length);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiOpenDatabaseW(
        string path, nint persistence, out SafeMsiDatabaseHandle database);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiDatabaseOpenViewW(
        SafeMsiDatabaseHandle database, string query, out SafeMsiViewHandle view);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiViewExecute(SafeMsiViewHandle view, nint record);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiViewFetch(
        SafeMsiViewHandle view, out SafeMsiRecordHandle record);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiViewClose(nint view);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiRecordGetFieldCount(SafeMsiRecordHandle record);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MsiRecordIsNull(SafeMsiRecordHandle record, uint field);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern int MsiRecordGetInteger(SafeMsiRecordHandle record, uint field);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    [SuppressMessage(
        "Performance",
        "CA1838:Avoid StringBuilder parameters for P/Invokes",
        Justification = "The bounded two-call MSI API contract requires a mutable UTF-16 buffer.")]
    private static extern uint MsiRecordGetStringW(
        SafeMsiRecordHandle record, uint field, StringBuilder? value, ref uint length);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiRecordDataSize(SafeMsiRecordHandle record, uint field);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiRecordReadStream(
        SafeMsiRecordHandle record, uint field, byte[] buffer, ref uint length);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiGetSummaryInformationW(
        SafeMsiDatabaseHandle database,
        string? databasePath,
        uint updateCount,
        out SafeMsiSummaryHandle summary);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    [SuppressMessage(
        "Performance",
        "CA1838:Avoid StringBuilder parameters for P/Invokes",
        Justification = "The bounded two-call MSI API contract requires a mutable UTF-16 buffer.")]
    private static extern uint MsiSummaryInfoGetPropertyW(
        SafeMsiSummaryHandle summary,
        uint propertyId,
        out uint dataType,
        out int integerValue,
        nint fileTime,
        StringBuilder? value,
        ref uint length);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiCloseHandle(nint handle);

    private sealed class SafeMsiDatabaseHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeMsiDatabaseHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() => MsiCloseHandle(handle) == ErrorSuccess;
    }

    private sealed class SafeMsiViewHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeMsiViewHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            var closeView = MsiViewClose(handle);
            var closeHandle = MsiCloseHandle(handle);
            return closeView == ErrorSuccess && closeHandle == ErrorSuccess;
        }
    }

    private sealed class SafeMsiRecordHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeMsiRecordHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() => MsiCloseHandle(handle) == ErrorSuccess;
    }

    private sealed class SafeMsiSummaryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeMsiSummaryHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() => MsiCloseHandle(handle) == ErrorSuccess;
    }
}

internal sealed record MsiTextReadResult(
    MsiTextResult? Text,
    bool IsComplete,
    string? IncompleteReason);

internal sealed class MsiDatabaseException : IOException
{
    internal MsiDatabaseException(string operation, uint status)
        : base($"Windows Installer could not {operation}; native status {status}.")
    {
        NativeStatus = status;
    }

    internal uint NativeStatus { get; }
}

internal sealed class MsiDataIncompleteException : IOException
{
    internal MsiDataIncompleteException(string message)
        : base(message)
    {
    }
}
