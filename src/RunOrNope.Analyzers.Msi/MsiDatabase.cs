using System.Collections.Immutable;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RunOrNope.Analyzers.Content;

namespace RunOrNope.Analyzers.Msi;

[StructLayout(LayoutKind.Sequential)]
internal struct MsiNativeFileTime
{
    internal uint Low;
    internal uint High;

    internal readonly long Value => unchecked((long)(((ulong)High << 32) | Low));
}

internal interface IMsiNativeApi
{
    uint OpenDatabaseReadOnly(string path, out uint database);
    uint OpenView(uint database, string query, out uint view);
    uint ExecuteView(uint view, uint record);
    uint FetchView(uint view, out uint record);
    uint CloseView(uint view);
    uint GetFieldCount(uint record);
    bool IsNull(uint record, uint field);
    int GetInteger(uint record, uint field);
    uint GetString(uint record, uint field, char[] value, ref uint length);
    uint ReadStream(uint record, uint field, byte[] buffer, ref uint length);
    uint GetSummary(uint database, out uint summary);
    uint GetSummaryProperty(
        uint summary,
        uint propertyId,
        out uint dataType,
        out int integerValue,
        out MsiNativeFileTime fileTime,
        char[] value,
        ref uint length);
    uint CloseHandle(uint handle);
}

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
    private readonly IMsiNativeApi native;

    internal MsiDatabaseFactory()
        : this(MsiDatabase.SystemNative)
    {
    }

    internal MsiDatabaseFactory(IMsiNativeApi native)
    {
        this.native = native ?? throw new ArgumentNullException(nameof(native));
    }

    public IMsiDatabaseReader OpenReadOnly(string path) =>
        MsiDatabase.OpenReadOnly(path, native);
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
    private const uint VariantFileTime = 64;
    private const int StreamBufferSize = 64 * 1024;
    private readonly IMsiNativeApi native;
    private readonly SafeMsiDatabaseHandle handle;
    private bool disposed;

    private MsiDatabase(IMsiNativeApi native, SafeMsiDatabaseHandle handle)
    {
        this.native = native;
        this.handle = handle;
    }

    internal static IMsiNativeApi SystemNative { get; } = new SystemMsiNativeApi();

    internal static MsiDatabase OpenReadOnly(string path)
        => OpenReadOnly(path, SystemNative);

    internal static MsiDatabase OpenReadOnly(string path, IMsiNativeApi native)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(native);
        return new MsiDatabase(native, OpenNativeReadOnly(path, native));
    }

    private static SafeMsiDatabaseHandle OpenNativeReadOnly(
        string path,
        IMsiNativeApi native)
    {
        var status = native.OpenDatabaseReadOnly(path, out var rawDatabase);
        var database = new SafeMsiDatabaseHandle(native, rawDatabase);
        if (status != ErrorSuccess)
        {
            database.Dispose();
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
        if (!MsiTables.IsKnown(definition))
        {
            throw new ArgumentException(
                "Only opaque definitions from the fixed MSI table catalog are accepted.",
                nameof(definition));
        }
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
        using var databaseLease = handle.AcquireLease();
        using var view = OpenView(databaseLease.Value, definition.Query);
        using var viewLease = view.AcquireLease();
        Check(native.ExecuteView(viewLease.Value, 0), "execute fixed query");

        var rowCount = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = native.FetchView(viewLease.Value, out var rawRecord);
            using var record = new SafeMsiRecordHandle(native, rawRecord);
            if (status == ErrorNoMoreItems)
            {
                yield break;
            }
            if (status != ErrorSuccess)
            {
                throw new MsiDatabaseException("fetch query row", status);
            }

            if (rowCount++ >= limits.MaxRowsPerTable)
            {
                throw new MsiDataIncompleteException(
                    $"MSI table {definition.Name} exceeded the configured row limit.");
            }
            using var recordLease = record.AcquireLease();
            yield return ReadRow(recordLease.Value, definition, limits);
        }
    }

    public ImmutableArray<MsiSummaryProperty> ReadSummary(
        MsiAnalysisLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ThrowIfDisposed();
        limits.Validate();
        using var databaseLease = handle.AcquireLease();
        var status = native.GetSummary(databaseLease.Value, out var rawSummary);
        using var summary = new SafeMsiSummaryHandle(native, rawSummary);
        if (status != ErrorSuccess)
        {
            throw new MsiDatabaseException("open summary information", status);
        }
        using var summaryLease = summary.AcquireLease();
        var properties = ImmutableArray.CreateBuilder<MsiSummaryProperty>();
        for (var propertyId = 1; propertyId <= 19; propertyId++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var property = ReadSummaryProperty(summaryLease.Value, propertyId, limits);
            if (property is not null) properties.Add(property);
        }
        return properties.ToImmutable();
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
        if (!MsiTables.IsKnown(definition))
        {
            throw new ArgumentException(
                "Only opaque definitions from the fixed MSI table catalog are accepted.",
                nameof(definition));
        }
        if (budget.Exhausted)
        {
            throw new MsiDataIncompleteException("MSI stream extraction budget was already exhausted.");
        }
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
        if (keyParameters.Any(key =>
                !key.IsComplete
                || key.Kind != MsiValueKind.String
                || key.Identity is null
                || key.Identity.Length
                    > checked(MsiAnalysisLimits.Default.MaxTextScalars * 2)
                || MsiTextPolicy.Sanitize(key.Identity, MsiAnalysisLimits.Default.MaxTextScalars)
                    .WasTruncated))
        {
            throw new MsiDataIncompleteException(
                "MSI stream keys must be complete bounded raw identities.");
        }

        using var databaseLease = handle.AcquireLease();
        using var view = OpenView(databaseLease.Value, definition.Query);
        using var viewLease = view.AcquireLease();
        Check(native.ExecuteView(viewLease.Value, 0), "execute fixed stream query");
        var rowCount = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = native.FetchView(viewLease.Value, out var rawRecord);
            using var record = new SafeMsiRecordHandle(native, rawRecord);
            if (status == ErrorNoMoreItems)
            {
                throw new MsiDataIncompleteException(
                    $"The requested stream was absent from MSI table {definition.Name}.");
            }
            if (status != ErrorSuccess)
            {
                throw new MsiDatabaseException("fetch stream row", status);
            }

            if (rowCount++ >= MsiAnalysisLimits.Default.MaxRowsPerTable)
            {
                throw new MsiDataIncompleteException(
                    $"MSI table {definition.Name} exceeded the configured stream-selection row limit.");
            }
            using var recordLease = record.AcquireLease();
            ValidateFieldCount(recordLease.Value, definition, MsiAnalysisLimits.Default);
            if (!KeysMatch(
                    recordLease.Value,
                    definition,
                    keyParameters,
                    cancellationToken))
            {
                continue;
            }
            return ReadStream(
                recordLease.Value,
                checked((uint)streamIndex + 1),
                budget,
                cancellationToken);
        }
    }

    internal static MsiTextReadResult ReadText(MsiStringRead reader, int maxScalars)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxScalars);

        var probe = new char[1];
        uint reportedLength = 0;
        var firstStatus = reader(probe, ref reportedLength);
        if (firstStatus != ErrorSuccess && firstStatus != ErrorMoreData)
        {
            throw new MsiDatabaseException("measure MSI string", firstStatus);
        }
        return ReadTextAfterMeasurement(
            reader, maxScalars, firstStatus, reportedLength);
    }

    private static MsiTextReadResult ReadTextAfterMeasurement(
        MsiStringRead reader,
        int maxScalars,
        uint firstStatus,
        uint reportedLength)
    {
        var maxUtf16Units = checked(maxScalars * 2);
        var buffer = new char[checked(maxUtf16Units + 1)];
        var secondLength = checked((uint)buffer.Length);
        var secondStatus = reader(buffer, ref secondLength);
        if (secondStatus != ErrorSuccess && secondStatus != ErrorMoreData)
        {
            throw new MsiDatabaseException("read MSI string", secondStatus);
        }

        var copiedLength = Math.Min(secondLength, checked((uint)maxUtf16Units));
        var rawText = new string(buffer, 0, checked((int)copiedLength));
        var text = MsiTextPolicy.Sanitize(rawText, maxScalars);
        var probeStateIsConsistent =
            firstStatus == ErrorSuccess && reportedLength == 0
            || firstStatus == ErrorMoreData && reportedLength > 0;
        var readStateIsConsistent =
            secondStatus == ErrorSuccess && secondLength <= maxUtf16Units
            || secondStatus == ErrorMoreData
                && secondLength >= checked((uint)buffer.Length);
        if (!probeStateIsConsistent || !readStateIsConsistent)
        {
            return new MsiTextReadResult(
                text with
                {
                    WasTruncated = text.WasTruncated
                        || secondStatus == ErrorMoreData
                        || secondLength > maxUtf16Units,
                },
                false,
                "MSI text returned an inconsistent native status and length.",
                rawText);
        }
        if (secondStatus == ErrorMoreData || secondLength > maxUtf16Units || text.WasTruncated)
        {
            return new MsiTextReadResult(
                text with { WasTruncated = true },
                false,
                secondLength > reportedLength && reportedLength <= maxUtf16Units
                    ? "MSI text changed while it was being retrieved."
                    : "MSI text exceeded the configured scalar limit.",
                rawText);
        }
        if (secondLength < reportedLength)
        {
            return new MsiTextReadResult(
                text,
                false,
                "MSI text became shorter while it was being retrieved.",
                rawText);
        }
        if (secondLength > reportedLength
            || (firstStatus == ErrorSuccess && reportedLength != secondLength))
        {
            return new MsiTextReadResult(
                text,
                false,
                "MSI text changed while it was being retrieved.",
                rawText);
        }

        return new MsiTextReadResult(text, true, null, rawText);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        handle.Dispose();
    }

    private MsiRow ReadRow(
        uint record,
        MsiTableDefinition definition,
        MsiAnalysisLimits limits)
    {
        ValidateFieldCount(record, definition, limits);

        var fields = ImmutableArray.CreateBuilder<MsiRecordValue>(definition.Columns.Length);
        for (var index = 0; index < definition.Columns.Length; index++)
        {
            fields.Add(ReadValue(record, checked((uint)index + 1), definition.Columns[index], limits));
        }
        return new MsiRow(fields.MoveToImmutable());
    }

    private MsiRecordValue ReadValue(
        uint record,
        uint field,
        MsiColumnDefinition column,
        MsiAnalysisLimits limits)
    {
        if (native.IsNull(record, field))
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
                MsiValueKind.Stream,
                null,
                null,
                null,
                false,
                "MSI stream length is available only from the bounded read path."),
            _ => throw new MsiDataIncompleteException("Unknown MSI column type."),
        };
    }

    private MsiRecordValue ReadInteger(
        uint record,
        uint field,
        MsiColumnDefinition column)
    {
        var value = native.GetInteger(record, field);
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

    private MsiRecordValue ReadString(
        uint record,
        uint field,
        MsiAnalysisLimits limits)
    {
        uint Reader(char[] buffer, ref uint length) =>
            native.GetString(record, field, buffer, ref length);
        var result = ReadText(Reader, limits.MaxTextScalars);
        return new MsiRecordValue(
            MsiValueKind.String,
            null,
            result.Text,
            null,
            result.IsComplete,
            result.IncompleteReason,
            result.RawText);
    }

    private MsiSummaryProperty? ReadSummaryProperty(
        uint summary,
        int propertyId,
        MsiAnalysisLimits limits)
    {
        uint dataType = 0;
        var integer = 0;
        MsiNativeFileTime fileTime;
        var probe = new char[1];
        uint length = 0;
        var status = native.GetSummaryProperty(
            summary,
            checked((uint)propertyId),
            out dataType,
            out integer,
            out fileTime,
            probe,
            ref length);
        if (status != ErrorSuccess && status != ErrorMoreData)
        {
            throw new MsiDatabaseException($"read summary property {propertyId}", status);
        }
        if (dataType == VariantEmpty)
        {
            if (status == ErrorSuccess && length == 0) return null;

            return IncompleteSummaryProperty(
                propertyId,
                MsiValueKind.Null,
                $"Summary property {propertyId} returned an inconsistent empty state.");
        }
        if (!IsExpectedSummaryType(propertyId, dataType))
        {
            return IncompleteSummaryProperty(
                propertyId,
                MsiValueKind.Null,
                $"Summary property {propertyId} used unexpected variant type {dataType}.");
        }
        if (dataType is VariantI2 or VariantI4)
        {
            if (status != ErrorSuccess || length != 0)
            {
                return IncompleteSummaryProperty(
                    propertyId,
                    MsiValueKind.Integer,
                    $"Summary property {propertyId} returned an inconsistent integer state.");
            }

            var value = new MsiRecordValue(MsiValueKind.Integer, integer, null, null);
            return new MsiSummaryProperty(propertyId, value, true, null);
        }
        if (dataType == VariantFileTime)
        {
            if (status != ErrorSuccess || length != 0)
            {
                return IncompleteSummaryProperty(
                    propertyId,
                    MsiValueKind.FileTime,
                    $"Summary property {propertyId} returned an inconsistent FILETIME state.");
            }

            if (propertyId == 10)
            {
                if (fileTime.Value < 0)
                {
                    var reason =
                        $"Summary property {propertyId} contained an invalid FILETIME.";
                    var invalid = new MsiRecordValue(
                        MsiValueKind.FileTime, null, null, null, false, reason);
                    return new MsiSummaryProperty(propertyId, invalid, false, reason);
                }

                var duration = new MsiRecordValue(
                    MsiValueKind.FileTime,
                    null,
                    null,
                    null,
                    Duration: TimeSpan.FromTicks(fileTime.Value));
                return new MsiSummaryProperty(propertyId, duration, true, null);
            }

            try
            {
                var value = new MsiRecordValue(
                    MsiValueKind.FileTime,
                    null,
                    null,
                    null,
                    Timestamp: DateTimeOffset.FromFileTime(fileTime.Value)
                        .ToUniversalTime());
                return new MsiSummaryProperty(propertyId, value, true, null);
            }
            catch (ArgumentOutOfRangeException)
            {
                var reason = $"Summary property {propertyId} contained an invalid FILETIME.";
                var invalid = new MsiRecordValue(
                    MsiValueKind.FileTime, null, null, null, false, reason);
                return new MsiSummaryProperty(propertyId, invalid, false, reason);
            }
        }
        if (dataType == VariantLpstr)
        {
            var measuredType = dataType;
            var typeChanged = false;
            uint Reader(char[] buffer, ref uint bufferLength)
            {
                var readStatus = native.GetSummaryProperty(
                    summary,
                    checked((uint)propertyId),
                    out dataType,
                    out integer,
                    out fileTime,
                    buffer,
                    ref bufferLength);
                typeChanged = dataType != measuredType;
                return readStatus;
            }
            var read = ReadTextAfterMeasurement(
                Reader, limits.MaxTextScalars, status, length);
            if (typeChanged)
            {
                const string reason =
                    "MSI summary property type changed while it was being retrieved.";
                var changed = new MsiRecordValue(
                    MsiValueKind.String,
                    null,
                    read.Text,
                    null,
                    false,
                    reason,
                    read.RawText);
                return new MsiSummaryProperty(propertyId, changed, false, reason);
            }
            var value = new MsiRecordValue(
                MsiValueKind.String,
                null,
                read.Text,
                null,
                read.IsComplete,
                read.IncompleteReason,
                read.RawText);
            return new MsiSummaryProperty(
                propertyId, value, read.IsComplete, read.IncompleteReason);
        }

        throw new MsiDataIncompleteException(
            $"Summary property {propertyId} could not be represented safely.");
    }

    private bool KeysMatch(
        uint record,
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
            if (!actual.IsComplete || actual.Identity is null)
            {
                throw new MsiDataIncompleteException(
                    actual.IncompleteReason ?? "An MSI stream key was unreadable.");
            }
            if (!EqualsValue(actual, keys[index])) return false;
        }
        return true;
    }

    private static bool EqualsValue(MsiRecordValue left, MsiRecordValue right) =>
        left.Kind == right.Kind
        && left.Integer == right.Integer
        && string.Equals(
            left.Identity,
            right.Identity,
            StringComparison.Ordinal);

    private MemoryStream ReadStream(
        uint record,
        uint field,
        ExtractionBudget budget,
        CancellationToken cancellationToken)
    {
        var output = new MemoryStream();
        try
        {
            var buffer = new byte[StreamBufferSize];
            long total = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = checked((uint)buffer.Length);
                Check(
                    native.ReadStream(
                        record, field, buffer, ref requested),
                    "read MSI stream");
                if (requested == 0) break;
                if (requested > checked((uint)buffer.Length))
                {
                    throw new MsiDataIncompleteException(
                        "MSI stream returned more bytes than fit in the supplied buffer.");
                }
                total += requested;
                if (!budget.ChargeBytes(requested, total, 0))
                {
                    throw new MsiDataIncompleteException(
                        "MSI stream exceeded the configured extraction budget.");
                }
                output.Write(buffer, 0, checked((int)requested));
            }
            output.Position = 0;
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    private SafeMsiViewHandle OpenView(uint database, string fixedQuery)
    {
        var status = native.OpenView(
            database, fixedQuery, out var rawView);
        var view = new SafeMsiViewHandle(native, rawView);
        if (status != ErrorSuccess)
        {
            view.Dispose();
            throw new MsiDatabaseException("open fixed query", status);
        }
        return view;
    }

    private void ValidateFieldCount(
        uint record,
        MsiTableDefinition definition,
        MsiAnalysisLimits limits)
    {
        var fieldCount = native.GetFieldCount(record);
        if (fieldCount > limits.MaxFieldsPerRecord
            || fieldCount != definition.Columns.Length)
        {
            throw new MsiDataIncompleteException(
                $"MSI query for {definition.Name} returned {fieldCount} fields; " +
                $"{definition.Columns.Length} bounded fields were required.");
        }
    }

    private static bool IsExpectedSummaryType(int propertyId, uint dataType) =>
        propertyId switch
        {
            1 => dataType == VariantI2,
            >= 2 and <= 9 or 18 => dataType == VariantLpstr,
            >= 10 and <= 13 => dataType == VariantFileTime,
            >= 14 and <= 16 or 19 => dataType == VariantI4,
            _ => false,
        };

    private static MsiSummaryProperty IncompleteSummaryProperty(
        int propertyId,
        MsiValueKind kind,
        string reason)
    {
        var value = new MsiRecordValue(
            kind, null, null, null, false, reason);
        return new MsiSummaryProperty(propertyId, value, false, reason);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }

    private static void Check(uint status, string operation)
    {
        if (status != ErrorSuccess) throw new MsiDatabaseException(operation, status);
    }

    internal delegate uint MsiStringRead(char[] buffer, ref uint length);

    private sealed class SystemMsiNativeApi : IMsiNativeApi
    {
        public uint OpenDatabaseReadOnly(string path, out uint database) =>
            MsiOpenDatabaseW(path, default, out database);

        public uint OpenView(uint database, string query, out uint view) =>
            MsiDatabaseOpenViewW(database, query, out view);

        public uint ExecuteView(uint view, uint record) =>
            MsiViewExecute(view, record);

        public uint FetchView(uint view, out uint record) =>
            MsiViewFetch(view, out record);

        public uint CloseView(uint view) => MsiViewClose(view);

        public uint GetFieldCount(uint record) => MsiRecordGetFieldCount(record);

        public bool IsNull(uint record, uint field) => MsiRecordIsNull(record, field);

        public int GetInteger(uint record, uint field) => MsiRecordGetInteger(record, field);

        public uint GetString(uint record, uint field, char[] value, ref uint length) =>
            MsiRecordGetStringW(record, field, value, ref length);

        public uint ReadStream(uint record, uint field, byte[] buffer, ref uint length) =>
            MsiRecordReadStream(record, field, buffer, ref length);

        public uint GetSummary(uint database, out uint summary) =>
            MsiGetSummaryInformationW(database, null, 0, out summary);

        public uint GetSummaryProperty(
            uint summary,
            uint propertyId,
            out uint dataType,
            out int integerValue,
            out MsiNativeFileTime fileTime,
            char[] value,
            ref uint length) =>
            MsiSummaryInfoGetPropertyW(
                summary,
                propertyId,
                out dataType,
                out integerValue,
                out fileTime,
                value,
                ref length);

        public uint CloseHandle(uint handle) => MsiCloseHandle(handle);
    }

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiOpenDatabaseW(
        [MarshalAs(UnmanagedType.LPWStr)] string path,
        nint persistence,
        out uint database);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiDatabaseOpenViewW(
        uint database,
        [MarshalAs(UnmanagedType.LPWStr)] string query,
        out uint view);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiViewExecute(uint view, uint record);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiViewFetch(uint view, out uint record);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiViewClose(uint view);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiRecordGetFieldCount(uint record);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MsiRecordIsNull(uint record, uint field);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern int MsiRecordGetInteger(uint record, uint field);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiRecordGetStringW(
        uint record,
        uint field,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2, SizeParamIndex = 3)]
        char[] value,
        ref uint length);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiRecordReadStream(
        uint record,
        uint field,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1, SizeParamIndex = 3)]
        byte[] buffer,
        ref uint length);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiGetSummaryInformationW(
        uint database,
        [MarshalAs(UnmanagedType.LPWStr)] string? databasePath,
        uint updateCount,
        out uint summary);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiSummaryInfoGetPropertyW(
        uint summary,
        uint propertyId,
        out uint dataType,
        out int integerValue,
        out MsiNativeFileTime fileTime,
        [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2, SizeParamIndex = 6)]
        char[] value,
        ref uint length);

    [DllImport(
        "msi.dll",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        CallingConvention = CallingConvention.Winapi,
        PreserveSig = true)]
    private static extern uint MsiCloseHandle(uint handle);

    private abstract class MsiSafeHandleBase : SafeHandle
    {
        protected MsiSafeHandleBase(uint handle)
            : base(nint.Zero, true)
        {
            SetHandle(unchecked((nint)handle));
        }

        public override bool IsInvalid => handle == nint.Zero;

        internal uint Value => unchecked((uint)handle.ToInt64());

        internal MsiHandleLease AcquireLease() => new(this);
    }

    private sealed class MsiHandleLease : IDisposable
    {
        private MsiSafeHandleBase? owner;

        internal MsiHandleLease(MsiSafeHandleBase owner)
        {
            var addedReference = false;
            owner.DangerousAddRef(ref addedReference);
            ObjectDisposedException.ThrowIf(!addedReference, owner);

            this.owner = owner;
            Value = owner.Value;
        }

        internal uint Value { get; }

        public void Dispose()
        {
            var owned = Interlocked.Exchange(ref owner, null);
            owned?.DangerousRelease();
        }
    }

    private sealed class SafeMsiDatabaseHandle : MsiSafeHandleBase
    {
        private readonly IMsiNativeApi native;

        internal SafeMsiDatabaseHandle(IMsiNativeApi native, uint handle)
            : base(handle)
        {
            this.native = native;
        }

        protected override bool ReleaseHandle() => native.CloseHandle(Value) == ErrorSuccess;
    }

    private sealed class SafeMsiViewHandle : MsiSafeHandleBase
    {
        private readonly IMsiNativeApi native;

        internal SafeMsiViewHandle(IMsiNativeApi native, uint handle)
            : base(handle)
        {
            this.native = native;
        }

        protected override bool ReleaseHandle()
        {
            var closeView = native.CloseView(Value);
            var closeHandle = native.CloseHandle(Value);
            return closeView == ErrorSuccess && closeHandle == ErrorSuccess;
        }
    }

    private sealed class SafeMsiRecordHandle : MsiSafeHandleBase
    {
        private readonly IMsiNativeApi native;

        internal SafeMsiRecordHandle(IMsiNativeApi native, uint handle)
            : base(handle)
        {
            this.native = native;
        }

        protected override bool ReleaseHandle() => native.CloseHandle(Value) == ErrorSuccess;
    }

    private sealed class SafeMsiSummaryHandle : MsiSafeHandleBase
    {
        private readonly IMsiNativeApi native;

        internal SafeMsiSummaryHandle(IMsiNativeApi native, uint handle)
            : base(handle)
        {
            this.native = native;
        }

        protected override bool ReleaseHandle() => native.CloseHandle(Value) == ErrorSuccess;
    }
}

internal sealed record MsiTextReadResult(
    MsiTextResult? Text,
    bool IsComplete,
    string? IncompleteReason,
    string? RawText = null);

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
