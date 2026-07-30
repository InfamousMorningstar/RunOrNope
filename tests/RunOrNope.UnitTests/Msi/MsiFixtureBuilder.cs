using System.Runtime.InteropServices;

namespace RunOrNope.Tests.Msi;

/// <summary>
/// Creates benign, synthetic MSI databases from test-authored literals only.
/// Mutating Windows Installer APIs are intentionally confined to this test assembly.
/// </summary>
internal sealed class MsiFixtureBuilder : IDisposable
{
    private const uint ErrorSuccess = 0;
    private const int MsiModifyInsert = 1;
    private static readonly nint CreatePersistence = 3;
    private readonly List<string> streamFiles = [];
    private nint database;

    public MsiFixtureBuilder()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"RunOrNope-benign-{Guid.NewGuid():N}.msi");
        Check(MsiOpenDatabaseW(Path, CreatePersistence, out database), nameof(MsiOpenDatabaseW));
    }

    public string Path { get; }

    public MsiFixtureBuilder AddTable(string createSql)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(createSql);
        Execute(createSql, 0);
        return this;
    }

    public MsiFixtureBuilder Insert(string insertSql, params object?[] values)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(insertSql);
        var record = MsiCreateRecord((uint)values.Length);
        if (record == 0) throw new InvalidOperationException("Could not create benign MSI fixture record.");

        try
        {
            for (var index = 0; index < values.Length; index++)
            {
                var field = checked((uint)index + 1);
                var status = values[index] switch
                {
                    null => ErrorSuccess,
                    int number => MsiRecordSetInteger(record, field, number),
                    string text => MsiRecordSetStringW(record, field, text),
                    _ => throw new ArgumentException(
                        $"Unsupported benign fixture value type {values[index]!.GetType().Name}.",
                        nameof(values)),
                };
                Check(status, "set fixture record field");
            }

            Execute(insertSql, record);
        }
        finally
        {
            Close(record);
        }

        return this;
    }

    public MsiFixtureBuilder AddStream(string table, string key, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (!string.Equals(table, "FixtureStreams", StringComparison.Ordinal))
        {
            throw new ArgumentException("Only the benign FixtureStreams table is supported.", nameof(table));
        }

        var streamPath = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"RunOrNope-benign-stream-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(streamPath, content);
        streamFiles.Add(streamPath);

        var record = MsiCreateRecord(2);
        if (record == 0) throw new InvalidOperationException("Could not create benign MSI stream record.");
        try
        {
            Check(MsiRecordSetStringW(record, 1, key), nameof(MsiRecordSetStringW));
            Check(MsiRecordSetStreamW(record, 2, streamPath), nameof(MsiRecordSetStreamW));
            Execute("INSERT INTO `FixtureStreams` (`Key`, `Payload`) VALUES (?, ?)", record);
        }
        finally
        {
            Close(record);
        }

        return this;
    }

    public MsiFixtureBuilder SetSummary(int propertyId, object value)
    {
        Check(
            MsiGetSummaryInformationW(database, null, 16, out var summary),
            nameof(MsiGetSummaryInformationW));
        try
        {
            uint status = value switch
            {
                int number => MsiSummaryInfoSetPropertyW(
                    summary, (uint)propertyId, 3, number, nint.Zero, null),
                string text => MsiSummaryInfoSetPropertyW(
                    summary, (uint)propertyId, 30, 0, nint.Zero, text),
                _ => throw new ArgumentException(
                    $"Unsupported benign summary value type {value.GetType().Name}.",
                    nameof(value)),
            };
            Check(status, nameof(MsiSummaryInfoSetPropertyW));
            Check(MsiSummaryInfoPersist(summary), nameof(MsiSummaryInfoPersist));
        }
        finally
        {
            Close(summary);
        }

        return this;
    }

    public string Commit()
    {
        Check(MsiDatabaseCommit(database), nameof(MsiDatabaseCommit));
        Close(database);
        database = 0;
        return Path;
    }

    public void Dispose()
    {
        if (database != 0)
        {
            Close(database);
            database = 0;
        }

        foreach (var streamFile in streamFiles)
        {
            if (File.Exists(streamFile)) File.Delete(streamFile);
        }

        if (File.Exists(Path)) File.Delete(Path);
    }

    private void Execute(string sql, nint record)
    {
        Check(MsiDatabaseOpenViewW(database, sql, out var view), nameof(MsiDatabaseOpenViewW));
        try
        {
            Check(MsiViewExecute(view, record), nameof(MsiViewExecute));
        }
        finally
        {
            Check(MsiViewClose(view), nameof(MsiViewClose));
            Close(view);
        }
    }

    private static void Close(nint handle)
    {
        if (handle != 0) Check(MsiCloseHandle(handle), nameof(MsiCloseHandle));
    }

    private static void Check(uint status, string operation)
    {
        if (status != ErrorSuccess)
        {
            throw new InvalidOperationException($"{operation} failed with Windows Installer status {status}.");
        }
    }

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiOpenDatabaseW(string path, nint persistence, out nint database);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiDatabaseOpenViewW(nint database, string query, out nint view);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiViewExecute(nint view, nint record);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiViewModify(nint view, int modifyMode, nint record);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern nint MsiCreateRecord(uint parameterCount);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiRecordSetStringW(nint record, uint field, string value);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiRecordSetInteger(nint record, uint field, int value);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiRecordSetStreamW(nint record, uint field, string filePath);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiDatabaseCommit(nint database);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiGetSummaryInformationW(
        nint database, string? databasePath, uint updateCount, out nint summary);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiSummaryInfoSetPropertyW(
        nint summary, uint propertyId, uint dataType, int integerValue, nint fileTime, string? value);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiSummaryInfoPersist(nint summary);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiViewClose(nint view);

    [DllImport("msi.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint MsiCloseHandle(nint handle);
}
