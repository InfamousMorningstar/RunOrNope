using System.Text;
using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.Tests.Msi;

public sealed class MsiDatabaseTests
{
    [Fact]
    public void Native_boundary_is_injectable_for_failure_path_proofs()
    {
        var assembly = typeof(MsiDatabase).Assembly;
        var nativeType = assembly.GetType("RunOrNope.Analyzers.Msi.IMsiNativeApi");

        nativeType.Should().NotBeNull();
        typeof(MsiDatabaseFactory).GetConstructors(
                System.Reflection.BindingFlags.Instance
                | System.Reflection.BindingFlags.Public
                | System.Reflection.BindingFlags.NonPublic)
            .SelectMany(constructor => constructor.GetParameters())
            .Select(parameter => parameter.ParameterType)
            .Should().Contain(nativeType!);
    }

    [Fact]
    public void Open_view_failure_closes_the_returned_view_and_database_handles()
    {
        var native = new RecordingMsiNativeApi { OpenViewStatus = 5 };
        using var database = new MsiDatabaseFactory(native).OpenReadOnly("synthetic.msi");

        var action = () => database.Query(
            MsiTables.FixtureValues,
            [],
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken).ToArray();

        action.Should().Throw<MsiDatabaseException>().Which.NativeStatus.Should().Be(5);
        database.Dispose();
        native.Events.Should().ContainInOrder("close-view:22", "close:22", "close:11");
    }

    [Fact]
    public void Database_open_failure_closes_the_returned_database_handle()
    {
        var native = new RecordingMsiNativeApi { OpenStatus = 5 };

        var action = () => MsiDatabase.OpenReadOnly("synthetic.msi", native);

        action.Should().Throw<MsiDatabaseException>().Which.NativeStatus.Should().Be(5);
        native.Events.Should().ContainInOrder("open:synthetic.msi:11", "close:11");
    }

    [Fact]
    public void Summary_open_failure_closes_the_returned_summary_and_database_handles()
    {
        var native = new RecordingMsiNativeApi { SummaryStatus = 5 };
        using var database = new MsiDatabaseFactory(native).OpenReadOnly("synthetic.msi");

        var action = () => database.ReadSummary(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDatabaseException>().Which.NativeStatus.Should().Be(5);
        database.Dispose();
        native.Events.Should().ContainInOrder("close:33", "close:11");
    }

    [Fact]
    public void Fetch_failure_closes_returned_record_before_view_and_database()
    {
        var native = new RecordingMsiNativeApi
        {
            FetchStatus = 5,
            FetchRecord = 44,
        };
        using var database = new MsiDatabaseFactory(native).OpenReadOnly("synthetic.msi");

        var action = () => database.Query(
            MsiTables.FixtureValues,
            [],
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken).ToArray();

        action.Should().Throw<MsiDatabaseException>().Which.NativeStatus.Should().Be(5);
        database.Dispose();
        native.Events.Should().ContainInOrder(
            "close:44",
            "close-view:22",
            "close:22",
            "close:11");
    }

    [Fact]
    public void Summary_type_change_between_probe_and_read_is_incomplete()
    {
        var native = new RecordingMsiNativeApi { ChangeSummaryTypeOnRead = true };
        using var database = new MsiDatabaseFactory(native).OpenReadOnly("synthetic.msi");

        var property = database.ReadSummary(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken)
            .Single(item => item.PropertyId == 2);

        property.IsComplete.Should().BeFalse();
        property.IncompleteReason.Should().Contain("type changed");
    }

    [Fact]
    public void Stream_selection_stops_at_the_row_ceiling_without_reading_content()
    {
        var native = new RecordingMsiNativeApi
        {
            RowsBeforeNoMore = MsiAnalysisLimits.Default.MaxRowsPerTable + 1,
            FieldCount = 2,
            ActualKey = "miss",
        };
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [CompleteKey("target")],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDataIncompleteException>().WithMessage("*row limit*");
        native.FetchCalls.Should().Be(MsiAnalysisLimits.Default.MaxRowsPerTable + 1);
        native.StreamReadCalls.Should().Be(0);
    }

    [Fact]
    public void Stream_selection_rejects_records_over_the_field_ceiling()
    {
        var native = new RecordingMsiNativeApi
        {
            RowsBeforeNoMore = 1,
            FieldCount = 33,
            ActualKey = "target",
        };
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [CompleteKey("target")],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDataIncompleteException>().WithMessage("*fields*");
        native.StreamReadCalls.Should().Be(0);
    }

    [Fact]
    public void Incomplete_caller_stream_key_is_rejected_before_opening_a_view()
    {
        var native = new RecordingMsiNativeApi();
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);
        var incomplete = CompleteKey("target") with
        {
            IsComplete = false,
            IncompleteReason = "test incomplete key",
        };

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [incomplete],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDataIncompleteException>().WithMessage("*complete bounded*");
        native.Events.Should().NotContain(item =>
            item.StartsWith("open-view:", StringComparison.Ordinal));
    }

    [Fact]
    public void Unreadable_actual_stream_key_fails_closed()
    {
        var native = new RecordingMsiNativeApi
        {
            RowsBeforeNoMore = 1,
            FieldCount = 2,
            ActualKey = "target",
            ChangeKeyOnRead = true,
        };
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [CompleteKey("target")],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDataIncompleteException>().WithMessage("*changed*");
        native.StreamReadCalls.Should().Be(0);
    }

    [Fact]
    public void Stream_cancellation_closes_record_view_and_database_handles()
    {
        using var cancellation = new CancellationTokenSource();
        var native = new RecordingMsiNativeApi
        {
            RowsBeforeNoMore = 1,
            FieldCount = 2,
            ActualKey = "target",
            StreamContent = [1, 2, 3],
            CancelAfterFirstStreamRead = cancellation,
        };
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [CompleteKey("target")],
            new ExtractionBudget(),
            cancellation.Token);

        action.Should().Throw<OperationCanceledException>();
        database.Dispose();
        native.Events.Should().ContainInOrder(
            "close:44",
            "close-view:22",
            "close:22",
            "close:11");
    }

    [Fact]
    public void Native_stream_failure_closes_record_view_and_database_handles()
    {
        var native = new RecordingMsiNativeApi
        {
            RowsBeforeNoMore = 1,
            FieldCount = 2,
            ActualKey = "target",
            StreamStatus = 5,
        };
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [CompleteKey("target")],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDatabaseException>().Which.NativeStatus.Should().Be(5);
        database.Dispose();
        native.Events.Should().ContainInOrder(
            "close:44",
            "close-view:22",
            "close:22",
            "close:11");
    }

    [Fact]
    public void Oversized_native_stream_count_is_incomplete_before_budget_charge()
    {
        var native = new RecordingMsiNativeApi
        {
            RowsBeforeNoMore = 1,
            FieldCount = 2,
            ActualKey = "target",
            OversizedStreamLength = true,
        };
        var budget = new ExtractionBudget();
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [CompleteKey("target")],
            budget,
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDataIncompleteException>().WithMessage("*buffer*");
        budget.TotalExpandedBytes.Should().Be(0);
    }

    [Fact]
    public void Edit_time_filetime_is_a_duration_not_a_timestamp()
    {
        var native = new RecordingMsiNativeApi
        {
            EditDurationTicks = TimeSpan.FromMinutes(17).Ticks,
        };
        using var database = MsiDatabase.OpenReadOnly("synthetic.msi", native);

        var property = database.ReadSummary(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken)
            .Single(item => item.PropertyId == 10);

        property.IsComplete.Should().BeTrue();
        property.Value.Duration.Should().Be(TimeSpan.FromMinutes(17));
        property.Value.Timestamp.Should().BeNull();
    }

    [Fact]
    public void Fixed_queries_return_null_integer_string_and_stream_values()
    {
        using var fixture = CreateFixture();
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());

        var row = database.Query(
            MsiTables.FixtureValues,
            [],
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken).Single();
        var streamRow = database.Query(
            MsiTables.FixtureStreams,
            [],
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken).Single();

        row.Fields[0].Text!.DisplayText.Should().Be("alpha");
        row.Fields[1].Kind.Should().Be(MsiValueKind.Null);
        row.Fields[2].Integer.Should().Be(42);
        row.Fields[3].Text!.DisplayText.Should().Be("benign value");
        streamRow.Fields[1].StreamLength.Should().BeNull();
        streamRow.Fields[1].IsComplete.Should().BeFalse();
    }

    [Fact]
    public void Enumerate_tables_and_summary_return_exact_benign_metadata()
    {
        using var fixture = CreateFixture();
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());

        var tables = database.EnumerateTables(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken);
        var summary = database.ReadSummary(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken);

        tables.Should().Contain(["FixtureValues", "FixtureStreams"]);
        summary.Single(property => property.PropertyId == 2)
            .Value.Text!.DisplayText.Should().Be("Benign Fixture");
        summary.Single(property => property.PropertyId == 14)
            .Value.Integer.Should().Be(7);
    }

    [Fact]
    public void Long_native_string_is_bounded_and_marked_incomplete()
    {
        using var fixture = CreateFixture(new string('x', 12_289));
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());

        var row = database.Query(
            MsiTables.FixtureValues,
            [],
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken).Single();

        row.Fields[3].Text!.DisplayText.Should().HaveLength(12_288);
        row.Fields[3].Text!.WasTruncated.Should().BeTrue();
        row.Fields[3].IsComplete.Should().BeFalse();
        row.Fields[3].IncompleteReason.Should().Contain("limit");
    }

    [Fact]
    public void Changing_native_string_is_incomplete()
    {
        var call = 0;
        uint Reader(char[]? buffer, ref uint length)
        {
            call++;
            if (call == 1)
            {
                length = 4;
                return 234;
            }

            length = 8;
            return 234;
        }

        var result = MsiDatabase.ReadText(Reader, 12_288);

        result.IsComplete.Should().BeFalse();
        result.IncompleteReason.Should().Contain("changed");
    }

    [Fact]
    public void Native_string_sizing_uses_non_null_probe_and_always_reads_again()
    {
        var call = 0;
        uint Reader(char[]? buffer, ref uint length)
        {
            buffer.Should().NotBeNull();
            call++;
            if (call == 1)
            {
                length.Should().Be(0);
                length = 0;
                return 0;
            }

            length.Should().BeGreaterThan(0);
            length = 0;
            return 0;
        }

        var result = MsiDatabase.ReadText(Reader, 12_288);

        call.Should().Be(2);
        result.IsComplete.Should().BeTrue();
        result.Text!.DisplayText.Should().BeEmpty();
    }

    [Fact]
    public void Utf16_buffer_allows_maximum_number_of_supplementary_scalars()
    {
        var expected = string.Concat(Enumerable.Repeat("\U0001F680", 12_288));
        var call = 0;
        uint Reader(char[]? buffer, ref uint length)
        {
            buffer.Should().NotBeNull();
            call++;
            if (call == 1)
            {
                length = checked((uint)expected.Length);
                return 234;
            }

            buffer!.Length.Should().BeGreaterThanOrEqualTo(expected.Length + 1);
            expected.AsSpan().CopyTo(buffer);
            length = checked((uint)expected.Length);
            return 0;
        }

        var result = MsiDatabase.ReadText(Reader, 12_288);

        result.IsComplete.Should().BeTrue();
        result.Text!.OriginalScalars.Should().Be(12_288);
        result.Text.WasTruncated.Should().BeFalse();
    }

    [Fact]
    public void Short_native_string_is_incomplete()
    {
        var call = 0;
        uint Reader(char[]? buffer, ref uint length)
        {
            call++;
            if (call == 1)
            {
                length = 8;
                return 234;
            }

            "tiny".AsSpan().CopyTo(buffer);
            length = 4;
            return 0;
        }

        var result = MsiDatabase.ReadText(Reader, 12_288);

        result.Text!.DisplayText.Should().Be("tiny");
        result.IsComplete.Should().BeFalse();
        result.IncompleteReason.Should().Contain("shorter");
    }

    [Fact]
    public void Stream_reads_charge_actual_bytes_to_extraction_budget()
    {
        using var fixture = CreateFixture();
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());
        var budget = new ExtractionBudget();

        using var stream = database.OpenStream(
            MsiTables.FixtureStreams,
            [new MsiRecordValue(
                MsiValueKind.String,
                null,
                MsiTextPolicy.Sanitize("payload", 32),
                null,
                Identity: "payload")],
            budget,
            TestContext.Current.CancellationToken);
        using var sink = new MemoryStream();
        stream.CopyTo(sink);

        sink.ToArray().Should().Equal(Enumerable.Range(0, 70_001).Select(i => (byte)(i % 251)));
        budget.TotalExpandedBytes.Should().Be(70_001);
    }

    [Fact]
    public void Exhausted_budget_is_rejected_before_any_stream_bytes_are_read()
    {
        using var fixture = CreateFixture();
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());
        var budget = new ExtractionBudget(new ExtractionCeilings { MaxTotalExpandedBytes = 1 });
        budget.ChargeBytes(2, 2, 0).Should().BeFalse();
        var chargedBefore = budget.TotalExpandedBytes;

        var action = () => database.OpenStream(
            MsiTables.FixtureStreams,
            [new MsiRecordValue(
                MsiValueKind.String,
                null,
                MsiTextPolicy.Sanitize("payload", 32),
                null,
                Identity: "payload")],
            budget,
            TestContext.Current.CancellationToken);

        action.Should().Throw<MsiDataIncompleteException>();
        budget.TotalExpandedBytes.Should().Be(chargedBefore);
    }

    [Fact]
    public void Stream_key_comparison_uses_raw_identity_not_sanitized_display()
    {
        var first = new byte[] { 1, 2, 3 };
        var second = new byte[] { 4, 5, 6 };
        using var fixture = new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `FixtureStreams` (`Key` CHAR(72) NOT NULL, `Payload` OBJECT PRIMARY KEY `Key`)")
            .AddStream("FixtureStreams", "a\u007Fb", first)
            .AddStream("FixtureStreams", "a.b", second);
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());
        database.Query(
                MsiTables.FixtureStreams,
                [],
                MsiAnalysisLimits.Default,
                TestContext.Current.CancellationToken)
            .Select(row => row.Fields[0].Identity)
            .Should().Contain("a\u007Fb");

        using var stream = database.OpenStream(
            MsiTables.FixtureStreams,
            [new MsiRecordValue(
                MsiValueKind.String,
                null,
                new MsiTextResult("a\u007Fb", false, false, 3),
                null,
                Identity: "a\u007Fb")],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        using var sink = new MemoryStream();
        stream.CopyTo(sink);
        sink.ToArray().Should().Equal(first);
    }

    [Fact]
    public void Query_derived_raw_key_selects_the_exact_stream()
    {
        using var fixture = CreateFixture();
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());
        var key = database.Query(
                MsiTables.FixtureStreams,
                [],
                MsiAnalysisLimits.Default,
                TestContext.Current.CancellationToken)
            .Single().Fields[0];

        using var stream = database.OpenStream(
            MsiTables.FixtureStreams,
            [key],
            new ExtractionBudget(),
            TestContext.Current.CancellationToken);

        stream.Length.Should().Be(70_001);
    }

    [Fact]
    public void Cloned_table_definition_is_rejected_before_native_query()
    {
        using var fixture = CreateFixture();
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());
        var clone = MsiTables.FixtureValues with { };

        var action = () => database.Query(
            clone,
            [],
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken).ToArray();

        action.Should().Throw<ArgumentException>().WithParameterName("definition");
    }

    [Fact]
    public void Summary_filetime_has_deterministic_utc_representation()
    {
        var timestamp = new DateTimeOffset(2025, 3, 4, 5, 6, 7, TimeSpan.Zero);
        using var fixture = CreateFixture().SetSummary(12, timestamp);
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());

        var property = database.ReadSummary(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken)
            .Single(item => item.PropertyId == 12);

        property.IsComplete.Should().BeTrue();
        property.Value.Kind.ToString().Should().Be("FileTime");
        var timestampProperty = property.Value.GetType().GetProperty("Timestamp");
        timestampProperty.Should().NotBeNull();
        timestampProperty!.GetValue(property.Value).Should().Be(timestamp);
    }

    [Fact]
    public void Summary_edit_time_has_deterministic_duration_representation()
    {
        var duration = TimeSpan.FromMinutes(17);
        using var fixture = CreateFixture().SetSummary(10, duration);
        using var database = MsiDatabase.OpenReadOnly(fixture.Commit());

        var property = database.ReadSummary(
            MsiAnalysisLimits.Default,
            TestContext.Current.CancellationToken)
            .Single(item => item.PropertyId == 10);

        property.IsComplete.Should().BeTrue();
        property.Value.Kind.Should().Be(MsiValueKind.FileTime);
        property.Value.Duration.Should().Be(duration);
        property.Value.Timestamp.Should().BeNull();
    }

    [Fact]
    public void Mapper_failure_does_not_leave_native_handles_open()
    {
        using var fixture = CreateFixture();
        var path = fixture.Commit();
        using (var database = MsiDatabase.OpenReadOnly(path))
        {
            var action = () => database.Query<MsiRow>(
                    MsiTables.FixtureValues,
                    [],
                    MsiAnalysisLimits.Default,
                    _ => throw new FormatException("injected mapper failure"),
                    TestContext.Current.CancellationToken)
                .ToArray();
            action.Should().Throw<FormatException>().WithMessage("injected mapper failure");
        }

        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
        exclusive.Length.Should().BeGreaterThan(0);
    }

    private static MsiFixtureBuilder CreateFixture(string? text = null) =>
        new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `FixtureValues` (`Key` CHAR(72) NOT NULL, `Optional` CHAR(0), " +
                "`Count` SHORT, `Text` CHAR(0) PRIMARY KEY `Key`)")
            .AddTable(
                "CREATE TABLE `FixtureStreams` (`Key` CHAR(72) NOT NULL, `Payload` OBJECT PRIMARY KEY `Key`)")
            .Insert(
                "INSERT INTO `FixtureValues` (`Key`, `Optional`, `Count`, `Text`) VALUES (?, ?, ?, ?)",
                "alpha",
                null,
                42,
                text ?? "benign value")
            .AddStream(
                "FixtureStreams",
                "payload",
                Enumerable.Range(0, 70_001).Select(i => (byte)(i % 251)).ToArray())
            .SetSummary(2, "Benign Fixture")
            .SetSummary(14, 7);

    private static MsiRecordValue CompleteKey(string identity) => new(
        MsiValueKind.String,
        null,
        MsiTextPolicy.Sanitize(identity, MsiAnalysisLimits.Default.MaxTextScalars),
        null,
        Identity: identity);

    private sealed class RecordingMsiNativeApi : IMsiNativeApi
    {
        private int summaryPropertyTwoCalls;
        private int keyCalls;
        private int successfulFetches;

        internal uint OpenViewStatus { get; init; }
        internal uint OpenStatus { get; init; }
        internal uint SummaryStatus { get; init; }
        internal uint FetchStatus { get; init; } = 259;
        internal nint FetchRecord { get; init; }
        internal bool ChangeSummaryTypeOnRead { get; init; }
        internal int RowsBeforeNoMore { get; init; }
        internal uint FieldCount { get; init; } = 4;
        internal string ActualKey { get; init; } = string.Empty;
        internal bool ChangeKeyOnRead { get; init; }
        internal byte[] StreamContent { get; init; } = [];
        internal uint StreamStatus { get; init; }
        internal bool OversizedStreamLength { get; init; }
        internal long? EditDurationTicks { get; init; }
        internal CancellationTokenSource? CancelAfterFirstStreamRead { get; init; }
        internal int FetchCalls { get; private set; }
        internal int StreamReadCalls { get; private set; }
        internal List<string> Events { get; } = [];

        public uint OpenDatabaseReadOnly(string path, out nint database)
        {
            database = 11;
            Events.Add($"open:{path}:11");
            return OpenStatus;
        }

        public uint OpenView(nint database, string query, out nint view)
        {
            Events.Add($"open-view:{database}:22:{query}");
            view = 22;
            return OpenViewStatus;
        }

        public uint ExecuteView(nint view, nint record)
        {
            Events.Add($"execute:{view}:{record}");
            return 0;
        }

        public uint FetchView(nint view, out nint record)
        {
            FetchCalls++;
            if (RowsBeforeNoMore > 0)
            {
                if (successfulFetches++ < RowsBeforeNoMore)
                {
                    record = 44;
                    Events.Add($"fetch:{view}:44");
                    return 0;
                }

                record = 0;
                return 259;
            }

            Events.Add($"fetch:{view}:{FetchRecord}");
            record = FetchRecord;
            return FetchStatus;
        }

        public uint CloseView(nint view)
        {
            Events.Add($"close-view:{view}");
            return 0;
        }

        public uint GetFieldCount(nint record) => FieldCount;

        public bool IsNull(nint record, uint field) => false;

        public int GetInteger(nint record, uint field) => 0;

        public uint GetString(nint record, uint field, char[] value, ref uint length)
        {
            keyCalls++;
            if ((keyCalls & 1) == 1)
            {
                length = checked((uint)ActualKey.Length);
                return 234;
            }

            ActualKey.AsSpan().CopyTo(value);
            length = ChangeKeyOnRead
                ? checked((uint)ActualKey.Length + 1)
                : checked((uint)ActualKey.Length);
            if (ChangeKeyOnRead) return 234;
            return 0;
        }

        public uint ReadStream(nint record, uint field, byte[] buffer, ref uint length)
        {
            StreamReadCalls++;
            if (StreamStatus != 0) return StreamStatus;
            if (OversizedStreamLength)
            {
                length = checked((uint)buffer.Length + 1);
                return 0;
            }
            if (StreamReadCalls == 1 && StreamContent.Length > 0)
            {
                StreamContent.CopyTo(buffer, 0);
                length = checked((uint)StreamContent.Length);
                CancelAfterFirstStreamRead?.Cancel();
                return 0;
            }

            length = 0;
            return 0;
        }

        public uint GetSummary(nint database, out nint summary)
        {
            Events.Add($"open-summary:{database}:33");
            summary = 33;
            return SummaryStatus;
        }

        public uint GetSummaryProperty(
            nint summary,
            uint propertyId,
            out uint dataType,
            out int integerValue,
            out MsiNativeFileTime fileTime,
            char[] value,
            ref uint length)
        {
            integerValue = 0;
            fileTime = default;
            if (propertyId == 10 && EditDurationTicks is { } duration)
            {
                dataType = 64;
                fileTime.Low = unchecked((uint)duration);
                fileTime.High = unchecked((uint)(duration >> 32));
                length = 0;
                return 0;
            }
            if (propertyId != 2 || !ChangeSummaryTypeOnRead)
            {
                dataType = 0;
                length = 0;
                return 0;
            }

            summaryPropertyTwoCalls++;
            if (summaryPropertyTwoCalls == 1)
            {
                dataType = 30;
                length = 4;
                return 234;
            }

            dataType = 3;
            integerValue = 7;
            "text".AsSpan().CopyTo(value);
            length = 4;
            return 0;
        }

        public uint CloseHandle(nint handle)
        {
            Events.Add($"close:{handle}");
            return 0;
        }
    }
}
