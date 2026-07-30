using System.Text;
using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.Tests.Msi;

public sealed class MsiDatabaseTests
{
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
        streamRow.Fields[1].StreamLength.Should().Be(70_001);
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
        uint Reader(StringBuilder? buffer, ref uint length)
        {
            call++;
            if (buffer is null)
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
    public void Short_native_string_is_incomplete()
    {
        uint Reader(StringBuilder? buffer, ref uint length)
        {
            if (buffer is null)
            {
                length = 8;
                return 234;
            }

            buffer.Append("tiny");
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
            [new MsiRecordValue(MsiValueKind.String, null, MsiTextPolicy.Sanitize("payload", 32), null)],
            budget,
            TestContext.Current.CancellationToken);
        using var sink = new MemoryStream();
        stream.CopyTo(sink);

        sink.ToArray().Should().Equal(Enumerable.Range(0, 70_001).Select(i => (byte)(i % 251)));
        budget.TotalExpandedBytes.Should().Be(70_001);
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
}
