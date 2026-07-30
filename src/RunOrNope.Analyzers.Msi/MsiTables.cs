using System.Collections.Immutable;

namespace RunOrNope.Analyzers.Msi;

internal enum MsiValueKind
{
    Null,
    Integer,
    String,
    Stream,
}

internal sealed record MsiRecordValue(
    MsiValueKind Kind,
    int? Integer,
    MsiTextResult? Text,
    long? StreamLength,
    bool IsComplete = true,
    string? IncompleteReason = null);

internal sealed record MsiRow(ImmutableArray<MsiRecordValue> Fields);

internal enum MsiColumnType
{
    Integer,
    String,
    Stream,
}

internal sealed record MsiColumnDefinition(
    string Name,
    MsiColumnType Type,
    bool IsNullable);

internal sealed record MsiSummaryProperty(
    int PropertyId,
    MsiRecordValue Value,
    bool IsComplete,
    string? IncompleteReason);

internal sealed record MsiTableDefinition(
    string Name,
    string Query,
    ImmutableArray<MsiColumnDefinition> Columns);

internal static class MsiTables
{
    internal static MsiTableDefinition Tables { get; } = new(
        "_Tables",
        "SELECT `Name` FROM `_Tables`",
        [new("Name", MsiColumnType.String, false)]);

    internal static MsiTableDefinition Property { get; } = new(
        "Property",
        "SELECT `Property`, `Value` FROM `Property`",
        [
            new("Property", MsiColumnType.String, false),
            new("Value", MsiColumnType.String, true),
        ]);

    internal static MsiTableDefinition FixtureValues { get; } = new(
        "FixtureValues",
        "SELECT `Key`, `Optional`, `Count`, `Text` FROM `FixtureValues`",
        [
            new("Key", MsiColumnType.String, false),
            new("Optional", MsiColumnType.String, true),
            new("Count", MsiColumnType.Integer, true),
            new("Text", MsiColumnType.String, true),
        ]);

    internal static MsiTableDefinition FixtureStreams { get; } = new(
        "FixtureStreams",
        "SELECT `Key`, `Payload` FROM `FixtureStreams`",
        [
            new("Key", MsiColumnType.String, false),
            new("Payload", MsiColumnType.Stream, false),
        ]);
}
