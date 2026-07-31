using System.Collections.Immutable;

namespace RunOrNope.Analyzers.Msi;

internal enum MsiValueKind
{
    Null,
    Integer,
    String,
    Stream,
    FileTime,
}

internal sealed record MsiRecordValue(
    MsiValueKind Kind,
    int? Integer,
    MsiTextResult? Text,
    long? StreamLength,
    bool IsComplete = true,
    string? IncompleteReason = null,
    string? Identity = null,
    DateTimeOffset? Timestamp = null,
    TimeSpan? Duration = null);

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

    internal static MsiTableDefinition Directory { get; } = new(
        "Directory",
        "SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`",
        [
            new("Directory", MsiColumnType.String, false),
            new("Directory_Parent", MsiColumnType.String, true),
            new("DefaultDir", MsiColumnType.String, false),
        ]);

    internal static MsiTableDefinition Component { get; } = new(
        "Component",
        "SELECT `Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath` FROM `Component`",
        [
            new("Component", MsiColumnType.String, false),
            new("ComponentId", MsiColumnType.String, true),
            new("Directory_", MsiColumnType.String, false),
            new("Attributes", MsiColumnType.Integer, false),
            new("Condition", MsiColumnType.String, true),
            new("KeyPath", MsiColumnType.String, true),
        ]);

    internal static MsiTableDefinition Feature { get; } = new(
        "Feature",
        "SELECT `Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, `Attributes` FROM `Feature`",
        [
            new("Feature", MsiColumnType.String, false),
            new("Feature_Parent", MsiColumnType.String, true),
            new("Title", MsiColumnType.String, true),
            new("Description", MsiColumnType.String, true),
            new("Display", MsiColumnType.Integer, true),
            new("Level", MsiColumnType.Integer, false),
            new("Directory_", MsiColumnType.String, true),
            new("Attributes", MsiColumnType.Integer, false),
        ]);

    internal static MsiTableDefinition FeatureComponents { get; } = new(
        "FeatureComponents",
        "SELECT `Feature_`, `Component_` FROM `FeatureComponents`",
        [
            new("Feature_", MsiColumnType.String, false),
            new("Component_", MsiColumnType.String, false),
        ]);

    internal static MsiTableDefinition File { get; } = new(
        "File",
        "SELECT `File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, `Attributes`, `Sequence` FROM `File`",
        [
            new("File", MsiColumnType.String, false),
            new("Component_", MsiColumnType.String, false),
            new("FileName", MsiColumnType.String, false),
            new("FileSize", MsiColumnType.Integer, false),
            new("Version", MsiColumnType.String, true),
            new("Language", MsiColumnType.String, true),
            new("Attributes", MsiColumnType.Integer, true),
            new("Sequence", MsiColumnType.Integer, false),
        ]);

    internal static MsiTableDefinition Media { get; } = new(
        "Media",
        "SELECT `DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source` FROM `Media`",
        [
            new("DiskId", MsiColumnType.Integer, false),
            new("LastSequence", MsiColumnType.Integer, false),
            new("DiskPrompt", MsiColumnType.String, true),
            new("Cabinet", MsiColumnType.String, true),
            new("VolumeLabel", MsiColumnType.String, true),
            new("Source", MsiColumnType.String, true),
        ]);

    internal static MsiTableDefinition MsiFileHash { get; } = new(
        "MsiFileHash",
        "SELECT `File_`, `Options`, `HashPart1`, `HashPart2`, `HashPart3`, `HashPart4` FROM `MsiFileHash`",
        [
            new("File_", MsiColumnType.String, false),
            new("Options", MsiColumnType.Integer, false),
            new("HashPart1", MsiColumnType.Integer, false),
            new("HashPart2", MsiColumnType.Integer, false),
            new("HashPart3", MsiColumnType.Integer, false),
            new("HashPart4", MsiColumnType.Integer, false),
        ]);

    internal static MsiTableDefinition Binary { get; } = new(
        "Binary",
        "SELECT `Name`, `Data` FROM `Binary`",
        [
            new("Name", MsiColumnType.String, false),
            new("Data", MsiColumnType.Stream, false),
        ]);

    internal static MsiTableDefinition Icon { get; } = new(
        "Icon",
        "SELECT `Name`, `Data` FROM `Icon`",
        [
            new("Name", MsiColumnType.String, false),
            new("Data", MsiColumnType.Stream, false),
        ]);

    internal static MsiTableDefinition Streams { get; } = new(
        "_Streams",
        "SELECT `Name`, `Data` FROM `_Streams`",
        [
            new("Name", MsiColumnType.String, false),
            new("Data", MsiColumnType.Stream, false),
        ]);

    internal static MsiTableDefinition Storages { get; } = new(
        "_Storages",
        "SELECT `Name`, `Data` FROM `_Storages`",
        [
            new("Name", MsiColumnType.String, false),
            new("Data", MsiColumnType.Stream, false),
        ]);

    internal static ImmutableArray<MsiTableDefinition> PackageCatalog { get; } =
    [
        Property,
        Directory,
        Component,
        Feature,
        FeatureComponents,
        File,
        Media,
        MsiFileHash,
        Binary,
        Icon,
        Streams,
        Storages,
    ];

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

    internal static bool IsKnown(MsiTableDefinition definition) =>
        ReferenceEquals(definition, Tables)
        || PackageCatalog.Any(item => ReferenceEquals(definition, item))
        || ReferenceEquals(definition, FixtureValues)
        || ReferenceEquals(definition, FixtureStreams);

    internal static MsiTableDefinition? FindPackage(string exactName) =>
        PackageCatalog.FirstOrDefault(definition =>
            string.Equals(definition.Name, exactName, StringComparison.Ordinal));
}
