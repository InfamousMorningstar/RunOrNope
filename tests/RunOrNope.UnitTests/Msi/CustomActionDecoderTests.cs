using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.UnitTests.Msi;

public sealed class CustomActionDecoderTests
{
    [Theory]
    [InlineData(1, CustomActionBaseKind.BinaryDll, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.DllEntryPoint)]
    [InlineData(2, CustomActionBaseKind.BinaryExe, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.CommandLine)]
    [InlineData(5, CustomActionBaseKind.BinaryJScript, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.ScriptFunction)]
    [InlineData(6, CustomActionBaseKind.BinaryVbScript, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.ScriptFunction)]
    [InlineData(17, CustomActionBaseKind.InstalledDll, CustomActionSourceKind.FileTable, CustomActionTargetKind.DllEntryPoint)]
    [InlineData(18, CustomActionBaseKind.InstalledExe, CustomActionSourceKind.FileTable, CustomActionTargetKind.CommandLine)]
    [InlineData(19, CustomActionBaseKind.ErrorMessage, CustomActionSourceKind.None, CustomActionTargetKind.FormattedText)]
    [InlineData(21, CustomActionBaseKind.InstalledJScript, CustomActionSourceKind.FileTable, CustomActionTargetKind.ScriptFunction)]
    [InlineData(22, CustomActionBaseKind.InstalledVbScript, CustomActionSourceKind.FileTable, CustomActionTargetKind.ScriptFunction)]
    [InlineData(34, CustomActionBaseKind.DirectoryExe, CustomActionSourceKind.DirectoryTable, CustomActionTargetKind.ExecutablePathAndArguments)]
    [InlineData(35, CustomActionBaseKind.DirectorySet, CustomActionSourceKind.DirectoryTable, CustomActionTargetKind.FormattedText)]
    [InlineData(37, CustomActionBaseKind.InlineJScript, CustomActionSourceKind.None, CustomActionTargetKind.ScriptText)]
    [InlineData(38, CustomActionBaseKind.InlineVbScript, CustomActionSourceKind.None, CustomActionTargetKind.ScriptText)]
    [InlineData(50, CustomActionBaseKind.PropertyExe, CustomActionSourceKind.Property, CustomActionTargetKind.CommandLine)]
    [InlineData(51, CustomActionBaseKind.PropertySet, CustomActionSourceKind.Property, CustomActionTargetKind.FormattedText)]
    [InlineData(53, CustomActionBaseKind.PropertyJScript, CustomActionSourceKind.Property, CustomActionTargetKind.ScriptFunction)]
    [InlineData(54, CustomActionBaseKind.PropertyVbScript, CustomActionSourceKind.Property, CustomActionTargetKind.ScriptFunction)]
    public void Decode_classifies_each_documented_literal_base_type(
        int type,
        CustomActionBaseKind expectedBaseKind,
        CustomActionSourceKind expectedSourceKind,
        CustomActionTargetKind expectedTargetKind)
    {
        var decoded = CustomActionDecoder.Decode(type);

        decoded.BaseKind.Should().Be(expectedBaseKind);
        decoded.SourceKind.Should().Be(expectedSourceKind);
        decoded.TargetKind.Should().Be(expectedTargetKind);
        decoded.UnknownBits.Should().Be(0);
    }

    [Theory]
    [InlineData(0x40, nameof(DecodedCustomAction.ContinueOnError))]
    [InlineData(0x80, nameof(DecodedCustomAction.Asynchronous))]
    [InlineData(0x100, nameof(DecodedCustomAction.IsRollback))]
    [InlineData(0x200, nameof(DecodedCustomAction.IsCommit))]
    [InlineData(0x400, nameof(DecodedCustomAction.IsDeferred))]
    [InlineData(0x800, nameof(DecodedCustomAction.NoImpersonation))]
    [InlineData(0x1000, nameof(DecodedCustomAction.Is64BitScript))]
    [InlineData(0x2000, nameof(DecodedCustomAction.HideTarget))]
    [InlineData(0x4000, nameof(DecodedCustomAction.IsTerminalServerAware))]
    [InlineData(0x8000, nameof(DecodedCustomAction.PatchUninstall))]
    public void Decode_recognizes_each_documented_flag_independently(int flag, string enabledProperty)
    {
        var decoded = CustomActionDecoder.Decode(2 | flag);

        IsEnabled(decoded, enabledProperty).Should().BeTrue();
        decoded.UnknownBits.Should().Be(0);
    }

    [Fact]
    public void Decode_retains_unknown_high_bits_without_changing_the_low_six_bit_base_kind()
    {
        var decoded = CustomActionDecoder.Decode(2 | 0x400 | 0x800 | 0x10000000);

        decoded.BaseKind.Should().Be(CustomActionBaseKind.BinaryExe);
        decoded.IsDeferred.Should().BeTrue();
        decoded.NoImpersonation.Should().BeTrue();
        decoded.UnknownBits.Should().Be(0x10000000);
    }

    private static bool IsEnabled(DecodedCustomAction decoded, string propertyName) => propertyName switch
    {
        nameof(DecodedCustomAction.ContinueOnError) => decoded.ContinueOnError,
        nameof(DecodedCustomAction.Asynchronous) => decoded.Asynchronous,
        nameof(DecodedCustomAction.IsRollback) => decoded.IsRollback,
        nameof(DecodedCustomAction.IsCommit) => decoded.IsCommit,
        nameof(DecodedCustomAction.IsDeferred) => decoded.IsDeferred,
        nameof(DecodedCustomAction.NoImpersonation) => decoded.NoImpersonation,
        nameof(DecodedCustomAction.Is64BitScript) => decoded.Is64BitScript,
        nameof(DecodedCustomAction.HideTarget) => decoded.HideTarget,
        nameof(DecodedCustomAction.IsTerminalServerAware) => decoded.IsTerminalServerAware,
        nameof(DecodedCustomAction.PatchUninstall) => decoded.PatchUninstall,
        _ => throw new ArgumentOutOfRangeException(nameof(propertyName)),
    };
}
