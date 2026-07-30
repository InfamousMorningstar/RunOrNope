using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.SecurityTests.Msi;

public sealed class MsiNativeSurfaceTests
{
    private static readonly string[] AllowedImports =
    [
        "MsiCloseHandle",
        "MsiDatabaseOpenViewW",
        "MsiGetSummaryInformationW",
        "MsiOpenDatabaseW",
        "MsiRecordDataSize",
        "MsiRecordGetFieldCount",
        "MsiRecordGetInteger",
        "MsiRecordGetStringW",
        "MsiRecordIsNull",
        "MsiRecordReadStream",
        "MsiSummaryInfoGetPropertyW",
        "MsiViewClose",
        "MsiViewExecute",
        "MsiViewFetch",
    ];

    private static readonly IReadOnlyDictionary<string, string> ExpectedSignatures =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["MsiCloseHandle"] = "UInt32(IntPtr)",
            ["MsiDatabaseOpenViewW"] =
                "UInt32(SafeMsiDatabaseHandle,String,SafeMsiViewHandle&)",
            ["MsiGetSummaryInformationW"] =
                "UInt32(SafeMsiDatabaseHandle,String,UInt32,SafeMsiSummaryHandle&)",
            ["MsiOpenDatabaseW"] =
                "UInt32(String,IntPtr,SafeMsiDatabaseHandle&)",
            ["MsiRecordDataSize"] = "UInt32(SafeMsiRecordHandle,UInt32)",
            ["MsiRecordGetFieldCount"] = "UInt32(SafeMsiRecordHandle)",
            ["MsiRecordGetInteger"] = "Int32(SafeMsiRecordHandle,UInt32)",
            ["MsiRecordGetStringW"] =
                "UInt32(SafeMsiRecordHandle,UInt32,StringBuilder,UInt32&)",
            ["MsiRecordIsNull"] = "Boolean(SafeMsiRecordHandle,UInt32)",
            ["MsiRecordReadStream"] =
                "UInt32(SafeMsiRecordHandle,UInt32,Byte[],UInt32&)",
            ["MsiSummaryInfoGetPropertyW"] =
                "UInt32(SafeMsiSummaryHandle,UInt32,UInt32&,Int32&,IntPtr,StringBuilder,UInt32&)",
            ["MsiViewClose"] = "UInt32(IntPtr)",
            ["MsiViewExecute"] = "UInt32(SafeMsiViewHandle,IntPtr)",
            ["MsiViewFetch"] = "UInt32(SafeMsiViewHandle,SafeMsiRecordHandle&)",
        };

    [Fact]
    public void Production_native_surface_is_exactly_the_read_only_msi_allowlist()
    {
        using var stream = File.OpenRead(typeof(MsiDatabase).Assembly.Location);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        var modules = Enumerable.Range(1, metadata.GetTableRowCount(TableIndex.ModuleRef))
            .Select(row => MetadataTokens.ModuleReferenceHandle(row))
            .Select(handle => metadata.GetString(metadata.GetModuleReference(handle).Name))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var imports = metadata.MethodDefinitions
            .Select(handle => metadata.GetMethodDefinition(handle))
            .Where(method => (method.Attributes & MethodAttributes.PinvokeImpl) != 0)
            .Select(method => metadata.GetString(method.GetImport().Name))
            .Order(StringComparer.Ordinal)
            .ToArray();

        modules.Should().Equal("msi.dll");
        imports.Should().Equal(AllowedImports.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Every_import_uses_unicode_winapi_and_expected_parameter_widths()
    {
        var imports = typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Static | BindingFlags.NonPublic))
            .Select(method => (Method: method, Import: method.GetCustomAttribute<DllImportAttribute>()))
            .Where(pair => pair.Import is not null)
            .ToArray();

        imports.Select(pair => pair.Method.Name).Order(StringComparer.Ordinal)
            .Should().Equal(AllowedImports.Order(StringComparer.Ordinal));
        imports.Should().OnlyContain(pair =>
            pair.Import!.Value == "msi.dll"
            && pair.Import.CharSet == CharSet.Unicode
            && pair.Import.CallingConvention == CallingConvention.Winapi);
        imports.ToDictionary(pair => pair.Method.Name, pair => Signature(pair.Method))
            .Should().BeEquivalentTo(ExpectedSignatures);
    }

    [Fact]
    public void Compiled_il_has_no_indirect_or_dynamic_native_resolution_path()
    {
        using var stream = File.OpenRead(typeof(MsiDatabase).Assembly.Location);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();

        foreach (var methodHandle in metadata.MethodDefinitions)
        {
            var method = metadata.GetMethodDefinition(methodHandle);
            if (method.RelativeVirtualAddress == 0) continue;
            var il = pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes()!;
            Decode(il).Where(instruction => instruction.OpCode == OpCodes.Calli)
                .Should().BeEmpty("calli is forbidden");
        }

        var referencedNames = metadata.TypeReferences
            .Select(handle => metadata.GetString(metadata.GetTypeReference(handle).Name))
            .Concat(metadata.MemberReferences.Select(handle =>
                metadata.GetString(metadata.GetMemberReference(handle).Name)))
            .ToArray();
        referencedNames.Where(name =>
                name == "NativeLibrary"
                || name.StartsWith("GetProcAddress", StringComparison.Ordinal)
                || name.StartsWith("LoadLibrary", StringComparison.Ordinal)
                || name.StartsWith("GetDelegateForFunctionPointer", StringComparison.Ordinal))
            .Should().BeEmpty();
        typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .SelectMany(method => method.GetParameters().Select(parameter => parameter.ParameterType)
                .Append(method.ReturnType))
            .Where(ContainsFunctionPointer)
            .Should().BeEmpty();
    }

    [Fact]
    public void Open_database_native_call_is_compiler_adjacent_to_null_persistence()
    {
        var callToken = typeof(MsiDatabase).GetMethod(
            "MsiOpenDatabaseW",
            BindingFlags.Static | BindingFlags.NonPublic)!.MetadataToken;
        var calls = typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .Where(method => method.GetMethodBody() is not null)
            .SelectMany(method => Decode(method.GetMethodBody()!.GetILAsByteArray()!)
                .Select((instruction, index) => (method, instruction, index)))
            .Where(item => item.instruction.OpCode == OpCodes.Call
                && item.instruction.Token == callToken)
            .ToArray();

        calls.Should().ContainSingle();
        calls[0].method.Name.Should().Be("OpenNativeReadOnly");
        var instructions = Decode(calls[0].method.GetMethodBody()!.GetILAsByteArray()!);
        instructions.Skip(calls[0].index - 4).Take(4).Select(instruction => instruction.OpCode)
            .Should().Equal(
                [OpCodes.Ldarg_0, OpCodes.Ldc_I4_0, OpCodes.Conv_I, OpCodes.Ldloca_S],
                "the native call arguments must be path, null persistence, and the output handle");
    }

    [Fact]
    public void Safe_handles_close_exactly_their_owned_resources()
    {
        var closeHandleToken = typeof(MsiDatabase).GetMethod(
            "MsiCloseHandle",
            BindingFlags.Static | BindingFlags.NonPublic)!.MetadataToken;
        var closeViewToken = typeof(MsiDatabase).GetMethod(
            "MsiViewClose",
            BindingFlags.Static | BindingFlags.NonPublic)!.MetadataToken;
        var handleTypes = typeof(MsiDatabase).GetNestedTypes(BindingFlags.NonPublic)
            .Where(type => type.Name.StartsWith("SafeMsi", StringComparison.Ordinal))
            .OrderBy(type => type.Name, StringComparer.Ordinal)
            .ToArray();

        handleTypes.Select(type => type.Name).Should().Equal(
            "SafeMsiDatabaseHandle",
            "SafeMsiRecordHandle",
            "SafeMsiSummaryHandle",
            "SafeMsiViewHandle");
        handleTypes.Should().OnlyContain(
            type => type.BaseType!.Name == "SafeHandleZeroOrMinusOneIsInvalid");

        foreach (var handleType in handleTypes)
        {
            var release = handleType.GetMethod(
                "ReleaseHandle",
                BindingFlags.Instance | BindingFlags.NonPublic)!;
            var nativeCalls = Decode(release.GetMethodBody()!.GetILAsByteArray()!)
                .Where(instruction => instruction.OpCode == OpCodes.Call)
                .Select(instruction => instruction.Token)
                .Where(token => token == closeViewToken || token == closeHandleToken)
                .ToArray();

            if (handleType.Name == "SafeMsiViewHandle")
            {
                nativeCalls.Should().Equal(closeViewToken, closeHandleToken);
            }
            else
            {
                nativeCalls.Should().Equal(closeHandleToken);
            }
        }
    }

    private static string Signature(MethodInfo method) =>
        $"{method.ReturnType.Name}({string.Join(",", method.GetParameters().Select(parameter => parameter.ParameterType.Name))})";

    private static bool ContainsFunctionPointer(Type type) =>
        type.IsFunctionPointer
        || (type.HasElementType && type.GetElementType() is { } element
            && ContainsFunctionPointer(element));

    private static List<IlInstruction> Decode(byte[] il)
    {
        var oneByte = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(field => (OpCode)field.GetValue(null)!)
            .Where(opcode => opcode.Size == 1)
            .ToDictionary(opcode => unchecked((byte)opcode.Value));
        var twoByte = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(field => (OpCode)field.GetValue(null)!)
            .Where(opcode => opcode.Size == 2)
            .ToDictionary(opcode => unchecked((byte)opcode.Value));
        var instructions = new List<IlInstruction>();
        var offset = 0;
        while (offset < il.Length)
        {
            var instructionOffset = offset;
            var first = il[offset++];
            var opcode = first == 0xfe ? twoByte[il[offset++]] : oneByte[first];
            int? token = null;
            var operandSize = opcode.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI
                    or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI or OperandType.InlineBrTarget or OperandType.InlineField
                    or OperandType.InlineMethod or OperandType.InlineSig
                    or OperandType.InlineString or OperandType.InlineTok
                    or OperandType.InlineType or OperandType.ShortInlineR => 4,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => checked(
                    4 + BitConverter.ToInt32(il, offset) * 4),
                _ => throw new InvalidDataException($"Unknown IL operand type {opcode.OperandType}."),
            };
            if (opcode.OperandType is OperandType.InlineMethod or OperandType.InlineSig)
            {
                token = BitConverter.ToInt32(il, offset);
            }
            instructions.Add(new IlInstruction(instructionOffset, opcode, token));
            offset += operandSize;
        }

        return instructions;
    }

    private sealed record IlInstruction(int Offset, OpCode OpCode, int? Token);
}
