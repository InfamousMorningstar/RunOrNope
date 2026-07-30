using System.Reflection;
using System.Collections.Immutable;
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
                "UInt32(IntPtr,String,IntPtr&)",
            ["MsiGetSummaryInformationW"] =
                "UInt32(IntPtr,String,UInt32,IntPtr&)",
            ["MsiOpenDatabaseW"] =
                "UInt32(String,IntPtr,IntPtr&)",
            ["MsiRecordGetFieldCount"] = "UInt32(IntPtr)",
            ["MsiRecordGetInteger"] = "Int32(IntPtr,UInt32)",
            ["MsiRecordGetStringW"] =
                "UInt32(IntPtr,UInt32,Char[],UInt32&)",
            ["MsiRecordIsNull"] = "Boolean(IntPtr,UInt32)",
            ["MsiRecordReadStream"] =
                "UInt32(IntPtr,UInt32,Byte[],UInt32&)",
            ["MsiSummaryInfoGetPropertyW"] =
                "UInt32(IntPtr,UInt32,UInt32&,Int32&,MsiNativeFileTime&,Char[],UInt32&)",
            ["MsiViewClose"] = "UInt32(IntPtr)",
            ["MsiViewExecute"] = "UInt32(IntPtr,IntPtr)",
            ["MsiViewFetch"] = "UInt32(IntPtr,IntPtr&)",
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
            && pair.Import.CallingConvention == CallingConvention.Winapi
            && pair.Import.PreserveSig
            && pair.Import.ExactSpelling);
        imports.ToDictionary(pair => pair.Method.Name, pair => Signature(pair.Method))
            .Should().BeEquivalentTo(ExpectedSignatures);
        imports.SelectMany(pair => pair.Method.GetParameters())
            .Where(parameter => parameter.ParameterType == typeof(string))
            .Select(parameter => parameter.GetCustomAttribute<MarshalAsAttribute>()?.Value)
            .Should().OnlyContain(value => value == UnmanagedType.LPWStr);
        imports.SelectMany(pair => pair.Method.GetParameters())
            .Where(parameter => parameter.ParameterType.IsArray)
            .Select(parameter => parameter.GetCustomAttribute<MarshalAsAttribute>()?.Value)
            .Should().OnlyContain(value => value == UnmanagedType.LPArray);
        imports.Should().OnlyContain(pair =>
            (pair.Method.MethodImplementationFlags & MethodImplAttributes.PreserveSig) != 0);
        var boolReturn = imports.Single(pair => pair.Method.Name == "MsiRecordIsNull")
            .Method.ReturnParameter.GetCustomAttribute<MarshalAsAttribute>();
        boolReturn.Should().NotBeNull();
        boolReturn!.Value.Should().Be(UnmanagedType.Bool);
        imports.SelectMany(pair => pair.Method.GetParameters())
            .Select(parameter => parameter.GetCustomAttribute<MarshalAsAttribute>())
            .Where(attribute => attribute is not null)
            .Select(attribute =>
                attribute!.MarshalType == null
                && attribute.MarshalTypeRef == null
                && attribute.MarshalCookie == null)
            .Should().OnlyContain(value => value);
        AssertArrayMarshalling(
            imports.Single(pair => pair.Method.Name == "MsiRecordGetStringW").Method,
            parameterIndex: 2,
            UnmanagedType.U2,
            sizeParameterIndex: 3);
        AssertArrayMarshalling(
            imports.Single(pair => pair.Method.Name == "MsiRecordReadStream").Method,
            parameterIndex: 2,
            UnmanagedType.U1,
            sizeParameterIndex: 3);
        AssertArrayMarshalling(
            imports.Single(pair => pair.Method.Name == "MsiSummaryInfoGetPropertyW").Method,
            parameterIndex: 5,
            UnmanagedType.U2,
            sizeParameterIndex: 6);
    }

    [Fact]
    public void Compiled_il_has_no_indirect_or_dynamic_native_resolution_path()
    {
        using var stream = File.OpenRead(typeof(MsiDatabase).Assembly.Location);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();
        var importTokens = metadata.MethodDefinitions
            .Where(handle =>
                (metadata.GetMethodDefinition(handle).Attributes & MethodAttributes.PinvokeImpl) != 0)
            .Select(handle => MetadataTokens.GetToken(handle))
            .ToHashSet();

        foreach (var methodHandle in metadata.MethodDefinitions)
        {
            var method = metadata.GetMethodDefinition(methodHandle);
            if (method.RelativeVirtualAddress == 0) continue;
            var il = pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes()!;
            var instructions = Decode(il);
            instructions.Where(instruction => instruction.OpCode == OpCodes.Calli)
                .Should().BeEmpty("calli is forbidden");
            instructions.Where(instruction =>
                    (instruction.OpCode == OpCodes.Ldftn
                        || instruction.OpCode == OpCodes.Ldvirtftn
                        || instruction.OpCode == OpCodes.Jmp)
                    && instruction.Token is { } token
                    && importTokens.Contains(token))
                .Should().BeEmpty("native imports must not be reachable through indirect IL");
            instructions.Where(instruction =>
                    instruction.Token is { } token
                    && importTokens.Contains(token))
                .Should().OnlyContain(
                    instruction => instruction.OpCode == OpCodes.Call,
                    "every compiled reference to a native import must be a direct call");
        }

        var referencedNames = metadata.TypeReferences
            .Select(handle => metadata.GetString(metadata.GetTypeReference(handle).Name))
            .ToArray();
        referencedNames.Where(name =>
                name == "NativeLibrary"
                || name.StartsWith("GetProcAddress", StringComparison.Ordinal)
                || name.StartsWith("LoadLibrary", StringComparison.Ordinal)
                || name.StartsWith("GetDelegateForFunctionPointer", StringComparison.Ordinal))
            .Should().BeEmpty();
        metadata.MemberReferences
            .Select(handle => QualifiedMemberName(metadata, handle))
            .Where(name =>
                name is "System.Reflection.MethodBase.Invoke"
                    or "System.Reflection.MethodInfo.CreateDelegate"
                    or "System.Delegate.CreateDelegate")
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
    public void Every_metadata_signature_is_free_of_unmanaged_function_pointers()
    {
        using var stream = File.OpenRead(typeof(MsiDatabase).Assembly.Location);
        using var pe = new PEReader(stream);
        var metadata = pe.GetMetadataReader();
        var provider = new FunctionPointerSignatureProvider();

        metadata.MethodDefinitions.Select(handle =>
                metadata.GetMethodDefinition(handle).DecodeSignature(provider, null))
            .Where(signature =>
                signature.ReturnType || signature.ParameterTypes.Any(value => value))
            .Should().BeEmpty();
        metadata.FieldDefinitions.Select(handle =>
                metadata.GetFieldDefinition(handle).DecodeSignature(provider, null))
            .Where(value => value)
            .Should().BeEmpty();
        Enumerable.Range(1, metadata.GetTableRowCount(TableIndex.Property))
            .Select(row => MetadataTokens.PropertyDefinitionHandle(row))
            .Select(handle =>
                metadata.GetPropertyDefinition(handle).DecodeSignature(provider, null))
            .Where(signature =>
                signature.ReturnType || signature.ParameterTypes.Any(value => value))
            .Should().BeEmpty();

        foreach (var row in Enumerable.Range(
            1, metadata.GetTableRowCount(TableIndex.StandAloneSig)))
        {
            var signature = metadata.GetStandaloneSignature(
                MetadataTokens.StandaloneSignatureHandle(row));
            var bytes = metadata.GetBlobBytes(signature.Signature);
            var reader = metadata.GetBlobReader(signature.Signature);
            var decoder = new SignatureDecoder<bool, object?>(provider, metadata, null);
            if ((bytes[0] & 0x0f) == 0x07)
            {
                decoder.DecodeLocalSignature(ref reader).Where(value => value)
                    .Should().BeEmpty();
            }
            else
            {
                var method = decoder.DecodeMethodSignature(ref reader);
                (method.ReturnType || method.ParameterTypes.Any(value => value))
                    .Should().BeFalse();
            }
        }
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
        calls[0].method.Name.Should().Be("OpenDatabaseReadOnly");
        var instructions = Decode(calls[0].method.GetMethodBody()!.GetILAsByteArray()!);
        instructions.Skip(calls[0].index - 4).Take(4).Select(instruction => instruction.OpCode)
            .Should().Equal(
                [OpCodes.Ldarg_1, OpCodes.Ldc_I4_0, OpCodes.Conv_I, OpCodes.Ldarg_2],
                "the native call arguments must be path, null persistence, and the output handle");
    }

    [Fact]
    public void Safe_handles_close_exactly_their_owned_resources()
    {
        var closeHandleToken = typeof(IMsiNativeApi).GetMethod(
            nameof(IMsiNativeApi.CloseHandle))!.MetadataToken;
        var closeViewToken = typeof(IMsiNativeApi).GetMethod(
            nameof(IMsiNativeApi.CloseView))!.MetadataToken;
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
        handleTypes.Should().OnlyContain(type =>
            type.GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
                .Count(field => field.FieldType == typeof(IMsiNativeApi)) == 1);

        foreach (var handleType in handleTypes)
        {
            var release = handleType.GetMethod(
                "ReleaseHandle",
                BindingFlags.Instance | BindingFlags.NonPublic)!;
            var nativeCalls = Decode(release.GetMethodBody()!.GetILAsByteArray()!)
                .Where(instruction =>
                    instruction.OpCode == OpCodes.Call
                    || instruction.OpCode == OpCodes.Callvirt)
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

    private static string QualifiedMemberName(MetadataReader metadata, MemberReferenceHandle handle)
    {
        var member = metadata.GetMemberReference(handle);
        if (member.Parent.Kind != HandleKind.TypeReference)
        {
            return metadata.GetString(member.Name);
        }
        var parent = metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
        return $"{metadata.GetString(parent.Namespace)}.{metadata.GetString(parent.Name)}.{metadata.GetString(member.Name)}";
    }

    private static bool ContainsFunctionPointer(Type type) =>
        type.IsFunctionPointer
        || (type.HasElementType && type.GetElementType() is { } element
            && ContainsFunctionPointer(element));

    private static void AssertArrayMarshalling(
        MethodInfo method,
        int parameterIndex,
        UnmanagedType elementType,
        int sizeParameterIndex)
    {
        var attribute = method.GetParameters()[parameterIndex]
            .GetCustomAttribute<MarshalAsAttribute>();
        attribute.Should().NotBeNull();
        attribute!.Value.Should().Be(UnmanagedType.LPArray);
        attribute.ArraySubType.Should().Be(elementType);
        attribute.SizeParamIndex.Should().Be((short)sizeParameterIndex);
    }

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

    private sealed class FunctionPointerSignatureProvider
        : ISignatureTypeProvider<bool, object?>
    {
        public bool GetArrayType(bool elementType, ArrayShape shape) => elementType;
        public bool GetByReferenceType(bool elementType) => elementType;
        public bool GetFunctionPointerType(MethodSignature<bool> signature) => true;
        public bool GetGenericInstantiation(
            bool genericType,
            ImmutableArray<bool> typeArguments) =>
            genericType || typeArguments.Any(value => value);
        public bool GetGenericMethodParameter(object? genericContext, int index) => false;
        public bool GetGenericTypeParameter(object? genericContext, int index) => false;
        public bool GetModifiedType(bool modifier, bool unmodifiedType, bool isRequired) =>
            modifier || unmodifiedType;
        public bool GetPinnedType(bool elementType) => elementType;
        public bool GetPointerType(bool elementType) => elementType;
        public bool GetPrimitiveType(PrimitiveTypeCode typeCode) => false;
        public bool GetSZArrayType(bool elementType) => elementType;
        public bool GetTypeFromDefinition(
            MetadataReader reader,
            TypeDefinitionHandle handle,
            byte rawTypeKind) => false;
        public bool GetTypeFromReference(
            MetadataReader reader,
            TypeReferenceHandle handle,
            byte rawTypeKind) => false;
        public bool GetTypeFromSpecification(
            MetadataReader reader,
            object? genericContext,
            TypeSpecificationHandle handle,
            byte rawTypeKind) =>
            reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
    }
}
