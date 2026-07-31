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

    private static readonly Dictionary<string, NativeMethodContract> ExpectedContracts =
        new Dictionary<string, NativeMethodContract>(StringComparer.Ordinal)
        {
            ["MsiCloseHandle"] = Contract(typeof(uint), Parameter(typeof(uint))),
            ["MsiDatabaseOpenViewW"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(string), marshal: Marshall(UnmanagedType.LPWStr)),
                Parameter(typeof(uint).MakeByRefType(), isOut: true)),
            ["MsiGetSummaryInformationW"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(string), marshal: Marshall(UnmanagedType.LPWStr)),
                Parameter(typeof(uint)),
                Parameter(typeof(uint).MakeByRefType(), isOut: true)),
            ["MsiOpenDatabaseW"] = Contract(
                typeof(uint),
                Parameter(typeof(string), marshal: Marshall(UnmanagedType.LPWStr)),
                Parameter(typeof(nint)),
                Parameter(typeof(uint).MakeByRefType(), isOut: true)),
            ["MsiRecordGetFieldCount"] = Contract(
                typeof(uint),
                Parameter(typeof(uint))),
            ["MsiRecordGetInteger"] = Contract(
                typeof(int),
                Parameter(typeof(uint)),
                Parameter(typeof(uint))),
            ["MsiRecordGetStringW"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(uint)),
                Parameter(
                    typeof(char[]),
                    isOut: true,
                    marshal: Marshall(
                        UnmanagedType.LPArray,
                        UnmanagedType.U2,
                        sizeParameterIndex: 3)),
                Parameter(typeof(uint).MakeByRefType())),
            ["MsiRecordIsNull"] = ContractWithReturnMarshal(
                typeof(bool),
                Marshall(UnmanagedType.Bool),
                Parameter(typeof(uint)),
                Parameter(typeof(uint))),
            ["MsiRecordReadStream"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(uint)),
                Parameter(
                    typeof(byte[]),
                    isOut: true,
                    marshal: Marshall(
                        UnmanagedType.LPArray,
                        UnmanagedType.U1,
                        sizeParameterIndex: 3)),
                Parameter(typeof(uint).MakeByRefType())),
            ["MsiSummaryInfoGetPropertyW"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(uint)),
                Parameter(typeof(uint).MakeByRefType(), isOut: true),
                Parameter(typeof(int).MakeByRefType(), isOut: true),
                Parameter(typeof(MsiNativeFileTime).MakeByRefType(), isOut: true),
                Parameter(
                    typeof(char[]),
                    isOut: true,
                    marshal: Marshall(
                        UnmanagedType.LPArray,
                        UnmanagedType.U2,
                        sizeParameterIndex: 6)),
                Parameter(typeof(uint).MakeByRefType())),
            ["MsiViewClose"] = Contract(typeof(uint), Parameter(typeof(uint))),
            ["MsiViewExecute"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(uint))),
            ["MsiViewFetch"] = Contract(
                typeof(uint),
                Parameter(typeof(uint)),
                Parameter(typeof(uint).MakeByRefType(), isOut: true)),
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
        imports.Should().OnlyContain(pair =>
            ExpectedContracts.ContainsKey(pair.Method.Name)
            && MatchesNativeContract(pair.Method, ExpectedContracts[pair.Method.Name]));
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
        typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(
                BindingFlags.Instance | BindingFlags.Static
                | BindingFlags.Public | BindingFlags.NonPublic
                | BindingFlags.DeclaredOnly))
            .SelectMany(FindForbiddenRoutes)
            .Should().BeEmpty();
        metadata.TypeReferences
            .Select(handle => metadata.GetTypeReference(handle))
            .Select(type =>
                $"{metadata.GetString(type.Namespace)}.{metadata.GetString(type.Name)}")
            .Where(IsForbiddenQualifiedRoute)
            .Should().BeEmpty();
        metadata.MemberReferences
            .Select(handle => QualifiedMemberName(metadata, handle))
            .Where(IsForbiddenQualifiedRoute)
            .Should().BeEmpty();
        typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(
                BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .SelectMany(method => method.GetParameters().Select(parameter => parameter.ParameterType)
                .Append(method.ReturnType))
            .Where(ContainsFunctionPointer)
            .Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(AdversarialRoutes.NativeLibraryRoute))]
    [InlineData(nameof(AdversarialRoutes.GetProcAddressRoute))]
    [InlineData(nameof(AdversarialRoutes.LoadLibraryRoute))]
    [InlineData(nameof(AdversarialRoutes.MarshalDelegateRoute))]
    [InlineData(nameof(AdversarialRoutes.DynamicInvokeRoute))]
    [InlineData(nameof(AdversarialRoutes.MethodHandleRoute))]
    [InlineData(nameof(AdversarialRoutes.InlineTokenRoute))]
    public void Dynamic_route_guard_rejects_each_adversarial_fixture(string methodName)
    {
        var method = typeof(AdversarialRoutes).GetMethod(
            methodName,
            BindingFlags.Static | BindingFlags.NonPublic)!;

        FindForbiddenRoutes(method).Should().NotBeEmpty();
    }

    [Theory]
    [InlineData(nameof(AdversarialSignatures.HandleWidthDrift), "MsiCloseHandle")]
    [InlineData(nameof(AdversarialSignatures.OutDirectionDrift), "MsiViewFetch")]
    [InlineData(nameof(AdversarialSignatures.StringMarshalDrift), "MsiOpenDatabaseW")]
    [InlineData(nameof(AdversarialSignatures.ArrayDirectionDrift), "MsiRecordGetStringW")]
    [InlineData(nameof(AdversarialSignatures.ReturnMarshalDrift), "MsiRecordIsNull")]
    public void Exact_signature_guard_rejects_width_direction_and_marshal_drift(
        string methodName,
        string contractName)
    {
        var method = typeof(AdversarialSignatures).GetMethod(
            methodName,
            BindingFlags.Static | BindingFlags.NonPublic)!;

        MatchesNativeContract(method, ExpectedContracts[contractName])
            .Should().BeFalse();
    }

    [Fact]
    public void Native_filetime_layout_is_exactly_two_uint_fields()
    {
        typeof(MsiNativeFileTime).StructLayoutAttribute!.Value
            .Should().Be(LayoutKind.Sequential);
        Marshal.SizeOf<MsiNativeFileTime>().Should().Be(8);
        typeof(MsiNativeFileTime).GetFields(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Select(field => (field.Name, field.FieldType, Offset: Marshal.OffsetOf<MsiNativeFileTime>(field.Name)))
            .Should().Equal(
                ("Low", typeof(uint), (nint)0),
                ("High", typeof(uint), (nint)4));
    }

    [Fact]
    public void Oversized_stream_key_length_gate_precedes_scalar_sanitizer()
    {
        var hasCompiledLengthGate = typeof(MsiDatabase).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(
                BindingFlags.Instance | BindingFlags.Static
                | BindingFlags.Public | BindingFlags.NonPublic))
            .Any(HasLengthGateBeforeSanitizer);

        hasCompiledLengthGate.Should().BeTrue();
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
            type => type.BaseType!.Name == "MsiSafeHandleBase");
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

    private static NativeMethodContract Contract(
        Type returnType,
        params NativeParameterContract[] parameters) =>
        new(returnType, null, parameters);

    private static NativeMethodContract ContractWithReturnMarshal(
        Type returnType,
        NativeMarshalContract returnMarshal,
        params NativeParameterContract[] parameters) =>
        new(returnType, returnMarshal, parameters);

    private static NativeParameterContract Parameter(
        Type type,
        bool isOut = false,
        bool isIn = false,
        NativeMarshalContract? marshal = null) =>
        new(type, isOut, isIn, marshal);

    private static NativeMarshalContract Marshall(
        UnmanagedType value,
        UnmanagedType arraySubType = 0,
        short sizeParameterIndex = 0) =>
        new(
            value,
            arraySubType,
            sizeParameterIndex,
            0,
            null,
            null,
            null,
            0,
            VarEnum.VT_EMPTY,
            null);

    private static bool MatchesNativeContract(
        MethodInfo method,
        NativeMethodContract contract)
    {
        if (method.ReturnType != contract.ReturnType
            || MarshalShape(method.ReturnParameter) != contract.ReturnMarshal
            || method.ReturnParameter.GetRequiredCustomModifiers().Length != 0
            || method.ReturnParameter.GetOptionalCustomModifiers().Length != 0)
        {
            return false;
        }

        var parameters = method.GetParameters();
        if (parameters.Length != contract.Parameters.Count) return false;
        for (var index = 0; index < parameters.Length; index++)
        {
            var actual = parameters[index];
            var expected = contract.Parameters[index];
            if (actual.ParameterType != expected.Type
                || actual.IsOut != expected.IsOut
                || actual.IsIn != expected.IsIn
                || MarshalShape(actual) != expected.Marshal
                || actual.GetRequiredCustomModifiers().Length != 0
                || actual.GetOptionalCustomModifiers().Length != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static NativeMarshalContract? MarshalShape(ParameterInfo parameter)
    {
        var attribute = parameter.GetCustomAttribute<MarshalAsAttribute>();
        return attribute is null
            ? null
            : new NativeMarshalContract(
                attribute.Value,
                attribute.ArraySubType,
                attribute.SizeParamIndex,
                attribute.SizeConst,
                attribute.MarshalType,
                attribute.MarshalTypeRef,
                attribute.MarshalCookie,
                attribute.IidParameterIndex,
                attribute.SafeArraySubType,
                attribute.SafeArrayUserDefinedSubType);
    }

    private static IReadOnlyList<string> FindForbiddenRoutes(MethodInfo method)
    {
        var body = method.GetMethodBody();
        if (body is null) return [];

        var forbidden = new List<string>();
        var typeArguments = method.DeclaringType?.GetGenericArguments();
        var methodArguments = method.IsGenericMethod
            ? method.GetGenericArguments()
            : null;
        foreach (var instruction in Decode(body.GetILAsByteArray()!))
        {
            if (instruction.OpCode == OpCodes.Calli)
            {
                forbidden.Add($"{method.DeclaringType?.FullName}.{method.Name}:calli");
                continue;
            }
            if (instruction.Token is not { } token) continue;

            MemberInfo? member;
            try
            {
                member = method.Module.ResolveMember(
                    token,
                    typeArguments,
                    methodArguments);
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (member is MethodInfo imported
                && imported.GetCustomAttribute<DllImportAttribute>() is not null
                && instruction.OpCode != OpCodes.Call)
            {
                forbidden.Add(
                    $"{method.DeclaringType?.FullName}.{method.Name}:" +
                    $"{instruction.OpCode.Name}:{QualifiedMemberName(imported)}");
            }

            var qualified = member switch
            {
                Type type => type.FullName ?? type.Name,
                null => string.Empty,
                _ => QualifiedMemberName(member),
            };
            if (IsForbiddenQualifiedRoute(qualified))
            {
                forbidden.Add(
                    $"{method.DeclaringType?.FullName}.{method.Name}:" +
                    $"{instruction.OpCode.Name}:{qualified}");
            }
        }

        return forbidden;
    }

    private static string QualifiedMemberName(MemberInfo member) =>
        $"{member.DeclaringType?.FullName}.{member.Name}";

    private static bool HasLengthGateBeforeSanitizer(MethodInfo method)
    {
        var body = method.GetMethodBody();
        if (body is null) return false;

        var instructions = Decode(body.GetILAsByteArray()!);
        var resolved = instructions
            .Select(instruction => (
                instruction,
                member: instruction.Token is { } token
                    ? ResolveMember(method, token)
                    : null))
            .ToArray();
        var lengthIndex = Array.FindIndex(
            resolved,
            item => item.member is MethodInfo target
                && target.DeclaringType == typeof(string)
                && target.Name == "get_Length");
        var sanitizerIndex = Array.FindIndex(
            resolved,
            item => item.member is MethodInfo target
                && target.DeclaringType == typeof(MsiTextPolicy)
                && target.Name == nameof(MsiTextPolicy.Sanitize));
        var readsRawIdentity = resolved.Any(
            item => item.member is MethodInfo target
                && target.DeclaringType == typeof(MsiRecordValue)
                && target.Name == "get_Identity");
        return readsRawIdentity
            && lengthIndex >= 0
            && sanitizerIndex > lengthIndex
            && resolved[(lengthIndex + 1)..sanitizerIndex]
                .Any(item =>
                    item.instruction.OpCode.FlowControl == FlowControl.Cond_Branch);
    }

    private static MemberInfo? ResolveMember(MethodInfo method, int token)
    {
        try
        {
            return method.Module.ResolveMember(
                token,
                method.DeclaringType?.GetGenericArguments(),
                method.IsGenericMethod ? method.GetGenericArguments() : null);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static bool IsForbiddenQualifiedRoute(string qualified)
    {
        if (qualified == "System.Runtime.InteropServices.NativeLibrary"
            || qualified.StartsWith(
                "System.Runtime.InteropServices.NativeLibrary.",
                StringComparison.Ordinal))
        {
            return true;
        }

        var separator = qualified.LastIndexOf('.');
        var memberName = separator >= 0 ? qualified[(separator + 1)..] : qualified;
        return memberName.StartsWith("GetProcAddress", StringComparison.Ordinal)
            || memberName.StartsWith("LoadLibrary", StringComparison.Ordinal)
            || memberName.StartsWith(
                "GetDelegateForFunctionPointer",
                StringComparison.Ordinal)
            || qualified is "System.Delegate.DynamicInvoke"
                or "System.RuntimeMethodHandle.GetFunctionPointer"
                or "System.Reflection.MethodBase.Invoke"
                or "System.Reflection.MethodInfo.CreateDelegate"
                or "System.Delegate.CreateDelegate";
    }

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
            if (opcode.OperandType is OperandType.InlineField
                or OperandType.InlineMethod
                or OperandType.InlineSig
                or OperandType.InlineString
                or OperandType.InlineTok
                or OperandType.InlineType)
            {
                token = BitConverter.ToInt32(il, offset);
            }
            instructions.Add(new IlInstruction(instructionOffset, opcode, token));
            offset += operandSize;
        }

        return instructions;
    }

    private sealed record IlInstruction(int Offset, OpCode OpCode, int? Token);

    private sealed record NativeMethodContract(
        Type ReturnType,
        NativeMarshalContract? ReturnMarshal,
        IReadOnlyList<NativeParameterContract> Parameters);

    private sealed record NativeParameterContract(
        Type Type,
        bool IsOut,
        bool IsIn,
        NativeMarshalContract? Marshal);

    private sealed record NativeMarshalContract(
        UnmanagedType Value,
        UnmanagedType ArraySubType,
        short SizeParamIndex,
        int SizeConst,
        string? MarshalType,
        Type? MarshalTypeRef,
        string? MarshalCookie,
        int IidParameterIndex,
        VarEnum SafeArraySubType,
        Type? SafeArrayUserDefinedSubType);

    private static class AdversarialRoutes
    {
        internal static nint NativeLibraryRoute() =>
            NativeLibrary.GetExport(nint.Zero, "benign-test-symbol");

        internal static nint GetProcAddressRoute() =>
            AdversarialNamedResolver.GetProcAddress(nint.Zero, "benign-test-symbol");

        internal static nint LoadLibraryRoute() =>
            AdversarialNamedResolver.LoadLibraryW("benign-test-library");

        internal static Delegate MarshalDelegateRoute() =>
            Marshal.GetDelegateForFunctionPointer<Action>(nint.Zero);

        internal static object? DynamicInvokeRoute(Delegate callback) =>
            callback.DynamicInvoke();

        internal static nint MethodHandleRoute(MethodInfo method) =>
            method.MethodHandle.GetFunctionPointer();

        internal static Type InlineTokenRoute() => typeof(NativeLibrary);
    }

    private static class AdversarialNamedResolver
    {
        internal static nint GetProcAddress(nint module, string symbol) => module;
        internal static nint LoadLibraryW(string path) => nint.Zero;
    }

    private static class AdversarialSignatures
    {
        internal static uint HandleWidthDrift(nint handle) => 0;

        internal static uint OutDirectionDrift(uint view, ref uint record) => 0;

        internal static uint StringMarshalDrift(
            [MarshalAs(UnmanagedType.LPStr)] string path,
            nint persistence,
            out uint database)
        {
            database = 0;
            return 0;
        }

        internal static uint ArrayDirectionDrift(
            uint record,
            uint field,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U2, SizeParamIndex = 3)]
            char[] value,
            ref uint length) => 0;

        internal static bool ReturnMarshalDrift(uint record, uint field) => false;
    }

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
