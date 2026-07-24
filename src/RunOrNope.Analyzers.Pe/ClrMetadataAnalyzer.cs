using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Reflection.Emit;
using System.Reflection;

namespace RunOrNope.Analyzers.Pe;

public sealed class ClrMetadataAnalyzer
{
    public static ClrAnalysisResult Analyze(Stream stream, long length, ClrAnalysisLimits limits)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("A readable, seekable stream is required.", nameof(stream));
        if (length < 0 || length > stream.Length) throw new ArgumentOutOfRangeException(nameof(length));
        if (limits.MaxMethods <= 0 || limits.MaxInstructionsPerMethod <= 0)
            throw new ArgumentOutOfRangeException(nameof(limits));
        stream.Position = 0;
        using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        if (!reader.HasMetadata)
            return new(false, null, [], [], [], false, []);

        var metadata = reader.GetMetadataReader();
        string? assemblyName = null;
        if (metadata.IsAssembly)
            assemblyName = metadata.GetString(metadata.GetAssemblyDefinition().Name);

        var references = ImmutableArray.CreateBuilder<string>();
        foreach (var handle in metadata.AssemblyReferences)
            references.Add(metadata.GetString(metadata.GetAssemblyReference(handle).Name));

        var methods = ImmutableArray.CreateBuilder<ClrMethodObservation>();
        var unresolved = ImmutableArray.CreateBuilder<string>();
        var truncated = false;
        foreach (var typeHandle in metadata.TypeDefinitions)
        {
            var type = metadata.GetTypeDefinition(typeHandle);
            var typeName = metadata.GetString(type.Namespace) + "." + metadata.GetString(type.Name);
            foreach (var methodHandle in type.GetMethods())
            {
                if (methods.Count >= limits.MaxMethods) { truncated = true; break; }
                var method = metadata.GetMethodDefinition(methodHandle);
                var calls = ImmutableArray<int>.Empty;
                var ilSize = 0;
                if (method.RelativeVirtualAddress != 0)
                {
                    try
                    {
                        var body = reader.GetMethodBody(method.RelativeVirtualAddress);
                        var il = body.GetILBytes() ?? [];
                        ilSize = il.Length;
                        calls = FindDirectCallTokens(il, limits.MaxInstructionsPerMethod, out var instructionLimit);
                        if (instructionLimit)
                        {
                            truncated = true;
                            unresolved.Add($"{MetadataTokens.GetToken(methodHandle):X8}: instruction limit reached");
                        }
                    }
                    catch (BadImageFormatException)
                    {
                        unresolved.Add($"{MetadataTokens.GetToken(methodHandle):X8}: malformed method body");
                    }
                }
                methods.Add(new(MetadataTokens.GetToken(methodHandle), typeName,
                    metadata.GetString(method.Name), ilSize, calls));
            }
            if (truncated && methods.Count >= limits.MaxMethods) break;
        }
        var calledTokens = methods.SelectMany(method => method.DirectCallTokens).ToHashSet();
        var externalReferences = ImmutableArray.CreateBuilder<ClrExternalReference>();
        foreach (var handle in metadata.MemberReferences)
        {
            var member = metadata.GetMemberReference(handle);
            externalReferences.Add(new(MetadataTokens.GetToken(handle),
                GetMemberReferenceName(metadata, member),
                "metadata member reference",
                calledTokens.Contains(MetadataTokens.GetToken(handle))));
        }
        foreach (var typeHandle in metadata.TypeDefinitions)
        {
            var type = metadata.GetTypeDefinition(typeHandle);
            foreach (var methodHandle in type.GetMethods())
            {
                var method = metadata.GetMethodDefinition(methodHandle);
                if ((method.Attributes & MethodAttributes.PinvokeImpl) == 0) continue;
                var import = method.GetImport();
                externalReferences.Add(new(MetadataTokens.GetToken(methodHandle),
                    metadata.GetString(import.Name) + " from " +
                    metadata.GetString(metadata.GetModuleReference(import.Module).Name),
                    "P/Invoke implementation",
                    calledTokens.Contains(MetadataTokens.GetToken(methodHandle))));
            }
        }
        return new(true, assemblyName, references.ToImmutable(), methods.ToImmutable(),
            externalReferences.ToImmutable(),
            truncated, unresolved.ToImmutable());
    }

    private static ImmutableArray<int> FindDirectCallTokens(
        ReadOnlySpan<byte> il,
        int maximumInstructions,
        out bool truncated)
    {
        var calls = ImmutableArray.CreateBuilder<int>();
        var inspected = 0;
        for (var index = 0; index < il.Length && inspected < maximumInstructions; inspected++)
        {
            var first = il[index++];
            short value = first;
            if (first == 0xfe)
            {
                if (index >= il.Length) break;
                value = unchecked((short)(0xfe00 | il[index++]));
            }
            if (!OpCodesByValue.TryGetValue(value, out var opCode)) break;
            var operandSize = GetOperandSize(opCode.OperandType, il, index);
            if (operandSize < 0 || index > il.Length - operandSize) break;
            if (opCode == OpCodes.Call || opCode == OpCodes.Callvirt)
                calls.Add(BitConverter.ToInt32(il.Slice(index, 4)));
            index += operandSize;
        }
        truncated = inspected >= maximumInstructions;
        return calls.ToImmutable();
    }

    private static string GetMemberReferenceName(MetadataReader metadata, MemberReference member)
    {
        var owner = member.Parent.Kind == HandleKind.TypeReference
            ? metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)member.Parent).Name)
            : member.Parent.Kind.ToString();
        return owner + "." + metadata.GetString(member.Name);
    }

    private static int GetOperandSize(OperandType type, ReadOnlySpan<byte> il, int index) => type switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineBrTarget or OperandType.InlineField or OperandType.InlineI
            or OperandType.InlineMethod or OperandType.InlineSig or OperandType.InlineString
            or OperandType.InlineTok or OperandType.InlineType or OperandType.ShortInlineR => 4,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch when index <= il.Length - 4 =>
            GetSwitchOperandSize(BitConverter.ToInt32(il.Slice(index, 4)), il.Length - index),
        _ => -1,
    };

    private static int GetSwitchOperandSize(int count, int remaining)
    {
        if (count < 0) return -1;
        var size = 4L + (long)count * 4;
        return size <= remaining && size <= int.MaxValue ? (int)size : -1;
    }

    private static readonly Dictionary<short, OpCode> OpCodesByValue =
        typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(OpCode))
            .Select(field => (OpCode)field.GetValue(null)!)
            .ToDictionary(opCode => opCode.Value);
}
