using System.Collections.Immutable;

namespace RunOrNope.Analyzers.Msi;

public enum CustomActionBaseKind
{
    Unknown,
    BinaryDll,
    BinaryExe,
    BinaryJScript,
    BinaryVbScript,
    InstalledDll,
    InstalledExe,
    ErrorMessage,
    InstalledJScript,
    InstalledVbScript,
    DirectoryExe,
    DirectorySet,
    InlineJScript,
    InlineVbScript,
    PropertyExe,
    PropertySet,
    PropertyJScript,
    PropertyVbScript,
}

public enum CustomActionSourceKind
{
    Unknown,
    None,
    BinaryTable,
    FileTable,
    DirectoryTable,
    Property,
}

public enum CustomActionTargetKind
{
    Unknown,
    DllEntryPoint,
    CommandLine,
    ScriptFunction,
    FormattedText,
    ExecutablePathAndArguments,
    ScriptText,
}

public sealed record DecodedCustomAction(
    CustomActionBaseKind BaseKind,
    CustomActionSourceKind SourceKind,
    CustomActionTargetKind TargetKind,
    bool ContinueOnError,
    bool Asynchronous,
    bool IsRollback,
    bool IsCommit,
    bool IsDeferred,
    bool NoImpersonation,
    bool Is64BitScript,
    bool IsTerminalServerAware,
    bool HideTarget,
    bool PatchUninstall,
    int UnknownBits);

public sealed record MsiUiActionReference(
    string Dialog,
    string Control,
    string Event,
    string Argument,
    string? Condition,
    int Ordering);

public sealed record CustomActionInvocation(
    string Action,
    DecodedCustomAction Decoded,
    ImmutableArray<string> ExecuteSequences,
    ImmutableArray<MsiUiActionReference> UiReferences);

public sealed record CustomActionReachabilityResult(
    bool PotentialElevation,
    bool UiDependent,
    bool InconsistentDeferredScheduling,
    bool Incomplete);

public static class CustomActionDecoder
{
    private const int BaseTypeMask = 0x3f;
    private const int ContinueOnErrorFlag = 0x40;
    private const int AsynchronousFlag = 0x80;
    private const int RollbackFlag = 0x100;
    private const int CommitFlag = 0x200;
    private const int DeferredFlag = 0x400;
    private const int NoImpersonationFlag = 0x800;
    private const int Bit64ScriptFlag = 0x1000;
    private const int HideTargetFlag = 0x2000;
    private const int TerminalServerAwareFlag = 0x4000;
    private const int PatchUninstallFlag = 0x8000;
    private const int KnownMask = BaseTypeMask
        | ContinueOnErrorFlag
        | AsynchronousFlag
        | RollbackFlag
        | CommitFlag
        | DeferredFlag
        | NoImpersonationFlag
        | Bit64ScriptFlag
        | HideTargetFlag
        | TerminalServerAwareFlag
        | PatchUninstallFlag;

    public static DecodedCustomAction Decode(int type)
    {
        var (baseKind, sourceKind, targetKind) = (type & BaseTypeMask) switch
        {
            1 => (CustomActionBaseKind.BinaryDll, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.DllEntryPoint),
            2 => (CustomActionBaseKind.BinaryExe, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.CommandLine),
            5 => (CustomActionBaseKind.BinaryJScript, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.ScriptFunction),
            6 => (CustomActionBaseKind.BinaryVbScript, CustomActionSourceKind.BinaryTable, CustomActionTargetKind.ScriptFunction),
            17 => (CustomActionBaseKind.InstalledDll, CustomActionSourceKind.FileTable, CustomActionTargetKind.DllEntryPoint),
            18 => (CustomActionBaseKind.InstalledExe, CustomActionSourceKind.FileTable, CustomActionTargetKind.CommandLine),
            19 => (CustomActionBaseKind.ErrorMessage, CustomActionSourceKind.None, CustomActionTargetKind.FormattedText),
            21 => (CustomActionBaseKind.InstalledJScript, CustomActionSourceKind.FileTable, CustomActionTargetKind.ScriptFunction),
            22 => (CustomActionBaseKind.InstalledVbScript, CustomActionSourceKind.FileTable, CustomActionTargetKind.ScriptFunction),
            34 => (CustomActionBaseKind.DirectoryExe, CustomActionSourceKind.DirectoryTable, CustomActionTargetKind.ExecutablePathAndArguments),
            35 => (CustomActionBaseKind.DirectorySet, CustomActionSourceKind.DirectoryTable, CustomActionTargetKind.FormattedText),
            37 => (CustomActionBaseKind.InlineJScript, CustomActionSourceKind.None, CustomActionTargetKind.ScriptText),
            38 => (CustomActionBaseKind.InlineVbScript, CustomActionSourceKind.None, CustomActionTargetKind.ScriptText),
            50 => (CustomActionBaseKind.PropertyExe, CustomActionSourceKind.Property, CustomActionTargetKind.CommandLine),
            51 => (CustomActionBaseKind.PropertySet, CustomActionSourceKind.Property, CustomActionTargetKind.FormattedText),
            53 => (CustomActionBaseKind.PropertyJScript, CustomActionSourceKind.Property, CustomActionTargetKind.ScriptFunction),
            54 => (CustomActionBaseKind.PropertyVbScript, CustomActionSourceKind.Property, CustomActionTargetKind.ScriptFunction),
            _ => (CustomActionBaseKind.Unknown, CustomActionSourceKind.Unknown, CustomActionTargetKind.Unknown),
        };

        return new DecodedCustomAction(
            baseKind,
            sourceKind,
            targetKind,
            HasFlag(type, ContinueOnErrorFlag),
            HasFlag(type, AsynchronousFlag),
            HasFlag(type, RollbackFlag),
            HasFlag(type, CommitFlag),
            HasFlag(type, DeferredFlag),
            HasFlag(type, NoImpersonationFlag),
            HasFlag(type, Bit64ScriptFlag),
            HasFlag(type, TerminalServerAwareFlag),
            HasFlag(type, HideTargetFlag),
            HasFlag(type, PatchUninstallFlag),
            type & ~KnownMask);
    }

    private static bool HasFlag(int type, int flag) => (type & flag) != 0;
}

public static class CustomActionReachability
{
    public static CustomActionReachabilityResult Correlate(CustomActionInvocation invocation)
    {
        ArgumentNullException.ThrowIfNull(invocation);

        var actionName = invocation.Action;
        var hasActionName = !string.IsNullOrEmpty(actionName);
        var executeSequencePresence = hasActionName
            && !invocation.ExecuteSequences.IsDefaultOrEmpty
            && invocation.ExecuteSequences.Any(sequence => StringComparer.Ordinal.Equals(sequence, actionName));
        var uiDependent = hasActionName
            && !invocation.UiReferences.IsDefaultOrEmpty
            && invocation.UiReferences.Any(reference =>
                reference is not null
                && !string.IsNullOrEmpty(reference.Dialog)
                && !string.IsNullOrEmpty(reference.Control)
                && StringComparer.Ordinal.Equals(reference.Event, "DoAction")
                && StringComparer.Ordinal.Equals(reference.Argument, actionName));

        var decoded = invocation.Decoded;
        var potentialElevation = decoded.IsDeferred
            && decoded.NoImpersonation
            && executeSequencePresence;
        var inconsistentDeferredScheduling = decoded.IsDeferred
            && decoded.NoImpersonation
            && uiDependent
            && !executeSequencePresence;

        return new CustomActionReachabilityResult(
            potentialElevation,
            uiDependent,
            inconsistentDeferredScheduling,
            decoded.HideTarget || inconsistentDeferredScheduling);
    }
}
