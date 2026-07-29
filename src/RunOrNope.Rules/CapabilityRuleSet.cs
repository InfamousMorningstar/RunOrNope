using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Rules;

/// <summary>
/// The curated capability rules, evaluated in this fixed order. Each rule names the
/// APIs that form its required core and, where a capability can be completed several
/// ways, an any-of set of which at least one must also be present. Tiers are
/// deliberately conservative: import presence yields at most structural evidence, and
/// the weak presence-only rules stay low so they add context rather than accusation.
/// </summary>
public static class CapabilityRuleSet
{
    public static ImmutableArray<CapabilityRule> Default { get; } =
    [
        new CapabilityRule(
            "process-injection",
            "Injects code into another process",
            "Writing and executing code inside another process runs with that process's identity and can bypass controls.",
            RiskFamily.ProcessManipulation, Severity.High,
            EvidenceStatus.StrongStructuralEvidence, EvidenceConfidence.Medium,
            RecommendedAction.ExerciseCaution,
            // Allocating and writing remote memory is the core; without one of the
            // execution primitives this is an ordinary patcher or debugger.
            ["VirtualAllocEx", "WriteProcessMemory"],
            ["CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
             "RtlCreateUserThread", "QueueUserAPC", "QueueUserAPC2"],
            ["Debuggers, profilers, anti-cheat, and legitimate launchers use these APIs."]),
        new CapabilityRule(
            "token-manipulation",
            "Manipulates process privileges or tokens",
            "Adjusting token privileges can enable elevation or access that the process would not otherwise have.",
            RiskFamily.PrivilegeElevation, Severity.Medium,
            EvidenceStatus.StrongStructuralEvidence, EvidenceConfidence.Medium,
            RecommendedAction.ExerciseCaution,
            ["OpenProcessToken", "AdjustTokenPrivileges"],
            [],
            ["Enabling a named privilege is the required preamble to ordinary operations: " +
             "SeShutdownPrivilege for any app offering restart or shutdown, SeBackupPrivilege " +
             "for backup and imaging tools, and SeDebugPrivilege for task managers and profilers."]),
        new CapabilityRule(
            "dpapi-credential-access",
            "Decrypts DPAPI-protected secrets",
            "CryptUnprotectData decrypts data protected by the Windows Data Protection API, including browser and app credentials.",
            RiskFamily.CredentialAccess, Severity.High,
            EvidenceStatus.StrongStructuralEvidence, EvidenceConfidence.Medium,
            RecommendedAction.ExerciseCaution,
            ["CryptUnprotectData"],
            [],
            ["An application may legitimately decrypt its own DPAPI-protected data."]),
        new CapabilityRule(
            "screen-capture",
            "Captures the screen",
            "Copying screen pixels into a bitmap can be used for surveillance or remote support.",
            RiskFamily.Surveillance, Severity.Medium,
            EvidenceStatus.StrongStructuralEvidence, EvidenceConfidence.Medium,
            RecommendedAction.ExerciseCaution,
            // The blit pair alone is the standard double-buffered painting idiom used by
            // every custom-drawn control. What distinguishes capture is where the source
            // device context comes from, so require a screen or window DC as well.
            ["BitBlt", "CreateCompatibleBitmap"],
            ["GetDesktopWindow", "GetWindowDC", "GetDC"],
            ["Screenshot, screen-sharing, and remote-desktop tools use these APIs."]),
        new CapabilityRule(
            "keylogging",
            "Records keystrokes",
            "Installing a keyboard hook and reading key state can capture what the user types.",
            RiskFamily.Surveillance, Severity.High,
            EvidenceStatus.StrongStructuralEvidence, EvidenceConfidence.Medium,
            RecommendedAction.ExerciseCaution,
            // The hook is the core. Key-state polling on its own is what every game and
            // hotkey handler does, and must never be reported as keystroke capture.
            ["SetWindowsHookEx"],
            ["GetAsyncKeyState", "GetKeyState", "GetKeyboardState"],
            ["Accessibility software, hotkey managers, and games read keyboard state."]),
        new CapabilityRule(
            "service-install",
            "Installs a Windows service",
            "Creating a service can establish persistence that runs with system privileges.",
            RiskFamily.Persistence, Severity.Medium,
            EvidenceStatus.StrongStructuralEvidence, EvidenceConfidence.Medium,
            RecommendedAction.ExerciseCaution,
            ["OpenSCManager", "CreateService"],
            [],
            ["Installers legitimately create services for background components."]),
        new CapabilityRule(
            "anti-debugging",
            "Checks for a debugger",
            "Detecting a debugger can be used to hinder analysis, but is also common in commercial software.",
            // Informational, like every presence-only rule: the C runtime pulls this in
            // on ordinary assert/abort paths. See the scoring note at the foot of this file.
            RiskFamily.DefenseEvasion, Severity.Informational,
            EvidenceStatus.ApiOrLibraryPresenceOnly, EvidenceConfidence.Low,
            RecommendedAction.ReviewProvenance,
            [],
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
             "NtQueryInformationProcess", "ZwQueryInformationProcess"],
            ["Commercial protectors, DRM, and games routinely check for debuggers."]),
        new CapabilityRule(
            "dynamic-api-resolution",
            "Resolves APIs at runtime",
            "Resolving functions dynamically can hide which APIs are used, but is an extremely common plugin pattern.",
            RiskFamily.Obfuscation, Severity.Informational,
            EvidenceStatus.ApiOrLibraryPresenceOnly, EvidenceConfidence.Low,
            RecommendedAction.ReviewProvenance,
            // GetProcAddress is the resolution primitive; either loader form satisfies
            // the module half, so LoadLibraryEx-only callers are still matched.
            ["GetProcAddress"],
            ["LoadLibrary", "LoadLibraryEx"],
            ["Nearly all software that loads plugins or optional features uses these APIs."]),
        new CapabilityRule(
            "network-communication",
            "Communicates over the network",
            "The file imports network APIs; this alone does not indicate malicious communication.",
            RiskFamily.NetworkCommunication, Severity.Informational,
            EvidenceStatus.ApiOrLibraryPresenceOnly, EvidenceConfidence.Low,
            RecommendedAction.ReviewProvenance,
            [],
            // "send" is omitted deliberately: anything that reaches it already connected
            // through one of these, so it adds no detection value and only widens the
            // surface for a same-named managed P/Invoke to match.
            ["InternetConnect", "HttpSendRequest", "WinHttpConnect", "WSAConnect", "connect"],
            ["Most networked applications use these APIs for ordinary communication."]),
    ];

    // Scoring note (ScoringPolicy is deliberately not modified by this slice):
    // every presence-only rule scores Informational(0) + ApiOrLibraryPresenceOnly(3)
    // + Low(1) = 4. All three firing together total 12, which stays below the
    // CautionThreshold of 15. That is the property design §5.3 asks for — these rules
    // are context, not accusations — and it is locked by
    // WorkerScanTests.AnalyzeAsync_OrdinaryDesktopAppImports_YieldFewMaterialConcerns.
    // Adding a presence-only rule means re-checking that sum.
}
