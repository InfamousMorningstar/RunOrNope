using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.UnitTests.Msi;

public sealed class CustomActionReachabilityTests
{
    [Fact]
    public void Correlate_marks_a_deferred_no_impersonation_action_in_an_execute_sequence_as_potentially_elevated()
    {
        var result = CustomActionReachability.Correlate(Invocation(
            decoded: Decoded(isDeferred: true, noImpersonation: true),
            executeSequences: ImmutableArray.Create("ElevatedAction")));

        result.PotentialElevation.Should().BeTrue();
        result.UiDependent.Should().BeFalse();
        result.InconsistentDeferredScheduling.Should().BeFalse();
        result.Incomplete.Should().BeFalse();
    }

    [Theory]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, true, false)]
    public void Correlate_withholds_potential_elevation_when_any_required_leg_is_absent(
        bool isDeferred,
        bool noImpersonation,
        bool inExecuteSequence)
    {
        var result = CustomActionReachability.Correlate(Invocation(
            decoded: Decoded(isDeferred, noImpersonation),
            executeSequences: inExecuteSequence ? ImmutableArray.Create("ElevatedAction") : ImmutableArray<string>.Empty));

        result.PotentialElevation.Should().BeFalse();
    }

    [Fact]
    public void Correlate_marks_an_immediate_action_reached_by_a_do_action_control_event_as_ui_dependent()
    {
        var result = CustomActionReachability.Correlate(Invocation(
            decoded: Decoded(isDeferred: false, noImpersonation: false),
            uiReferences: ImmutableArray.Create(new MsiUiActionReference(
                "WelcomeDlg", "Next", "DoAction", "ElevatedAction", "INSTALLLEVEL > 1", 10))));

        result.UiDependent.Should().BeTrue();
        result.PotentialElevation.Should().BeFalse();
        result.InconsistentDeferredScheduling.Should().BeFalse();
        result.Incomplete.Should().BeFalse();
    }

    [Fact]
    public void Correlate_marks_a_deferred_no_impersonation_action_reached_only_through_do_action_as_incomplete_not_elevated()
    {
        var result = CustomActionReachability.Correlate(Invocation(
            decoded: Decoded(isDeferred: true, noImpersonation: true),
            uiReferences: ImmutableArray.Create(new MsiUiActionReference(
                "WelcomeDlg", "Next", "DoAction", "ElevatedAction", "INSTALLLEVEL > 1", 10))));

        result.UiDependent.Should().BeTrue();
        result.PotentialElevation.Should().BeFalse();
        result.InconsistentDeferredScheduling.Should().BeTrue();
        result.Incomplete.Should().BeTrue();
    }

    [Theory]
    [InlineData("", "Next")]
    [InlineData("WelcomeDlg", "")]
    public void Correlate_requires_a_dialog_and_control_for_do_action_reachability(string dialog, string control)
    {
        var result = CustomActionReachability.Correlate(Invocation(
            decoded: Decoded(isDeferred: false, noImpersonation: false),
            uiReferences: ImmutableArray.Create(new MsiUiActionReference(
                dialog, control, "DoAction", "ElevatedAction", "INSTALLLEVEL > 1", 10))));

        result.UiDependent.Should().BeFalse();
    }

    [Fact]
    public void Correlate_treats_hidden_targets_as_an_evidence_gap()
    {
        var result = CustomActionReachability.Correlate(Invocation(
            decoded: Decoded(isDeferred: false, noImpersonation: false, hideTarget: true)));

        result.Incomplete.Should().BeTrue();
    }

    [Fact]
    public void Correlate_is_safe_for_default_immutable_arrays_and_an_empty_action_name()
    {
        var invocation = new CustomActionInvocation(
            string.Empty,
            Decoded(isDeferred: false, noImpersonation: false),
            default,
            default);

        var result = CustomActionReachability.Correlate(invocation);

        result.PotentialElevation.Should().BeFalse();
        result.UiDependent.Should().BeFalse();
        result.InconsistentDeferredScheduling.Should().BeFalse();
        result.Incomplete.Should().BeFalse();
    }

    private static CustomActionInvocation Invocation(
        DecodedCustomAction decoded,
        ImmutableArray<string> executeSequences = default,
        ImmutableArray<MsiUiActionReference> uiReferences = default) =>
        new("ElevatedAction", decoded, executeSequences, uiReferences);

    private static DecodedCustomAction Decoded(bool isDeferred, bool noImpersonation, bool hideTarget = false) =>
        new(
            CustomActionBaseKind.BinaryExe,
            CustomActionSourceKind.BinaryTable,
            CustomActionTargetKind.CommandLine,
            false,
            false,
            false,
            false,
            isDeferred,
            noImpersonation,
            false,
            false,
            hideTarget,
            false,
            0);
}
