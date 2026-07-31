using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using RunOrNope.App.Infrastructure;
using RunOrNope.App.Services;
using RunOrNope.Contracts;
using RunOrNope.Intake;
using RunOrNope.Reporting;

namespace RunOrNope.App.ViewModels;

public enum ScanUiState
{
    Idle, Acquiring, Analyzing, Completed, Cancelling, Cancelled, Failed
}

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private static readonly Uri VirusTotalDestination = new("https://www.virustotal.com");
    private readonly IScanCoordinator _coordinator;
    private readonly IReportExportService _export;
    private readonly IHashReputationLookup _lookup;
    private readonly IUserInteraction _interaction;
    private CancellationTokenSource? _operation;
    private string? _virusTotalApiKey;
    private string? _selectedPath;
    private CompletedScan? _completedScan;
    private ScanUiState _state;
    private string _statusMessage = "Choose a local PE or MSI to begin.";
    private HashReputationViewModel _reputation = HashReputationViewModel.Empty;
    private IReadOnlyList<CapabilityCardViewModel> _capabilityCards = [];
    private bool _disposed;
    private bool _lookupActive;

    public MainViewModel(
        IScanCoordinator coordinator,
        IReportExportService export,
        IHashReputationLookup lookup,
        IUserInteraction interaction)
    {
        _coordinator = coordinator;
        _export = export;
        _lookup = lookup;
        _interaction = interaction;
        ScanCommand = new AsyncCommand(ScanAsync, () => CanStart);
        CancelCommand = new DelegateCommand(Cancel, () => CanCancel);
        LookupHashCommand = new AsyncCommand(LookupHashAsync, () => CanLookupHash);
        ExportHtmlCommand = new AsyncCommand(
            () => ExportAsync(ReportFormat.Html), () => CanExport);
        ExportJsonCommand = new AsyncCommand(
            () => ExportAsync(ReportFormat.Json), () => CanExport);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ScanUiState State { get => _state; private set => Set(ref _state, value); }
    public ScanMode SelectedMode { get; set; } = ScanMode.Quick;
    public bool IsQuickMode
    {
        get => SelectedMode == ScanMode.Quick;
        set { if (value) { SelectedMode = ScanMode.Quick; OnPropertyChanged(); OnPropertyChanged(nameof(IsDeepMode)); } }
    }
    public bool IsDeepMode
    {
        get => SelectedMode == ScanMode.Deep;
        set { if (value) { SelectedMode = ScanMode.Deep; OnPropertyChanged(); OnPropertyChanged(nameof(IsQuickMode)); } }
    }
    public bool UseFullEvidence { get; set; }
    public string? SelectedPath { get => _selectedPath; private set => Set(ref _selectedPath, value); }
    public string StatusMessage { get => _statusMessage; private set => Set(ref _statusMessage, value); }
    public CompletedScan? CompletedScan { get => _completedScan; private set => Set(ref _completedScan, value); }
    public IReadOnlyList<CapabilityCardViewModel> CapabilityCards
    {
        get => _capabilityCards;
        private set => Set(ref _capabilityCards, value);
    }
    public HashReputationViewModel Reputation { get => _reputation; private set => Set(ref _reputation, value); }
    public string AnalysisStatus => CompletedScan?.Result.AnalysisStatus.ToString() ?? "Not analyzed";
    public string Completeness => CompletedScan?.Result.Completeness.ToString() ?? "Not analyzed";
    public string? RiskDisposition => CompletedScan?.Verdict.RiskDisposition?.ToString();
    public string Sha256 => CompletedScan?.Sha256 ?? "Not available";
    public string SignerState => CompletedScan?.Result.Observations
        .FirstOrDefault(observation => observation.Kind == "pe.trust")?.Description
        ?? "Not reported";
    public string StrongestEvidence => CompletedScan?.Result.Findings
        .OrderBy(finding => EvidenceRank(finding.EvidenceStatus))
        .Select(finding => finding.EvidenceStatus.ToString())
        .FirstOrDefault() ?? "None reported";
    public bool CanStart => !_disposed && !_lookupActive &&
        (State is ScanUiState.Idle or ScanUiState.Completed or ScanUiState.Cancelled or ScanUiState.Failed) &&
        !string.IsNullOrWhiteSpace(SelectedPath);
    public bool CanCancel => _lookupActive || State is ScanUiState.Acquiring or ScanUiState.Analyzing;
    public bool CanExport => CompletedScan is not null && State == ScanUiState.Completed;
    public bool CanLookupHash => !_lookupActive && CanExport && !string.IsNullOrEmpty(_virusTotalApiKey);

    public ICommand ScanCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand LookupHashCommand { get; }
    public ICommand ExportHtmlCommand { get; }
    public ICommand ExportJsonCommand { get; }

    public void SelectPath(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        SelectedPath = path;
        StatusMessage = "Ready to analyze. The sample will not be executed or uploaded.";
        RaiseCommandState();
    }

    public void SetVirusTotalApiKey(string? apiKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _virusTotalApiKey = string.IsNullOrEmpty(apiKey) ? null : apiKey;
        RaiseCommandState();
    }

    public async Task ScanAsync()
    {
        if (!CanStart || SelectedPath is null) return;
        ReplaceOperation();
        CompletedScan = null;
        CapabilityCards = [];
        Reputation = HashReputationViewModel.Empty;
        State = ScanUiState.Acquiring;
        StatusMessage = "Acquiring a stable, read-only handle…";
        RaiseAllSummary();
        RaiseCommandState();
        try
        {
            State = ScanUiState.Analyzing;
            StatusMessage = "Analyzing inside the capability-free worker…";
            RaiseCommandState();
            var completed = await _coordinator.ScanAsync(
                SelectedPath, SelectedMode, _operation!.Token).ConfigureAwait(true);
            CompletedScan = completed;
            CapabilityCards = completed.Result.Findings
                .Select(finding => CapabilityCardViewModel.From(completed.Result, finding))
                .ToArray();
            State = ScanUiState.Completed;
            StatusMessage = completed.Result.AnalysisStatus == RunOrNope.Contracts.AnalysisStatus.Incomplete
                ? "Analysis is incomplete. No favourable conclusion is available."
                : completed.Result.AnalysisStatus == RunOrNope.Contracts.AnalysisStatus.IsolationUnavailable
                    ? "Analysis did not run because required isolation was unavailable."
                    : "Static analysis completed.";
        }
        catch (OperationCanceledException)
        {
            State = ScanUiState.Cancelled;
            StatusMessage = "Analysis cancelled.";
        }
        catch (IntakeRejectedException)
        {
            State = ScanUiState.Failed;
            StatusMessage = "voidlens could not safely acquire this local file.";
        }
        catch (Exception) when (!_disposed)
        {
            State = ScanUiState.Failed;
            StatusMessage = "Analysis could not be completed. No favourable conclusion is available.";
        }
        finally
        {
            _operation?.Dispose();
            _operation = null;
            RaiseAllSummary();
            RaiseCommandState();
        }
    }

    public async Task LookupHashAsync()
    {
        if (!CanLookupHash || CompletedScan is null || _virusTotalApiKey is null) return;
        var confirmed = await _interaction.ConfirmHashLookupAsync(
            CompletedScan.Sha256, VirusTotalDestination, CancellationToken.None).ConfigureAwait(true);
        if (!confirmed)
        {
            Reputation = HashReputationViewModel.From(new(
                HashReputationStatus.Skipped, CompletedScan.Sha256, 0, 0, 0, 0, null));
            return;
        }

        ReplaceOperation();
        _lookupActive = true;
        RaiseCommandState();
        try
        {
            var result = await _lookup.LookupAsync(
                CompletedScan.Sha256, _virusTotalApiKey, _operation!.Token).ConfigureAwait(true);
            Reputation = HashReputationViewModel.From(result);
        }
        catch (OperationCanceledException)
        {
            Reputation = HashReputationViewModel.From(new(
                HashReputationStatus.Skipped, CompletedScan.Sha256, 0, 0, 0, 0, null));
        }
        catch (Exception)
        {
            Reputation = HashReputationViewModel.From(new(
                HashReputationStatus.Failed, CompletedScan.Sha256, 0, 0, 0, 0, null));
        }
        finally
        {
            _lookupActive = false;
            _operation?.Dispose();
            _operation = null;
            RaiseCommandState();
        }
    }

    public async Task ExportAsync(ReportFormat format)
    {
        if (!CanExport || CompletedScan is null) return;
        var htmlName = HtmlReportWriter.SuggestFileName(CompletedScan.Result.SampleName);
        var suggested = format == ReportFormat.Html
            ? htmlName
            : htmlName[..^".html".Length] + ".json";
        var destination = _interaction.ChooseReportDestination(suggested, format);
        if (destination is null) return;
        destination = destination with
        {
            EvidenceMode = UseFullEvidence ? ReportEvidenceMode.Full : ReportEvidenceMode.Redacted
        };
        try
        {
            await _export.ExportAsync(
                CompletedScan.Result, destination, CancellationToken.None).ConfigureAwait(true);
            StatusMessage = "Report saved. voidlens did not open or preview it.";
        }
        catch (Exception)
        {
            StatusMessage = "The report could not be saved.";
        }
    }

    public void Cancel()
    {
        if (!CanCancel) return;
        if (_lookupActive)
        {
            StatusMessage = "Cancelling external reputation lookup…";
            _operation?.Cancel();
            RaiseCommandState();
            return;
        }
        State = ScanUiState.Cancelling;
        StatusMessage = "Cancelling analysis…";
        _operation?.Cancel();
        RaiseCommandState();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _virusTotalApiKey = null;
        _operation?.Cancel();
        _operation?.Dispose();
        _operation = null;
        GC.SuppressFinalize(this);
    }

    private void ReplaceOperation()
    {
        _operation?.Cancel();
        _operation?.Dispose();
        _operation = new CancellationTokenSource();
    }

    private void RaiseAllSummary()
    {
        OnPropertyChanged(nameof(AnalysisStatus));
        OnPropertyChanged(nameof(Completeness));
        OnPropertyChanged(nameof(RiskDisposition));
        OnPropertyChanged(nameof(Sha256));
        OnPropertyChanged(nameof(SignerState));
        OnPropertyChanged(nameof(StrongestEvidence));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanCancel));
        OnPropertyChanged(nameof(CanExport));
        OnPropertyChanged(nameof(CanLookupHash));
    }

    private void RaiseCommandState()
    {
        ((AsyncCommand)ScanCommand).RaiseCanExecuteChanged();
        ((DelegateCommand)CancelCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)LookupHashCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)ExportHtmlCommand).RaiseCanExecuteChanged();
        ((AsyncCommand)ExportJsonCommand).RaiseCanExecuteChanged();
        RaiseAllSummary();
    }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        OnPropertyChanged(propertyName);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private static int EvidenceRank(EvidenceStatus status) => status switch
    {
        EvidenceStatus.ConfirmedStaticImplementation => 0,
        EvidenceStatus.StrongStructuralEvidence => 1,
        EvidenceStatus.LinkedImplementation => 2,
        EvidenceStatus.ApiOrLibraryPresenceOnly => 3,
        EvidenceStatus.Heuristic => 4,
        _ => 5,
    };
}
