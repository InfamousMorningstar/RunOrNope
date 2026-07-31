using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using RunOrNope.App.Services;
using RunOrNope.App.ViewModels;
using RunOrNope.Broker.Windows;
using RunOrNope.Reporting;

namespace RunOrNope.App;

public partial class MainWindow : Window, IUserInteraction, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly MainViewModel _viewModel;
    private bool _disposed;

    public MainWindow()
    {
        InitializeComponent();
        _httpClient = VirusTotalHashLookup.CreateHttpClient();
        _viewModel = new MainViewModel(
            new ScanCoordinator(new WorkerBroker()),
            new ReportExportService(),
            new VirusTotalHashLookup(_httpClient),
            this);
        DataContext = _viewModel;
        Closed += OnClosed;
    }

    public string? ChooseSample()
    {
        var dialog = new OpenFileDialog
        {
            CheckFileExists = true,
            Multiselect = false,
            Title = "Choose a local PE or MSI for static analysis",
            Filter = "PE and MSI candidates|*.exe;*.dll;*.sys;*.msi|All files|*.*",
        };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }

    public ReportDestination? ChooseReportDestination(string suggestedName, ReportFormat format)
    {
        var dialog = new SaveFileDialog
        {
            FileName = suggestedName,
            AddExtension = true,
            DefaultExt = format == ReportFormat.Html ? ".html" : ".json",
            Filter = format == ReportFormat.Html ? "HTML report|*.html" : "JSON report|*.json",
            Title = "Save voidlens report",
        };
        return dialog.ShowDialog(this) == true
            ? new(dialog.FileName, format, ReportEvidenceMode.Redacted)
            : null;
    }

    public Task<bool> ConfirmHashLookupAsync(
        string sha256, Uri destination, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var message = $"Only this SHA-256 will be sent. The sample will not be uploaded.\n\n" +
                      $"SHA-256:\n{sha256}\n\nDestination:\n{destination.GetLeftPart(UriPartial.Authority)}";
        var result = MessageBox.Show(this, message, "Confirm hash-only VirusTotal lookup",
            MessageBoxButton.OKCancel, MessageBoxImage.Information, MessageBoxResult.Cancel);
        return Task.FromResult(result == MessageBoxResult.OK);
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        if (ChooseSample() is { } path) _viewModel.SelectPath(path);
    }

    private void OnVirusTotalPasswordChanged(object sender, RoutedEventArgs e) =>
        _viewModel.SetVirusTotalApiKey(((PasswordBox)sender).Password);

    private void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = HasSingleFile(e.Data) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (!HasSingleFile(e.Data)) return;
        var path = ((string[])e.Data.GetData(DataFormats.FileDrop)!)[0];
        if (File.Exists(path)) _viewModel.SelectPath(path);
    }

    private static bool HasSingleFile(IDataObject data) =>
        data.GetDataPresent(DataFormats.FileDrop) &&
        data.GetData(DataFormats.FileDrop) is string[] { Length: 1 } paths &&
        File.Exists(paths[0]);

    private void OnClosed(object? sender, EventArgs e)
        => Dispose();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        VirusTotalKey.Clear();
        _viewModel.Dispose();
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
