using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using ClamGuard.Antivirus.Controls;
using ClamGuard.Antivirus.Localization;
using ClamGuard.Antivirus.Models;
using ClamGuard.Antivirus.Services;
using ClamGuard.Antivirus.ViewModels;
using ClamGuard.Antivirus.Views;
using ClamGuard.Core;
using ClamGuard.Database.Update;

namespace ClamGuard.Antivirus;

public partial class MainWindow : ClamGuardWindow
{
    private readonly AntivirusEngineService _engine;
    private readonly RealtimeProtectionService _realtime;
    private readonly MainViewModel _viewModel;
    private readonly CancellationTokenSource _lifetimeCts = new();
    private int _updateRunning;
    private string _currentPage = "Overview";

    private OverviewView? _overviewView;
    private ScanView? _scanView;
    private UpdateView? _updateView;
    private SecurityView? _securityView;
    private HistoryView? _historyView;
    private QuarantineView? _quarantineView;
    private ToolsView? _toolsView;
    private SystemView? _systemView;
    private SettingsView? _settingsView;

    public MainWindow()
    {
        _engine = new AntivirusEngineService();
        _realtime = new RealtimeProtectionService(_engine);
        _viewModel = new MainViewModel(_engine);

        DataContext = _viewModel;
        InitializeComponent();

        _viewModel.QuickScanRequested += (_, _) => QuickScan();
        _viewModel.CustomScanRequested += (_, _) => CustomScan();
        _viewModel.SmartScanRequested += (_, _) => RunPathScanMode(
            () => _viewModel.SmartScanAsync(_lifetimeCts.Token),
            App.Localization.Get("scan.smart"),
            results => threatsToast(results));
        _viewModel.CriticalScanRequested += (_, _) => RunPathScanMode(
            () => _viewModel.CriticalScanAsync(_lifetimeCts.Token),
            App.Localization.Get("scan.critical"),
            results => threatsToast(results));
        _viewModel.MemoryScanRequested += (_, _) => MemoryScan();
        _viewModel.StartupScanRequested += (_, _) => RunPathScanMode(
            () => _viewModel.StartupScanAsync(_lifetimeCts.Token),
            App.Localization.Get("scan.startup"),
            results => threatsToast(results));
        _viewModel.CancelScanRequested += (_, _) => CancelActiveScan();
        _viewModel.UpdateRequested += (_, _) => Update();
        _viewModel.ConfigureSecurityRequested += (_, _) => Navigate("Security");
        _viewModel.OpenToolsRequested += (_, _) => Navigate("Tools");
        _viewModel.ChangeDataLocationRequested += (_, _) => ChangeDataLocation();
        _viewModel.RealtimeFolderRequested += (_, _) => RealtimeFolder();
        _viewModel.RealtimeToggleRequested += (_, _) => RealtimeToggle();
        _viewModel.DeleteHistoryRequested += (_, _) => DeleteHistory();
        _viewModel.ClearHistoryRequested += (_, _) => ClearHistory();
        _viewModel.ExportHistoryRequested += (_, _) => ExportHistory();
        _viewModel.NavigateHistoryRequested += (_, _) => Navigate("History");
        _viewModel.ToggleThemeRequested += (_, _) => ToggleTheme();
        _viewModel.InspectFileRequested += (_, _) => InspectFile();
        _viewModel.OpenWindowsSecurityRequested += (_, _) => OpenWindowsSecurity();
        _viewModel.QuarantineRequested += (_, item) => QuarantineItem(item);
        _viewModel.RestoreQuarantineRequested += (_, item) => RestoreQuarantineItem(item);
        _viewModel.DeleteQuarantineRequested += (_, item) => DeleteQuarantineItem(item);

        App.Localization.LanguageChanged += Localization_LanguageChanged;
        _realtime.ScanCompleted += Realtime_ScanCompleted;
        _realtime.Error += Realtime_Error;

        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;

        Navigate("Overview");
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        Loaded -= MainWindow_Loaded;
        await _viewModel.InitializeAsync(_lifetimeCts.Token);
        RestoreRealtimePath();
        _viewModel.RealtimeEnabled = false;
        Navigate("Overview");
    }

    private void Localization_LanguageChanged(object? sender, EventArgs e)
    {
        SetHeader(_currentPage);
        _settingsView?.RefreshTheme();
    }

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string page)
            Navigate(page);
    }

    private ClamGuardWindow Chrome => this;

    private void SyncNavRadio(string page)
    {
        switch (page)
        {
            case "Scan": if (NavScan != null) NavScan.IsChecked = true; break;
            case "Update": if (NavUpdate != null) NavUpdate.IsChecked = true; break;
            case "History": if (NavHistory != null) NavHistory.IsChecked = true; break;
            case "Quarantine": if (NavQuarantine != null) NavQuarantine.IsChecked = true; break;
            case "Tools": if (NavTools != null) NavTools.IsChecked = true; break;
            case "Settings": if (NavSettings != null) NavSettings.IsChecked = true; break;
            default: if (NavOverview != null) NavOverview.IsChecked = true; break;
        }
    }

    private void Navigate(string page)
    {
        _currentPage = page;
        SyncNavRadio(page);
        _viewModel.CurrentView = page switch
        {
            "Scan" => _scanView ??= new ScanView { DataContext = _viewModel },
            "Update" => _updateView ??= new UpdateView { DataContext = _viewModel },
            "Security" => _securityView ??= new SecurityView { DataContext = _viewModel },
            "History" => _historyView ??= new HistoryView { DataContext = _viewModel },
            "Quarantine" => _quarantineView ??= new QuarantineView { DataContext = _viewModel },
            "Tools" => _toolsView ??= new ToolsView { DataContext = _viewModel },
            "System" => _systemView ??= new SystemView { DataContext = _viewModel },
            "Settings" => _settingsView ??= new SettingsView { DataContext = _viewModel },
            _ => _overviewView ??= new OverviewView { DataContext = _viewModel }
        };

        SetHeader(page);
        if (string.Equals(page, "System", StringComparison.Ordinal))
            _ = _viewModel.RefreshSystemSnapshotAsync();
    }

    private void SetHeader(string page)
    {
        var key = page switch
        {
            "Scan" => "scan",
            "Update" => "update",
            "Security" => "security",
            "History" => "history",
            "Quarantine" => "quarantine",
            "Tools" => "tools",
            "System" => "system",
            "Settings" => "settings",
            _ => "overview"
        };
        _viewModel.HeaderTitle = App.Localization.Get($"header.{key}");
        _viewModel.HeaderSubtitle = App.Localization.Get($"header.{key}_sub");
    }

    private void CancelActiveScan()
    {
        try
        {
            _viewModel.CancelActiveScans();
        }
        catch { }
    }

    private async void QuickScan()
    {
        if (!_viewModel.DatabaseReady)
        {
            ShowToast(App.Localization.Get("toast.not_ready"), App.Localization.Get("toast.not_ready_body"), ToastKind.Warning);
            return;
        }

        var dialog = new OpenFileDialog { Title = App.Localization.Get("scan.select_file"), Filter = "All files|*.*", CheckFileExists = true };
        if (dialog.ShowDialog() != true) return;

        Navigate("Scan");
        _viewModel.IsShowingScanResults = false;

        try
        {
            var result = await _viewModel.ScanFileAsync(dialog.FileName, _lifetimeCts.Token);
            _viewModel.PopulateScanResults([result]);
            PresentScanResult(result, manual: true);
        }
        catch (OperationCanceledException)
        {
            _viewModel.PopulateScanResults([], App.Localization.Get("scan.cancelled"));
            ShowToast(App.Localization.Get("toast.scan_stopped"), App.Localization.Get("scan.cancelled"), ToastKind.Warning);
        }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("toast.scan_failed"), ex.Message, ToastKind.Error);
        }
    }

    private async void RunPathScanMode(Func<Task<IReadOnlyList<ScanResult>>> scan, string title, Action<IReadOnlyList<ScanResult>> reportToast)
    {
        if (!_viewModel.DatabaseReady)
        {
            ShowToast(App.Localization.Get("toast.not_ready"), App.Localization.Get("toast.not_ready_body"), ToastKind.Warning);
            return;
        }

        Navigate("Scan");
        _viewModel.IsShowingScanResults = false;
        try
        {
            var results = await scan();
            _viewModel.PopulateScanResults(results, title);
            reportToast(results);
        }
        catch (OperationCanceledException)
        {
            ShowToast(App.Localization.Get("toast.scan_stopped"), App.Localization.Get("scan.cancelled"), ToastKind.Warning);
        }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("toast.scan_failed"), ex.Message, ToastKind.Error);
        }
    }

    private void threatsToast(IReadOnlyList<ScanResult> results)
    {
        var threats = results.Count(x => x.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator);
        ShowToast(
            threats > 0 ? App.Localization.Get("toast.threats_found") : App.Localization.Get("toast.scan_finished"),
            threats > 0 ? App.Localization.Format("toast.threat_summary", results.Count, threats) : App.Localization.Format("toast.no_threats", results.Count),
            threats > 0 ? ToastKind.Error : ToastKind.Success);
    }

    private async void MemoryScan()
    {
        if (!_viewModel.DatabaseReady)
        {
            ShowToast(App.Localization.Get("toast.not_ready"), App.Localization.Get("toast.not_ready_body"), ToastKind.Warning);
            return;
        }

        Navigate("Scan");
        _viewModel.IsShowingScanResults = false;
        try
        {
            var results = await _viewModel.MemoryScanAsync(_lifetimeCts.Token);
            _viewModel.PopulateScanResults(results, App.Localization.Get("scan.memory"));
            threatsToast(results);
        }
        catch (OperationCanceledException)
        {
            ShowToast(App.Localization.Get("toast.scan_stopped"), App.Localization.Get("scan.cancelled"), ToastKind.Warning);
        }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("toast.scan_failed"), ex.Message, ToastKind.Error);
        }
    }

    private async void CustomScan()
    {
        if (!_viewModel.DatabaseReady)
        {
            ShowToast(App.Localization.Get("toast.not_ready"), App.Localization.Get("toast.not_ready_body"), ToastKind.Warning);
            return;
        }

        var dialog = new OpenFolderDialog { Title = App.Localization.Get("scan.select_folder") };
        if (dialog.ShowDialog() != true) return;

        Navigate("Scan");
        _viewModel.IsShowingScanResults = false;

        try
        {
            var results = await _viewModel.ScanFolderAsync(dialog.FolderName, _lifetimeCts.Token);
            _viewModel.PopulateScanResults(results);
            var threats = results.Count(x => x.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator);
            ShowToast(
                threats > 0 ? App.Localization.Get("toast.threats_found") : App.Localization.Get("toast.scan_finished"),
                threats > 0 ? App.Localization.Format("toast.threat_summary", results.Count, threats) : App.Localization.Format("toast.no_threats", results.Count),
                threats > 0 ? ToastKind.Error : ToastKind.Success);
        }
        catch (OperationCanceledException)
        {
            ShowToast(App.Localization.Get("toast.scan_stopped"), App.Localization.Get("scan.cancelled"), ToastKind.Warning);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ShowToast(App.Localization.Get("toast.scan_stopped"), ex.Message, ToastKind.Warning);
        }
    }

    private async void Update()
    {
        if (Interlocked.Exchange(ref _updateRunning, 1) != 0) return;
        ShowToast(App.Localization.Get("toast.updating"), App.Localization.Get("toast.update_body"), ToastKind.Info);
        try
        {
            var result = await _viewModel.UpdateDatabaseAsync(_lifetimeCts.Token);
            var kind = result.Status switch
            {
                UpdateStatus.Updated => ToastKind.Success,
                UpdateStatus.UpToDate => ToastKind.Info,
                _ => ToastKind.Warning
            };
            ShowToast(App.Localization.Get("toast.update"), result.Message, kind);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("toast.update_failed"), ex.Message, ToastKind.Error);
        }
        finally
        {
            Interlocked.Exchange(ref _updateRunning, 0);
        }
    }

    private async void ChangeDataLocation()
    {
        var dialog = new OpenFolderDialog { Title = App.Localization.Get("update.change_location") };
        if (dialog.ShowDialog() != true) return;

        var newDir = dialog.FolderName;
        var oldDir = _engine.DatabaseDirectory;
        var confirmed = await Chrome.ShowDialogAsync(
            App.Localization.Get("dialog.change_location"),
            App.Localization.Format("dialog.change_location_body", newDir),
            App.Localization.Get("dialog.change"),
            App.Localization.Get("common.cancel"),
            ToastKind.Warning);
        if (!confirmed) return;

        try
        {
            _engine.SetDatabaseDirectory(newDir);
            await _engine.ReloadDatabaseAsync(_lifetimeCts.Token);
            _viewModel.RefreshHealth();
            ShowToast(App.Localization.Get("toast.location_changed"), App.Localization.Get("toast.location_changed_body"), ToastKind.Success);
        }
        catch (Exception ex)
        {
            try
            {
                _engine.SetDatabaseDirectory(oldDir);
                await _engine.ReloadDatabaseAsync(_lifetimeCts.Token);
                _viewModel.RefreshHealth();
            }
            catch { }
            ShowToast(App.Localization.Get("toast.not_changed"), ex.Message, ToastKind.Error);
        }
    }

    private void RealtimeFolder()
    {
        var dialog = new OpenFolderDialog { Title = App.Localization.Get("security.choose_folder") };
        if (dialog.ShowDialog() != true) return;

        var dir = Path.GetFullPath(dialog.FolderName);
        App.Settings.RealtimeDirectory = dir;
        App.SaveSettings();
        _viewModel.RealtimePath = dir;

        if (_viewModel.RealtimeEnabled && _viewModel.DatabaseReady)
        {
            try
            {
                _realtime.Start(dir);
                ShowToast(App.Localization.Get("toast.folder_changed"), App.Localization.Get("toast.folder_changed_body"), ToastKind.Success);
            }
            catch (Exception ex)
            {
                _viewModel.RealtimeEnabled = false;
                ShowToast(App.Localization.Get("toast.not_ready"), ex.Message, ToastKind.Error);
            }
        }
    }

    private void RealtimeToggle()
    {
        try
        {
            if (_viewModel.RealtimeEnabled)
            {
                var dir = App.Settings.RealtimeDirectory;
                if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                {
                    _viewModel.RealtimeEnabled = false;
                    ShowToast(App.Localization.Get("toast.choose_folder_first"), App.Localization.Get("toast.choose_folder_first_body"), ToastKind.Warning);
                    return;
                }
                if (!_viewModel.DatabaseReady)
                {
                    _viewModel.RealtimeEnabled = false;
                    ShowToast(App.Localization.Get("toast.not_ready"), App.Localization.Get("toast.not_ready_body"), ToastKind.Warning);
                    return;
                }
                _realtime.Start(dir);
                _viewModel.RealtimePath = _realtime.WatchedDirectory ?? dir;
                ShowToast(App.Localization.Get("toast.realtime_on"), App.Localization.Get("toast.realtime_on_body"), ToastKind.Success);
            }
            else
            {
                _realtime.Stop();
                ShowToast(App.Localization.Get("toast.realtime_off"), App.Localization.Get("toast.realtime_off_body"), ToastKind.Info);
            }
        }
        catch (Exception ex)
        {
            _viewModel.RealtimeEnabled = false;
            ShowToast(App.Localization.Get("toast.realtime_error"), ex.Message, ToastKind.Error);
        }
    }

    private void DeleteHistory()
    {
        if (_historyView?.HistoryGrid.SelectedItem is not ScanHistoryItem item)
        {
            ShowToast(App.Localization.Get("toast.nothing_selected"), App.Localization.Get("toast.nothing_selected_body"), ToastKind.Warning);
            return;
        }
        _viewModel.RemoveHistory(item);
        ShowToast(App.Localization.Get("toast.deleted"), Path.GetFileName(item.FullPath), ToastKind.Info);
    }

    private async void ClearHistory()
    {
        if (_viewModel.RecentScans.Count == 0)
        {
            ShowToast(App.Localization.Get("common.info"), App.Localization.Get("common.no_scans"), ToastKind.Info);
            return;
        }

        var confirmed = await Chrome.ShowDialogAsync(
            App.Localization.Get("dialog.clear_history"),
            App.Localization.Get("dialog.clear_history_body"),
            App.Localization.Get("dialog.clear"),
            App.Localization.Get("common.cancel"),
            ToastKind.Warning);
        if (!confirmed) return;

        _viewModel.ClearReports();
        ShowToast(App.Localization.Get("toast.cleared"), App.Localization.Get("history.clear_all"), ToastKind.Success);
    }

    private void ExportHistory()
    {
        if (_viewModel.RecentScans.Count == 0)
        {
            ShowToast(App.Localization.Get("toast.nothing_export"), App.Localization.Get("toast.nothing_export_body"), ToastKind.Warning);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = App.Localization.Get("history.export"),
            Filter = "CSV files|*.csv|All files|*.*",
            FileName = $"clamguard-history-{DateTime.Now:yyyyMMdd-HHmm}.csv"
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            var csv = new StringBuilder();
            csv.AppendLine("Time,Kind,Target,Process,Result,Detections,DurationMs,Signature");
            foreach (var item in _viewModel.RecentScans)
            {
                csv.AppendLine(string.Join(",",
                    Csv(item.Time.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
                    Csv(item.Kind), Csv(item.FullPath), Csv(item.ProcessName), Csv(item.VerdictText),
                    Csv(item.DetectionCount.ToString(CultureInfo.InvariantCulture)),
                    Csv(item.Duration.TotalMilliseconds.ToString("N0", CultureInfo.InvariantCulture)),
                    Csv(item.PrimaryDetection ?? string.Empty)));
            }
            File.WriteAllText(dialog.FileName, csv.ToString(), Encoding.UTF8);
            ShowToast(App.Localization.Get("toast.exported"), dialog.FileName, ToastKind.Success);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowToast(App.Localization.Get("toast.export_failed"), ex.Message, ToastKind.Error);
        }
    }

    private void InspectFile()
    {
        var dialog = new OpenFileDialog { Title = App.Localization.Get("tools.inspect_file"), Filter = "All files|*.*", CheckFileExists = true };
        if (dialog.ShowDialog() != true) return;
        _ = InspectFileAsync(dialog.FileName);
    }

    private async Task InspectFileAsync(string path)
    {
        try
        {
            await _viewModel.InspectFileAsync(path);
            if (_viewModel.InspectedFile is not { } file) return;

            var details = string.Join("\n", [
                App.Localization.Format("tools.detail_name", file.Name),
                App.Localization.Format("tools.detail_size", file.SizeBytes),
                App.Localization.Format("tools.detail_modified", file.LastWriteTime),
                App.Localization.Format("tools.detail_version", file.Version),
                App.Localization.Format("tools.detail_company", file.Company),
                App.Localization.Format("tools.detail_product", file.Product),
                App.Localization.Format("tools.detail_signature", file.SignatureStatus),
                App.Localization.Format("tools.detail_sha256", file.Sha256)
            ]);
            await Chrome.ShowDialogAsync(App.Localization.Get("tools.file_inspector"), details,
                App.Localization.Get("common.close"), string.Empty, ToastKind.Info);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ShowToast(App.Localization.Get("toast.inspect_failed"), ex.Message, ToastKind.Error);
        }
    }

    private static void OpenWindowsSecurity()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("windowsdefender:") { UseShellExecute = true });
        }
        catch
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:windowsdefender") { UseShellExecute = true });
        }
    }

    private static string Csv(string value)
    {
        var escaped = "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        // Neutralize spreadsheet formula injection (=, +, -, @, tab/CR prefixes)
        // from attacker-controlled file/threat names opened in Excel.
        return escaped.Length > 1 && escaped[1] is '=' or '+' or '-' or '@' or '\t' or '\r'
            ? "\"'" + escaped[1..]
            : escaped;
    }

    private void RestoreRealtimePath()
        => _viewModel.RealtimePath = string.IsNullOrWhiteSpace(App.Settings.RealtimeDirectory)
            ? App.Localization.Get("security.choose_folder")
            : App.Settings.RealtimeDirectory!;

    private void Realtime_ScanCompleted(object? sender, ScanResult result)
    {
        Dispatcher.Invoke(() =>
        {
            _viewModel.AddHistory(result, "Real-time scan");
            PresentScanResult(result, manual: false);
        });
    }

    private void Realtime_Error(object? sender, string message)
        => Dispatcher.Invoke(() => ShowToast(App.Localization.Get("toast.realtime_error"), message, ToastKind.Warning));

}
