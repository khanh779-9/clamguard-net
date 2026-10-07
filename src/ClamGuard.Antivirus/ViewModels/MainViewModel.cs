using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ClamGuard.Antivirus.Localization;
using ClamGuard.Antivirus.Models;
using ClamGuard.Antivirus.Services;
using ClamGuard.Core;
using ClamGuard.Update;

namespace ClamGuard.Antivirus.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly AntivirusEngineService _engine;
    private readonly SystemInspectorService _systemInspector = new();
    private readonly QuarantineService _quarantine = new();
    private bool _isBusy;
    private bool _isSystemBusy;
    private string _statusTitle = string.Empty;
    private string _statusDescription = string.Empty;
    private bool _databaseReady;
    private uint? _databaseVersion;
    private int _signatureCount;
    private string _databaseSummary = string.Empty;
    private string _databasePath = string.Empty;
    private bool _realtimeEnabled;
    private string _realtimePath = string.Empty;
    private string _scanProgressText = string.Empty;
    private int _cleanReports;
    private int _threatReports;
    private string _lastUpdateText = string.Empty;
    private string _headerTitle = string.Empty;
    private string _headerSubtitle = string.Empty;
    private object? _currentView;
    private string _systemOperatingSystem = string.Empty;
    private string _systemArchitecture = string.Empty;
    private int _systemLogicalProcessors;
    private double _systemTotalMemoryGb;
    private double _systemAvailableMemoryGb;
    private TimeSpan _systemUptime;
    private string _systemStorageSummary = string.Empty;
    private bool _systemIsAdministrator;
    private FileInspectionResult? _inspectedFile;
    private QuarantineItem? _selectedQuarantineItem;

    public MainViewModel(AntivirusEngineService engine)
    {
        _engine = engine;
        RefreshLocalizedUi();
        LocalizationService.Instance.LanguageChanged += (_, _) => RefreshLocalizedUi();

        QuickScanCommand = new RelayCommand(() => QuickScanRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy && DatabaseReady);
        CustomScanCommand = new RelayCommand(() => CustomScanRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy && DatabaseReady);
        UpdateCommand = new RelayCommand(() => UpdateRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        ConfigureSecurityCommand = new RelayCommand(() => ConfigureSecurityRequested?.Invoke(this, EventArgs.Empty));
        OpenToolsCommand = new RelayCommand(() => OpenToolsRequested?.Invoke(this, EventArgs.Empty));
        ChangeDataLocationCommand = new RelayCommand(() => ChangeDataLocationRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        RealtimeFolderCommand = new RelayCommand(() => RealtimeFolderRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        RealtimeToggleCommand = new RelayCommand(() => RealtimeToggleRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        DeleteHistoryCommand = new RelayCommand(() => DeleteHistoryRequested?.Invoke(this, EventArgs.Empty), () => HasReports);
        ClearHistoryCommand = new RelayCommand(() => ClearHistoryRequested?.Invoke(this, EventArgs.Empty), () => HasReports);
        ExportHistoryCommand = new RelayCommand(() => ExportHistoryRequested?.Invoke(this, EventArgs.Empty), () => HasReports);
        NavigateHistoryCommand = new RelayCommand(() => NavigateHistoryRequested?.Invoke(this, EventArgs.Empty));
        ToggleThemeCommand = new RelayCommand(() => ToggleThemeRequested?.Invoke(this, EventArgs.Empty));
        RefreshSystemCommand = new AsyncRelayCommand(RefreshSystemSnapshotAsync, () => !IsSystemBusy);
        InspectFileCommand = new RelayCommand(() => InspectFileRequested?.Invoke(this, EventArgs.Empty), () => !IsSystemBusy);
        OpenWindowsSecurityCommand = new RelayCommand(() => OpenWindowsSecurityRequested?.Invoke(this, EventArgs.Empty));
        QuarantineCommand = new ParameterRelayCommand<QuarantineItem>(item => QuarantineRequested?.Invoke(this, item));
        RestoreQuarantineCommand = new ParameterRelayCommand<QuarantineItem>(item => RestoreQuarantineRequested?.Invoke(this, item));
        DeleteQuarantineCommand = new ParameterRelayCommand<QuarantineItem>(item => DeleteQuarantineRequested?.Invoke(this, item));
        RestoreSelectedQuarantineCommand = new RelayCommand(() => { if (SelectedQuarantineItem is { } item) RestoreQuarantineRequested?.Invoke(this, item); }, () => SelectedQuarantineItem is not null);
        DeleteSelectedQuarantineCommand = new RelayCommand(() => { if (SelectedQuarantineItem is { } item) DeleteQuarantineRequested?.Invoke(this, item); }, () => SelectedQuarantineItem is not null);
        RefreshQuarantineCommand = new RelayCommand(RefreshQuarantine);
        CancelScanCommand = new RelayCommand(() => CancelScanRequested?.Invoke(this, EventArgs.Empty), () => IsBusy);
        ApplyScanActionsCommand = new AsyncRelayCommand(ApplyScanActionsAsync, () => !IsBusy && CurrentScanResults.Any(x => !x.IsProcessed));
        BackToScanCommand = new RelayCommand(() => IsShowingScanResults = false);
    }

    public event EventHandler? QuickScanRequested;
    public event EventHandler? CustomScanRequested;
    public event EventHandler? CancelScanRequested;
    public event EventHandler? UpdateRequested;
    public event EventHandler? ConfigureSecurityRequested;
    public event EventHandler? OpenToolsRequested;
    public event EventHandler? ChangeDataLocationRequested;
    public event EventHandler? RealtimeFolderRequested;
    public event EventHandler? RealtimeToggleRequested;
    public event EventHandler? DeleteHistoryRequested;
    public event EventHandler? ClearHistoryRequested;
    public event EventHandler? ExportHistoryRequested;
    public event EventHandler? NavigateHistoryRequested;
    public event EventHandler? ToggleThemeRequested;
    public event EventHandler? InspectFileRequested;
    public event EventHandler? OpenWindowsSecurityRequested;
    public event EventHandler<QuarantineItem>? QuarantineRequested;
    public event EventHandler<QuarantineItem>? RestoreQuarantineRequested;
    public event EventHandler<QuarantineItem>? DeleteQuarantineRequested;

    public ICommand QuickScanCommand { get; }
    public ICommand CustomScanCommand { get; }
    public ICommand UpdateCommand { get; }
    public ICommand ConfigureSecurityCommand { get; }
    public ICommand OpenToolsCommand { get; }
    public ICommand ChangeDataLocationCommand { get; }
    public ICommand RealtimeFolderCommand { get; }
    public ICommand RealtimeToggleCommand { get; }
    public ICommand DeleteHistoryCommand { get; }
    public ICommand ClearHistoryCommand { get; }
    public ICommand ExportHistoryCommand { get; }
    public ICommand NavigateHistoryCommand { get; }
    public ICommand ToggleThemeCommand { get; }
    public ICommand RefreshSystemCommand { get; }
    public ICommand InspectFileCommand { get; }
    public ICommand OpenWindowsSecurityCommand { get; }
    public ICommand QuarantineCommand { get; }
    public ICommand RestoreQuarantineCommand { get; }
    public ICommand DeleteQuarantineCommand { get; }
    public ICommand RestoreSelectedQuarantineCommand { get; }
    public ICommand DeleteSelectedQuarantineCommand { get; }
    public ICommand RefreshQuarantineCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand ApplyScanActionsCommand { get; }
    public ICommand BackToScanCommand { get; }

    public ObservableCollection<ScanResultRowItem> CurrentScanResults { get; } = [];
    public ObservableCollection<ScanHistoryItem> RecentScans { get; } = [];
    public ObservableCollection<ProcessSnapshotItem> RunningProcesses { get; } = [];
    public ObservableCollection<StartupSnapshotItem> StartupItems { get; } = [];
    public ObservableCollection<NetworkSnapshotItem> NetworkAdapters { get; } = [];
    public ObservableCollection<DriveSnapshotItem> Drives { get; } = [];
    public ObservableCollection<QuarantineItem> QuarantineItems { get; } = [];

    public bool IsBusy {
        get => _isBusy;
        private set { if (SetField(ref _isBusy, value)) { OnPropertyChanged(nameof(BusyStatusText)); } }
    }
    public bool IsSystemBusy { get => _isSystemBusy; private set => SetField(ref _isSystemBusy, value); }
    public string StatusTitle { get => _statusTitle; private set => SetField(ref _statusTitle, value); }
    public string StatusDescription { get => _statusDescription; private set => SetField(ref _statusDescription, value); }
    public bool DatabaseReady {
        get => _databaseReady;
        private set { if (SetField(ref _databaseReady, value)) { OnPropertyChanged(nameof(DatabaseStatusText)); } }
    }
    public uint? DatabaseVersion { get => _databaseVersion; private set => SetField(ref _databaseVersion, value); }
    public int SignatureCount { get => _signatureCount; private set => SetField(ref _signatureCount, value); }
    public string DatabaseSummary { get => _databaseSummary; private set => SetField(ref _databaseSummary, value); }
    public string DatabasePath { get => _databasePath; private set => SetField(ref _databasePath, value); }
    public bool RealtimeEnabled {
        get => _realtimeEnabled;
        set { if (SetField(ref _realtimeEnabled, value)) { OnPropertyChanged(nameof(RealtimeStatusText)); } }
    }
    public string RealtimePath { get => _realtimePath; set => SetField(ref _realtimePath, value); }
    private bool _isScanning;
    public bool IsScanning { get => _isScanning; private set => SetField(ref _isScanning, value); }
    private int _scannedCount;
    public int ScannedCount { get => _scannedCount; private set => SetField(ref _scannedCount, value); }
    private int _totalToScan;
    public int TotalToScan { get => _totalToScan; private set => SetField(ref _totalToScan, value); }
    private int _threatsDetectedCount;
    public int ThreatsDetectedCount { get => _threatsDetectedCount; private set => SetField(ref _threatsDetectedCount, value); }
    private string _currentScanningFile = string.Empty;
    public string CurrentScanningFile { get => _currentScanningFile; private set => SetField(ref _currentScanningFile, value); }
    private double _scanPercent;
    public double ScanPercent { get => _scanPercent; set => SetField(ref _scanPercent, value); }
    public string ScanProgressText { get => _scanProgressText; set => SetField(ref _scanProgressText, value); }
    public string LastUpdateText { get => _lastUpdateText; private set => SetField(ref _lastUpdateText, value); }
    public string HeaderTitle { get => _headerTitle; set => SetField(ref _headerTitle, value); }
    public string HeaderSubtitle { get => _headerSubtitle; set => SetField(ref _headerSubtitle, value); }
    public object? CurrentView { get => _currentView; set => SetField(ref _currentView, value); }
    public bool HasReports => RecentScans.Count > 0;
    public int TotalReports => RecentScans.Count;
    public int CleanReports { get => _cleanReports; private set => SetField(ref _cleanReports, value); }
    public int ThreatReports { get => _threatReports; private set => SetField(ref _threatReports, value); }
    public string LastScanText => RecentScans.Count == 0 ? LocalizationService.Instance.Get("common.no_scans") : RecentScans[0].Time.LocalDateTime.ToString("g");

    public string Language
    {
        get => App.Settings.Language;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(App.Settings.Language, value, StringComparison.OrdinalIgnoreCase)) return;
            App.Settings.Language = value;
            LocalizationService.Instance.Apply(value);
            App.SaveSettings();
            OnPropertyChanged();
        }
    }

    public string Theme
    {
        get => App.Settings.Theme;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(App.Settings.Theme, value, StringComparison.OrdinalIgnoreCase)) return;
            App.Theme.Apply(value);
            App.SaveSettings();
            OnPropertyChanged();
        }
    }

    public string ScanThreatAction
    {
        get => App.Settings.ScanThreatAction;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(App.Settings.ScanThreatAction, value, StringComparison.OrdinalIgnoreCase)) return;
            App.Settings.ScanThreatAction = value;
            App.SaveSettings();
            OnPropertyChanged();
        }
    }

    public string RealtimeThreatAction
    {
        get => App.Settings.RealtimeThreatAction;
        set
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(App.Settings.RealtimeThreatAction, value, StringComparison.OrdinalIgnoreCase)) return;
            App.Settings.RealtimeThreatAction = value;
            App.SaveSettings();
            OnPropertyChanged();
        }
    }

    public string SystemOperatingSystem { get => _systemOperatingSystem; private set => SetField(ref _systemOperatingSystem, value); }
    public string SystemArchitecture { get => _systemArchitecture; private set => SetField(ref _systemArchitecture, value); }
    public int SystemLogicalProcessors { get => _systemLogicalProcessors; private set => SetField(ref _systemLogicalProcessors, value); }
    public string SystemMemoryText => $"{_systemAvailableMemoryGb:N1} / {_systemTotalMemoryGb:N1} GB";
    public string SystemUptimeText => FormatDuration(_systemUptime);
    public string SystemStorageSummary { get => _systemStorageSummary; private set => SetField(ref _systemStorageSummary, value); }
    public bool SystemIsAdministrator { get => _systemIsAdministrator; private set => SetField(ref _systemIsAdministrator, value); }
    public string SystemPrivilegeText => LocalizationService.Instance.Get(SystemIsAdministrator ? "system.administrator" : "system.standard_user");
    public string DatabaseStatusText => LocalizationService.Instance.Get(DatabaseReady ? "common.ready" : "common.not_ready");
    public string RealtimeStatusText => LocalizationService.Instance.Get(RealtimeEnabled ? "common.on" : "common.off");
    public string BusyStatusText => LocalizationService.Instance.Get(IsBusy ? "common.working" : "common.ready");
    public FileInspectionResult? InspectedFile { get => _inspectedFile; private set => SetField(ref _inspectedFile, value); }
    public QuarantineItem? SelectedQuarantineItem { get => _selectedQuarantineItem; set { if (SetField(ref _selectedQuarantineItem, value)) CommandManager.InvalidateRequerySuggested(); } }

    private bool _isShowingScanResults;
    public bool IsShowingScanResults
    {
        get => _isShowingScanResults;
        set
        {
            if (SetField(ref _isShowingScanResults, value))
            {
                OnPropertyChanged(nameof(ScanResultsSummaryText));
            }
        }
    }

    private string _scanResultsTitle = string.Empty;
    public string ScanResultsTitle
    {
        get => string.IsNullOrEmpty(_scanResultsTitle) ? LocalizationService.Instance.Get("scan.results_title") : _scanResultsTitle;
        set => SetField(ref _scanResultsTitle, value);
    }

    public string ScanResultsSummaryText
    {
        get
        {
            var total = CurrentScanResults.Count;
            var threats = CurrentScanResults.Count(x => x.IsThreat);
            var mitigated = CurrentScanResults.Count(x => x.IsProcessed && x.IsThreat);
            return LocalizationService.Instance.Format("scan.results_summary", total, threats, mitigated);
        }
    }

    private ScanResultRowItem? _selectedScanResult;
    public ScanResultRowItem? SelectedScanResult
    {
        get => _selectedScanResult;
        set => SetField(ref _selectedScanResult, value);
    }

    public void PopulateScanResults(IEnumerable<ScanResult> results, string? customTitle = null)
    {
        CurrentScanResults.Clear();
        if (!string.IsNullOrWhiteSpace(customTitle))
            ScanResultsTitle = customTitle;
        else
            ScanResultsTitle = LocalizationService.Instance.Get("scan.results_title");

        var defaultAction = ScanThreatAction switch
        {
            "Quarantine" => ThreatResolutionAction.Quarantine,
            "Delete" => ThreatResolutionAction.Delete,
            "Ignore" => ThreatResolutionAction.Ignore,
            _ => ThreatResolutionAction.Quarantine
        };

        foreach (var r in results)
        {
            var isThreat = r.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator;
            var threatName = r.Detections.FirstOrDefault()?.Name ?? (isThreat ? "Threat" : string.Empty);
            var item = new ScanResultRowItem
            {
                FilePath = r.FilePath,
                Verdict = r.Verdict,
                ThreatName = threatName,
                Duration = r.Duration,
                SelectedAction = defaultAction,
                Status = isThreat ? LocalizationService.Instance.Get("scan.status_pending") : LocalizationService.Instance.Get("scan.status_done"),
                IsProcessed = !isThreat
            };
            CurrentScanResults.Add(item);
        }
        IsShowingScanResults = true;
        OnPropertyChanged(nameof(ScanResultsSummaryText));
        CommandManager.InvalidateRequerySuggested();
    }

    public async Task ApplyScanActionsAsync()
    {
        var pendingItems = CurrentScanResults.Where(x => x.IsThreat && !x.IsProcessed).ToList();
        if (pendingItems.Count == 0) return;

        IsBusy = true;
        try
        {
            foreach (var item in pendingItems)
            {
                try
                {
                    switch (item.SelectedAction)
                    {
                        case ThreatResolutionAction.Quarantine:
                            await QuarantineFileAsync(item.FilePath, item.ThreatName);
                            item.Status = LocalizationService.Instance.Get("scan.status_done");
                            item.IsProcessed = true;
                            break;
                        case ThreatResolutionAction.Delete:
                            if (File.Exists(item.FilePath)) File.Delete(item.FilePath);
                            item.Status = LocalizationService.Instance.Get("scan.status_done");
                            item.IsProcessed = true;
                            break;
                        case ThreatResolutionAction.Ignore:
                            item.Status = LocalizationService.Instance.Get("scan.act_ignore");
                            item.IsProcessed = true;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    item.Status = LocalizationService.Instance.Get("scan.status_failed") + ": " + ex.Message;
                }
            }
            RefreshQuarantine();
            RefreshHealth();
            OnPropertyChanged(nameof(ScanResultsSummaryText));
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(ScanResultsSummaryText));
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public async Task InitializeAsync(CancellationToken token = default)
    {
        IsBusy = true;
        StatusTitle = LocalizationService.Instance.Get("nav.engine");
        StatusDescription = LocalizationService.Instance.Get("overview.loading_db");
        try
        {
            await _engine.InitializeAsync(token);
            RefreshHealth();
            SetProtectionStatus();
            RefreshQuarantine();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException or UnauthorizedAccessException)
        {
            DatabaseReady = false;
            StatusTitle = LocalizationService.Instance.Get("nav.not_ready");
            StatusDescription = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task<ScanResult> ScanFileAsync(string file, CancellationToken token = default)
    {
        IsBusy = true;
        IsScanning = true;
        ScannedCount = 0;
        TotalToScan = 1;
        ThreatsDetectedCount = 0;
        ScanPercent = 10;
        CurrentScanningFile = file;
        ScanProgressText = LocalizationService.Instance.Format("scan.file_scan_desc");
        try
        {
            var result = await Task.Run(() => _engine.ScanFileAsync(file, token), token).ConfigureAwait(true);
            ScannedCount = 1;
            ScanPercent = 100;
            if (result.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator) ThreatsDetectedCount++;
            AddHistory(result, "File Scan");
            RefreshHealth();
            return result;
        }
        finally
        {
            IsScanning = false;
            IsBusy = false;
            ScanProgressText = LocalizationService.Instance.Get("scan.ready");
        }
    }

    public async Task<IReadOnlyList<ScanResult>> ScanFolderAsync(string folder, CancellationToken token = default)
    {
        IsBusy = true;
        IsScanning = true;
        ScannedCount = 0;
        TotalToScan = 0;
        ThreatsDetectedCount = 0;
        ScanPercent = 0;
        CurrentScanningFile = folder;
        var collected = new List<ScanResult>();
        var lastUiUpdateTicks = 0L;

        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.Result is { } r)
            {
                collected.Add(r);
                if (r.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator)
                {
                    ThreatsDetectedCount++;
                    AddHistory(r, "Folder Scan");
                }
            }

            var nowTicks = Environment.TickCount64;
            var isFinal = p.Completed >= p.Total && p.Total > 0;
            // Throttle UI property changes to at most once every 60ms to prevent WPF Dispatcher starvation
            if (isFinal || nowTicks - lastUiUpdateTicks >= 60)
            {
                lastUiUpdateTicks = nowTicks;
                ScannedCount = p.Completed;
                TotalToScan = p.Total;
                CurrentScanningFile = p.Path;
                ScanPercent = p.Total > 0 ? Math.Min(100.0, (double)p.Completed / p.Total * 100.0) : 0;
                ScanProgressText = string.Format(CultureInfo.CurrentCulture, "{0:N0} / {1:N0} · {2}", p.Completed, p.Total, Path.GetFileName(p.Path));
            }
        });
        try
        {
            var results = await Task.Run(() => _engine.ScanFolderAsync(folder, progress, token), token).ConfigureAwait(true);
            RefreshHealth();
            return results;
        }
        catch (OperationCanceledException)
        {
            PopulateScanResults(collected, LocalizationService.Instance.Get("scan.cancelled"));
            RefreshHealth();
            throw;
        }
        finally
        {
            IsScanning = false;
            IsBusy = false;
            ScanProgressText = LocalizationService.Instance.Get("scan.ready");
        }
    }

    public async Task<UpdateResult> UpdateDatabaseAsync(CancellationToken token = default)
    {
        IsBusy = true;
        StatusTitle = LocalizationService.Instance.Get("update.database");
        StatusDescription = LocalizationService.Instance.Get("update.keep_current");
        try
        {
            var result = await _engine.UpdateDatabaseAsync(token);
            RefreshHealth();
            SetProtectionStatus(result.Message);
            DatabasePath = _engine.DatabaseDirectory;
            return result;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void RefreshHealth()
    {
        var health = _engine.Health;
        DatabaseReady = health.Healthy;
        SignatureCount = health.SignatureCount;
        var current = health.DatabaseGeneration;
        DatabaseSummary = LocalizationService.Instance.Format("tools.summary") + $": " +
                         LocalizationService.Instance.Format("tools.database_files", health.DatabaseCount) + " · " +
                         LocalizationService.Instance.Format("tools.database_signatures", health.SignatureCount) + " · " +
                         LocalizationService.Instance.Format("tools.database_generation", current);
        DatabasePath = _engine.DatabaseDirectory;
        DatabaseVersion = _engine.CurrentDatabase?.Version;
        LastUpdateText = ResolveLastUpdate();
    }

    public async Task RefreshSystemSnapshotAsync()
    {
        IsSystemBusy = true;
        try
        {
            var snapshot = await Task.Run(() => _systemInspector.Capture());
            SystemOperatingSystem = snapshot.OperatingSystem;
            SystemArchitecture = snapshot.Architecture;
            SystemLogicalProcessors = snapshot.LogicalProcessors;
            _systemTotalMemoryGb = snapshot.TotalMemoryGb;
            _systemAvailableMemoryGb = snapshot.AvailableMemoryGb;
            _systemUptime = snapshot.Uptime;
            SystemIsAdministrator = _systemInspector.IsAdministrator();
            SystemStorageSummary = string.Join("  ·  ", snapshot.Drives.Select(x => $"{x.Name} {x.UsedGb:N0}/{x.TotalGb:N0} GB"));
            Replace(RunningProcesses, snapshot.Processes);
            Replace(StartupItems, snapshot.StartupItems);
            Replace(NetworkAdapters, snapshot.Networks);
            Replace(Drives, snapshot.Drives);
            OnPropertyChanged(nameof(SystemMemoryText));
            OnPropertyChanged(nameof(SystemUptimeText));
            OnPropertyChanged(nameof(SystemPrivilegeText));
        }
        finally
        {
            IsSystemBusy = false;
        }
    }

    public async Task InspectFileAsync(string file)
    {
        IsSystemBusy = true;
        try
        {
            InspectedFile = await Task.Run(() => _systemInspector.InspectFile(file));
        }
        finally
        {
            IsSystemBusy = false;
        }
    }

    public void RefreshQuarantine()
    {
        Replace(QuarantineItems, _quarantine.GetItems());
    }

    private void Replace<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();
        foreach (var item in items) target.Add(item);
    }

    private string ResolveLastUpdate()
    {
        try
        {
            var directory = _engine.DatabaseDirectory;
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
                return LocalizationService.Instance.Get("common.not_installed");

            DateTimeOffset? latest = null;
            foreach (var file in Directory.EnumerateFiles(directory))
            {
                var write = File.GetLastWriteTimeUtc(file);
                if (latest is null || write > latest.Value.UtcDateTime)
                    latest = write;
            }
            return latest is null ? LocalizationService.Instance.Get("common.not_installed") : latest.Value.ToLocalTime().ToString("g");
        }
        catch (IOException) { return LocalizationService.Instance.Get("common.not_installed"); }
        catch (UnauthorizedAccessException) { return LocalizationService.Instance.Get("common.not_installed"); }
    }

    public void AddHistory(ScanResult result, string kind = "File Scan")
    {
        if (RecentScans.Any(x => string.Equals(x.FullPath, result.FilePath, StringComparison.OrdinalIgnoreCase) && x.Time > DateTimeOffset.Now.AddSeconds(-1)))
            return;

        RecentScans.Insert(0, ScanHistoryItem.FromResult(result, kind));
        while (RecentScans.Count > 100)
            RecentScans.RemoveAt(RecentScans.Count - 1);

        RecountReports();
        OnPropertyChanged(nameof(HasReports));
        OnPropertyChanged(nameof(TotalReports));
        OnPropertyChanged(nameof(LastScanText));
        OnPropertyChanged(nameof(SystemPrivilegeText));
        OnPropertyChanged(nameof(DatabaseStatusText));
        OnPropertyChanged(nameof(RealtimeStatusText));
        OnPropertyChanged(nameof(BusyStatusText));
    }

    public void RemoveHistory(ScanHistoryItem item)
    {
        if (!RecentScans.Remove(item)) return;
        RecountReports();
        OnPropertyChanged(nameof(HasReports));
        OnPropertyChanged(nameof(TotalReports));
        OnPropertyChanged(nameof(LastScanText));
    }

    public void ClearReports()
    {
        RecentScans.Clear();
        RecountReports();
        OnPropertyChanged(nameof(HasReports));
        OnPropertyChanged(nameof(TotalReports));
        OnPropertyChanged(nameof(LastScanText));
    }

    private void RecountReports()
    {
        CleanReports = RecentScans.Count(x => x.IsClean);
        ThreatReports = RecentScans.Count(x => x.IsThreat);
    }

    private void RefreshLocalizedUi()
    {
        HeaderTitle = string.IsNullOrWhiteSpace(HeaderTitle) ? LocalizationService.Instance.Get("header.overview") : HeaderTitle;
        if (HeaderSubtitle.Length == 0) HeaderSubtitle = LocalizationService.Instance.Get("header.overview_sub");
        ScanProgressText = string.IsNullOrEmpty(ScanProgressText) ? LocalizationService.Instance.Get("scan.ready") : ScanProgressText;
        RealtimePath = string.IsNullOrEmpty(RealtimePath) ? LocalizationService.Instance.Get("security.choose_folder") : RealtimePath;
        LastUpdateText = string.IsNullOrEmpty(LastUpdateText) ? LocalizationService.Instance.Get("common.not_installed") : LastUpdateText;
        SetProtectionStatus();
        OnPropertyChanged(nameof(LastScanText));
        OnPropertyChanged(nameof(SystemPrivilegeText));
        OnPropertyChanged(nameof(DatabaseStatusText));
        OnPropertyChanged(nameof(RealtimeStatusText));
        OnPropertyChanged(nameof(BusyStatusText));
    }

    private void SetProtectionStatus(string? message = null)
    {
        StatusTitle = DatabaseReady
            ? "ClamGuard · " + LocalizationService.Instance.Get("nav.ready")
            : LocalizationService.Instance.Get("nav.not_ready");
        StatusDescription = message ?? (DatabaseReady
            ? LocalizationService.Instance.Get("overview.quick_scan") + " · " + LocalizationService.Instance.Get("overview.realtime_desc")
            : LocalizationService.Instance.Get("scan.file_scan_desc"));
    }

    public Task<QuarantineItem> QuarantineFileAsync(string path, string detection, CancellationToken token = default)
        => _quarantine.QuarantineAsync(path, detection, token);

    public void RestoreQuarantineItem(QuarantineItem item) => _quarantine.Restore(item);
    public void DeleteQuarantineItem(QuarantineItem item) => _quarantine.Delete(item);

    private static string FormatDuration(TimeSpan value)
    {
        if (value.TotalDays >= 1)
            return string.Join(" ", [
                LocalizationService.Instance.Format("common.days", (int)value.TotalDays),
                LocalizationService.Instance.Format("common.hours", value.Hours),
                LocalizationService.Instance.Format("common.minutes", value.Minutes)]);
        if (value.TotalHours >= 1)
            return string.Join(" ", [
                LocalizationService.Instance.Format("common.hours", (int)value.TotalHours),
                LocalizationService.Instance.Format("common.minutes", value.Minutes)]);
        return string.Join(" ", [
            LocalizationService.Instance.Format("common.minutes", value.Minutes),
            LocalizationService.Instance.Format("common.seconds", value.Seconds)]);
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public event PropertyChangedEventHandler? PropertyChanged;
}

internal sealed class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;
    public void Execute(object? parameter) => _execute();

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

internal sealed class ParameterRelayCommand<T> : ICommand
{
    private readonly Action<T> _execute;
    private readonly Func<bool>? _canExecute;

    public ParameterRelayCommand(Action<T> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => parameter is T && (_canExecute?.Invoke() ?? true);
    public void Execute(object? parameter)
    {
        if (parameter is T value) _execute(value);
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

internal sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private int _running;

    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _running == 0 && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0) return;
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        try { await _execute(); }
        catch { /* UI caller owns user-facing error policy. */ }
        finally
        {
            Volatile.Write(ref _running, 0);
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public event EventHandler? CanExecuteChanged;
}
