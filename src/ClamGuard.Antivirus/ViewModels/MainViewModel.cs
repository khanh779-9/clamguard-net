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
using ClamGuard.Database.Update;

namespace ClamGuard.Antivirus.ViewModels;

public sealed partial class MainViewModel : INotifyPropertyChanged
{
    private readonly AntivirusEngineService _engine;
    private readonly SystemInspectorService _systemInspector = new();
    private readonly QuarantineService _quarantine = new();
    private readonly ActiveTaskTracker _tracker = new();
    private int _lastCompletedScanned;
    private int _lastCompletedTotal;
    private int _lastCompletedThreats;
    private double _lastCompletedPercent;
    private string _lastCompletedFile = string.Empty;
    private string _lastCompletedText = string.Empty;
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

        _tracker.Changed += (_, _) => OnTrackerChanged();
        _tracker.ProgressChanged += (_, _) => OnTrackerChanged();

        QuickScanCommand = new RelayCommand(() => QuickScanRequested?.Invoke(this, EventArgs.Empty), () => DatabaseReady);
        CustomScanCommand = new RelayCommand(() => CustomScanRequested?.Invoke(this, EventArgs.Empty), () => DatabaseReady);
        UpdateCommand = new RelayCommand(() => UpdateRequested?.Invoke(this, EventArgs.Empty));
        ConfigureSecurityCommand = new RelayCommand(() => ConfigureSecurityRequested?.Invoke(this, EventArgs.Empty));
        OpenToolsCommand = new RelayCommand(() => OpenToolsRequested?.Invoke(this, EventArgs.Empty));
        ChangeDataLocationCommand = new RelayCommand(() => ChangeDataLocationRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        RealtimeFolderCommand = new RelayCommand(() => RealtimeFolderRequested?.Invoke(this, EventArgs.Empty));
        RealtimeToggleCommand = new RelayCommand(() => RealtimeToggleRequested?.Invoke(this, EventArgs.Empty));
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
        CancelScanCommand = new RelayCommand(() => CancelScanRequested?.Invoke(this, EventArgs.Empty), () => IsScanning);
        ApplyScanActionsCommand = new AsyncRelayCommand(ApplyScanActionsAsync, () => CurrentScanResults.Any(x => !x.IsProcessed));
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

    public bool IsBusy => _tracker.HasActiveTasks;
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
    public bool IsScanning => _tracker.HasActiveScans;
    private int _scannedCount;
    public int ScannedCount { get => _scannedCount; private set => SetField(ref _scannedCount, value); }
    private int _totalToScan;
    public int TotalToScan { get => _totalToScan; private set => SetField(ref _totalToScan, value); }
    private int _threatsDetectedCount;
    public int ThreatsDetectedCount { get => _threatsDetectedCount; private set => SetField(ref _threatsDetectedCount, value); }
    private string _currentScanningFile = string.Empty;
    public string CurrentScanningFile { get => _currentScanningFile; private set => SetField(ref _currentScanningFile, value); }
    private double _scanPercent;
    public double ScanPercent { get => _scanPercent; private set => SetField(ref _scanPercent, value); }
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

    public void CancelActiveScans() => _tracker.CancelScans();

    private void OnTrackerChanged()
    {
        UpdateScanAggregates();
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(IsScanning));
        OnPropertyChanged(nameof(BusyStatusText));
        CommandManager.InvalidateRequerySuggested();
    }

    private void UpdateScanAggregates()
    {
        var scans = _tracker.ActiveTasks.Where(t => t.IsScan).ToList();
        if (scans.Count > 0)
        {
            ScannedCount = scans.Sum(x => x.ScannedCount);
            TotalToScan = scans.Sum(x => x.TotalToScan);
            ThreatsDetectedCount = scans.Sum(x => x.ThreatsFound);
            ScanPercent = TotalToScan > 0 ? Math.Min(100.0, (double)ScannedCount / TotalToScan * 100.0) : 0;
            var latest = scans[^1];
            CurrentScanningFile = latest.CurrentFile;
            ScanProgressText = scans.Count > 1
                ? string.Format(CultureInfo.CurrentCulture, "{0} · {1}", LocalizationService.Instance.Format("tasks.running_multi", scans.Count), Path.GetFileName(latest.CurrentFile))
                : latest.ProgressText;
        }
        else
        {
            ScannedCount = _lastCompletedScanned;
            TotalToScan = _lastCompletedTotal;
            ThreatsDetectedCount = _lastCompletedThreats;
            ScanPercent = _lastCompletedPercent;
            CurrentScanningFile = _lastCompletedFile;
            ScanProgressText = _lastCompletedText;
        }
    }

    private void SnapshotCompletedScan(ActiveTaskItem task)
    {
        if (_tracker.ActiveTasks.Any(t => t.IsScan && !ReferenceEquals(t, task))) return;
        _lastCompletedScanned = task.ScannedCount;
        _lastCompletedTotal = task.TotalToScan;
        _lastCompletedThreats = task.ThreatsFound;
        _lastCompletedPercent = task.Percent;
        _lastCompletedFile = task.CurrentFile;
        _lastCompletedText = task.ProgressText;
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
        _lastCompletedText = string.Equals(_lastCompletedText, string.Empty, StringComparison.Ordinal)
            ? LocalizationService.Instance.Get("scan.ready")
            : _lastCompletedText;
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
