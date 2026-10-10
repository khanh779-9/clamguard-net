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

public sealed partial class MainViewModel
{
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

        var task = _tracker.Start("ApplyActions", LocalizationService.Instance.Get("tasks.apply_actions"), string.Empty);
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
            _tracker.Complete(task);
            OnPropertyChanged(nameof(ScanResultsSummaryText));
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public async Task InitializeAsync(CancellationToken token = default)
    {
        var task = _tracker.Start("Initialize", LocalizationService.Instance.Get("tasks.initializing"), string.Empty);
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
            _tracker.Complete(task);
        }
    }

    public async Task<ScanResult> ScanFileAsync(string file, CancellationToken token = default)
    {
        var task = _tracker.Start("ScanFile",
            LocalizationService.Instance.Format("scan.file_scan") + ": " + Path.GetFileName(file),
            file, isCancellable: true, token);
        task.TotalToScan = 1;
        task.Percent = 10;
        task.CurrentFile = file;
        task.ProgressText = LocalizationService.Instance.Format("scan.file_scan_desc");
        try
        {
            var result = await Task.Run(() => _engine.ScanFileAsync(file, task.Token), token).ConfigureAwait(true);
            task.ScannedCount = 1;
            task.Percent = 100;
            if (result.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator)
                task.ThreatsFound++;
            AddHistory(result, "File Scan");
            RefreshHealth();
            return result;
        }
        finally
        {
            task.ProgressText = LocalizationService.Instance.Get("scan.ready");
            SnapshotCompletedScan(task);
            _tracker.Complete(task);
        }
    }

    public async Task<IReadOnlyList<ScanResult>> ScanFolderAsync(string folder, CancellationToken token = default)
    {
        var task = _tracker.Start("ScanFolder",
            LocalizationService.Instance.Format("scan.folder_scan") + ": " + Path.GetFileName(folder),
            folder, isCancellable: true, token);
        task.CurrentFile = folder;
        var collected = new List<ScanResult>();
        var lastUiUpdateTicks = 0L;

        var progress = new Progress<ScanProgress>(p =>
        {
            if (p.Result is { } r)
            {
                collected.Add(r);
                if (r.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator)
                {
                    task.ThreatsFound++;
                    AddHistory(r, "Folder Scan");
                }
            }

            var nowTicks = Environment.TickCount64;
            var isFinal = p.Completed >= p.Total && p.Total > 0;
            // Throttle UI property changes to at most once every 60ms to prevent WPF Dispatcher starvation
            if (isFinal || nowTicks - lastUiUpdateTicks >= 60)
            {
                lastUiUpdateTicks = nowTicks;
                task.ScannedCount = p.Completed;
                task.TotalToScan = p.Total;
                task.CurrentFile = p.Path;
                task.Percent = p.Total > 0 ? Math.Min(100.0, (double)p.Completed / p.Total * 100.0) : 0;
                task.ProgressText = string.Format(CultureInfo.CurrentCulture, "{0:N0} / {1:N0} · {2}", p.Completed, p.Total, Path.GetFileName(p.Path));
            }
        });
        try
        {
            var results = await Task.Run(() => _engine.ScanFolderAsync(folder, progress, task.Token), token).ConfigureAwait(true);
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
            task.ProgressText = LocalizationService.Instance.Get("scan.ready");
            SnapshotCompletedScan(task);
            _tracker.Complete(task);
        }
    }

    public async Task<UpdateResult> UpdateDatabaseAsync(CancellationToken token = default)
    {
        var task = _tracker.Start("Update", LocalizationService.Instance.Get("update.database"), string.Empty, externalToken: token);
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
            _tracker.Complete(task);
        }
    }

}
