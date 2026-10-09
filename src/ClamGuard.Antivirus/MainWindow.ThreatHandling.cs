using System.Globalization;
using System.IO;
using System.Text;
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

public partial class MainWindow
{
    private void PresentScanResult(ScanResult result, bool manual)
    {
        var dangerous = result.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator;
        var kind = dangerous ? ToastKind.Error : result.Verdict == ScanVerdict.Clean ? ToastKind.Success : ToastKind.Warning;
        var title = dangerous ? App.Localization.Get("toast.threat_found") : result.Verdict switch
        {
            ScanVerdict.Clean => App.Localization.Get("toast.file_clean"),
            ScanVerdict.Trusted => App.Localization.Get("toast.file_clean"),
            _ => App.Localization.Get("toast.scan_finished")
        };
        var subject = manual ? App.Localization.Get("toast.scan") : App.Localization.Get("toast.realtime");
        var message = result.Detections.Count > 0
            ? $"{subject}: {result.Detections[0].Name} · {Path.GetFileName(result.FilePath)}"
            : $"{subject}: {Path.GetFileName(result.FilePath)} · {result.Duration.TotalMilliseconds:N0} ms";
        ShowToast(title, message, kind);

        if (dangerous)
        {
            if (manual)
            {
                // In manual scan mode, action is handled via Scan Results table or configured policy
                if (string.Equals(_viewModel.ScanThreatAction, "Manual", StringComparison.OrdinalIgnoreCase))
                {
                    _ = OfferQuarantineAsync(result);
                }
            }
            else
            {
                // In real-time protection mode, execute configured automated action
                _ = HandleRealtimeThreatAsync(result);
            }
        }
    }

    private async Task HandleRealtimeThreatAsync(ScanResult result)
    {
        var action = _viewModel.RealtimeThreatAction;
        var detection = result.Detections.FirstOrDefault()?.Name ?? App.Localization.Get("toast.threat_found");
        var fileName = Path.GetFileName(result.FilePath);

        try
        {
            switch (action)
            {
                case "Delete":
                    if (File.Exists(result.FilePath))
                    {
                        File.Delete(result.FilePath);
                        ShowToast(App.Localization.Get("toast.deleted"), fileName, ToastKind.Warning);
                    }
                    break;

                case "Ignore":
                    // Alert was already raised by PresentScanResult
                    break;

                case "Quarantine":
                default:
                    await _viewModel.QuarantineFileAsync(result.FilePath, detection, _lifetimeCts.Token);
                    _viewModel.RefreshQuarantine();
                    ShowToast(App.Localization.Get("quarantine.quarantined"), fileName, ToastKind.Success);
                    break;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowToast(App.Localization.Get("quarantine.quarantine_failed"), ex.Message, ToastKind.Error);
        }
    }

    private async Task OfferQuarantineAsync(ScanResult result)
    {
        var detection = result.Detections.FirstOrDefault()?.Name ?? App.Localization.Get("toast.threat_found");
        var confirmed = await Chrome.ShowDialogAsync(
            App.Localization.Get("quarantine.threat_title"),
            App.Localization.Format("quarantine.threat_body", Path.GetFileName(result.FilePath), detection),
            App.Localization.Get("quarantine.quarantine"),
            App.Localization.Get("common.cancel"),
            ToastKind.Error);
        if (!confirmed) return;

        try
        {
            await _viewModel.QuarantineFileAsync(result.FilePath, detection, _lifetimeCts.Token);
            _viewModel.RefreshQuarantine();
            ShowToast(App.Localization.Get("quarantine.quarantined"), Path.GetFileName(result.FilePath), ToastKind.Success);
            Navigate("Quarantine");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowToast(App.Localization.Get("quarantine.quarantine_failed"), ex.Message, ToastKind.Error);
        }
    }

    private async void QuarantineItem(QuarantineItem item)
    {
        try
        {
            await _viewModel.QuarantineFileAsync(item.OriginalPath, item.Detection, _lifetimeCts.Token);
            _viewModel.RefreshQuarantine();
        }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("quarantine.quarantine_failed"), ex.Message, ToastKind.Error);
        }
    }

    private async void RestoreQuarantineItem(QuarantineItem item)
    {
        var confirmed = await Chrome.ShowDialogAsync(
            App.Localization.Get("quarantine.restore_title"),
            App.Localization.Format("quarantine.restore_body", Path.GetFileName(item.OriginalPath)),
            App.Localization.Get("quarantine.restore"),
            App.Localization.Get("common.cancel"),
            ToastKind.Warning);
        if (!confirmed) return;
        try
        {
            _viewModel.RestoreQuarantineItem(item);
            _viewModel.RefreshQuarantine();
            ShowToast(App.Localization.Get("quarantine.restored"), Path.GetFileName(item.OriginalPath), ToastKind.Success);
        }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("quarantine.restore_failed"), ex.Message, ToastKind.Error);
        }
    }

    private async void DeleteQuarantineItem(QuarantineItem item)
    {
        var confirmed = await Chrome.ShowDialogAsync(
            App.Localization.Get("quarantine.delete_title"),
            App.Localization.Format("quarantine.delete_body", Path.GetFileName(item.OriginalPath)),
            App.Localization.Get("quarantine.delete"),
            App.Localization.Get("common.cancel"),
            ToastKind.Error);
        if (!confirmed) return;
        try
        {
            _viewModel.DeleteQuarantineItem(item);
            _viewModel.RefreshQuarantine();
            ShowToast(App.Localization.Get("quarantine.deleted"), Path.GetFileName(item.OriginalPath), ToastKind.Success);
        }
        catch (Exception ex)
        {
            ShowToast(App.Localization.Get("quarantine.delete_failed"), ex.Message, ToastKind.Error);
        }
    }

    private void ToggleTheme()
    {
        App.Theme.Toggle();
        _settingsView?.RefreshTheme();
    }

    private async void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_shutdownStarted) return;
        _shutdownStarted = true;
        e.Cancel = true;
        Closing -= MainWindow_Closing;
        App.Localization.LanguageChanged -= Localization_LanguageChanged;
        try
        {
            _realtime.Stop();
            _lifetimeCts.Cancel();
            App.SaveSettings();
            await _realtime.DisposeAsync();
            await _engine.DisposeAsync();
            _lifetimeCts.Dispose();
        }
        finally
        {
            Application.Current.Shutdown();
        }
    }

    private bool _shutdownStarted;
}
