using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using ClamGuard.Antivirus.Controls;
using ClamGuard.Antivirus.Localization;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Scanner;
using ClamGuard.Signatures.Parsing;
using Microsoft.Win32;

namespace ClamGuard.Antivirus.Views;

public partial class ToolsView : UserControl
{
    // The industry-standard, harmless antivirus test string (EICAR). Every AV
    // product detects it; writing it to disk is the canonical way to verify
    // real-time protection and scan detection end-to-end.
    private const string EicarTestString =
        @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private List<(string Path, long Size)> _junkFiles = [];
    private string? _samplePath;

    public ToolsView() => InitializeComponent();

    private async void PickHashFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = App.Localization.Get("tools.hash_pick"),
            CheckFileExists = true
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;

        var path = dialog.FileName;
        HashFileNameText.Text = path;
        HashFileNameText.Visibility = Visibility.Visible;
        HashStatusText.Visibility = Visibility.Collapsed;
        HashResultsGrid.Visibility = Visibility.Collapsed;

        try
        {
            var (md5, sha1, sha256) = await Task.Run(() =>
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    128 * 1024, FileOptions.SequentialScan);
                return (
                    Convert.ToHexString(MD5.HashData(stream)),
                    Convert.ToHexString(SHA1.HashData(stream)),
                    Convert.ToHexString(SHA256.HashData(stream)));
            });

            HashMd5Text.Text = md5;
            HashSha1Text.Text = sha1;
            HashSha256Text.Text = sha256;
            HashResultsGrid.Visibility = Visibility.Visible;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowStatus(HashStatusText, string.Format(App.Localization.Get("tools.hash_failed"), ex.Message));
        }
    }

    private void CopyHash_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string algorithm }) return;
        var value = algorithm switch
        {
            "MD5" => HashMd5Text.Text,
            "SHA1" => HashSha1Text.Text,
            _ => HashSha256Text.Text
        };
        if (string.IsNullOrEmpty(value)) return;

        Clipboard.SetText(value);
        ShowStatus(HashStatusText, $"{algorithm}: {App.Localization.Get("tools.hash_copied")}");
    }

    private async void CreateEicar_Click(object sender, RoutedEventArgs e)
    {
        var window = Window.GetWindow(this) as ClamGuardWindow;
        if (window is not null)
        {
            var confirmed = await window.ShowDialogAsync(
                App.Localization.Get("tools.eicar_title"),
                App.Localization.Get("tools.eicar_confirm_body"),
                App.Localization.Get("tools.eicar_create"),
                App.Localization.Get("common.cancel"),
                ToastKind.Warning);
            if (!confirmed) return;
        }

        try
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var path = Path.Combine(desktop, "EICAR-Test-File.com");
            await File.WriteAllTextAsync(path, EicarTestString);

            EicarStatusText.Text = string.Format(App.Localization.Get("tools.eicar_created"), path);
            EicarStatusText.Visibility = Visibility.Visible;
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            EicarStatusText.Text = string.Format(App.Localization.Get("tools.eicar_failed"), ex.Message);
            EicarStatusText.Visibility = Visibility.Visible;
        }
    }

    // --- Temp file cleanup ----------------------------------------------------

    private async void ScanJunk_Click(object sender, RoutedEventArgs e)
    {
        CleanupStatusText.Visibility = Visibility.Collapsed;
        CleanNowButton.IsEnabled = false;
        try
        {
            _junkFiles = await Task.Run(ComputeJunkFiles);
            var totalBytes = _junkFiles.Sum(f => f.Size);
            if (_junkFiles.Count == 0)
            {
                ShowStatus(CleanupStatusText, App.Localization.Get("tools.cleanup_nothing"));
                return;
            }

            var userBytes = _junkFiles
                .Where(f => f.Path.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
                .Sum(f => f.Size);
            var windowsBytes = totalBytes - userBytes;
            CleanupStatusText.Text = string.Format(
                App.Localization.Get("tools.cleanup_found"),
                FormatBytes(totalBytes), _junkFiles.Count, FormatBytes(userBytes), FormatBytes(windowsBytes));
            CleanupStatusText.Visibility = Visibility.Visible;
            CleanNowButton.IsEnabled = true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowStatus(CleanupStatusText, string.Format(App.Localization.Get("tools.cleanup_failed"), ex.Message));
        }
    }

    private static List<(string Path, long Size)> ComputeJunkFiles()
    {
        var cutoff = DateTime.UtcNow - TimeSpan.FromHours(24);
        var results = new List<(string, long)>();
        var directories = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
        };
        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System
        };
        foreach (var directory in directories.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(directory)) continue;
            foreach (var file in Directory.EnumerateFiles(directory, "*", options))
            {
                try
                {
                    var info = new FileInfo(file);
                    if (info.LastWriteTimeUtc >= cutoff) continue;
                    results.Add((file, info.Length));
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        return results;
    }

    private async void CleanJunk_Click(object sender, RoutedEventArgs e)
    {
        if (_junkFiles.Count == 0) return;
        var totalBytes = _junkFiles.Sum(f => f.Size);
        var window = Window.GetWindow(this) as ClamGuardWindow;
        if (window is not null)
        {
            var confirmed = await window.ShowDialogAsync(
                App.Localization.Get("tools.cleanup_confirm_title"),
                string.Format(App.Localization.Get("tools.cleanup_confirm_body"), _junkFiles.Count, FormatBytes(totalBytes)),
                App.Localization.Get("tools.cleanup_clean"),
                App.Localization.Get("common.cancel"),
                ToastKind.Warning);
            if (!confirmed) return;
        }

        CleanNowButton.IsEnabled = false;
        var pending = _junkFiles;
        _junkFiles = [];
        var (freed, skipped) = await Task.Run(() =>
        {
            long freedBytes = 0;
            var skippedCount = 0;
            foreach (var (path, size) in pending)
            {
                try
                {
                    File.Delete(path);
                    freedBytes += size;
                }
                catch (IOException) { skippedCount++; }
                catch (UnauthorizedAccessException) { skippedCount++; }
            }
            return (freedBytes, skippedCount);
        });

        ShowStatus(CleanupStatusText, string.Format(App.Localization.Get("tools.cleanup_done"), FormatBytes(freed), skipped));
    }

    // --- Signature tester -----------------------------------------------------

    private void PickSampleFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { CheckFileExists = true };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;
        _samplePath = dialog.FileName;
        SampleFileText.Text = Path.GetFileName(_samplePath);
    }

    private async void TestSignature_Click(object sender, RoutedEventArgs e)
    {
        var signatureText = SignatureInput.Text;
        if (string.IsNullOrWhiteSpace(signatureText))
        {
            ShowStatus(TesterStatusText, App.Localization.Get("tools.tester_no_signature"));
            return;
        }
        if (_samplePath is null || !File.Exists(_samplePath))
        {
            ShowStatus(TesterStatusText, App.Localization.Get("tools.tester_no_file"));
            return;
        }

        TestSignatureButton.IsEnabled = false;
        var samplePath = _samplePath;
        try
        {
            var lines = signatureText.Split('\n')
                .Select(l => l.TrimEnd('\r').Trim())
                .Where(l => l.Length != 0)
                .ToList();
            var extension = lines.Any(l => l.Contains('=')) ? ".db" : ".ndb";
            var tempPath = Path.Combine(Path.GetTempPath(), "clamguard-sigtest-" + Guid.NewGuid().ToString("N") + extension);
            try
            {
                await File.WriteAllLinesAsync(tempPath, lines);

                var database = new SignatureDatabase();
                foreach (var signature in SignatureParser.ParseFile(tempPath, 240))
                    database.Add(signature);
                if (database.Signatures.Count == 0)
                {
                    ShowStatus(TesterStatusText, App.Localization.Get("tools.tester_not_loaded"));
                    return;
                }

                var result = await Task.Run(() => new ScannerEngine(new DatabaseManager(database))
                    .Scan(samplePath, new ScanOptions { CollectAllMatches = true }));

                if (result.Detections.Count == 0)
                {
                    ShowStatus(TesterStatusText, App.Localization.Get("tools.tester_no_match"));
                    return;
                }

                var detections = string.Join("; ", result.Detections
                    .Select(d => d.Offset is null ? d.Name : $"{d.Name} @ {d.Offset}"));
                ShowStatus(TesterStatusText, string.Format(App.Localization.Get("tools.tester_match"), detections));
            }
            finally
            {
                try { File.Delete(tempPath); } catch (IOException) { }
            }
        }
        catch (FormatException ex)
        {
            ShowStatus(TesterStatusText, string.Format(App.Localization.Get("tools.tester_invalid"), TrimReason(ex.Message)));
        }
        finally
        {
            TestSignatureButton.IsEnabled = true;
        }
    }

    private static string TrimReason(string message)
    {
        // Parser errors embed the whole DB line; keep the reason readable.
        var index = message.IndexOf(". ", StringComparison.Ordinal);
        return index > 0 ? message[..index] : message;
    }

    // --- Shared helpers -------------------------------------------------------

    private static void ShowStatus(TextBlock target, string message)
    {
        target.Text = message;
        target.Visibility = Visibility.Visible;
    }

    private static string FormatBytes(long bytes)
    {
        return bytes switch
        {
            >= 1L << 30 => $"{bytes / (double)(1L << 30):F2} GB",
            >= 1L << 20 => $"{bytes / (double)(1L << 20):F1} MB",
            >= 1L << 10 => $"{bytes / (double)(1L << 10):F1} KB",
            _ => $"{bytes} B"
        };
    }
}
