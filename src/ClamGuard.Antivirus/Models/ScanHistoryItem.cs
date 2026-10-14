using ClamGuard.Core;
using System.Diagnostics;
using System.IO;

namespace ClamGuard.Antivirus.Models;

public sealed record ScanHistoryItem(
    string FileName,
    string FullPath,
    ScanVerdict Verdict,
    int DetectionCount,
    TimeSpan Duration,
    DateTimeOffset Time,
    string? PrimaryDetection,
    string Kind = "File Scan")
{
    private static readonly string HostProcess = $"{Process.GetCurrentProcess().ProcessName}.exe";

    public static ScanHistoryItem FromResult(ScanResult result, string kind = "File Scan")
        => new(
            Path.GetFileName(result.FilePath),
            result.FilePath,
            result.Verdict,
            result.Detections.Count,
            result.Duration,
            DateTimeOffset.Now,
            result.Detections.FirstOrDefault()?.Name,
            kind);

    public bool IsThreat => Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator;
    public bool IsClean => Verdict == ScanVerdict.Clean;
    public string ProcessName => HostProcess;

    public string VerdictText => Verdict switch
    {
        ScanVerdict.Clean => App.Localization.Get("history.verdict_clean"),
        ScanVerdict.Malicious => App.Localization.Get("history.verdict_threat"),
        ScanVerdict.Trusted => App.Localization.Get("history.verdict_trusted"),
        ScanVerdict.PotentiallyUnwanted => App.Localization.Get("history.verdict_pua"),
        ScanVerdict.StrongIndicator => App.Localization.Get("history.verdict_indicator"),
        ScanVerdict.Timeout => App.Localization.Get("history.verdict_timeout"),
        _ => App.Localization.Get("history.verdict_error")
    };
}