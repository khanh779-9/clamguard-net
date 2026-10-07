namespace ClamGuard.Antivirus.Services;

public sealed class AppSettings
{
    public string DatabaseDirectory { get; set; } = AppPaths.DatabaseDirectory;
    public string? RealtimeDirectory { get; set; } = string.Empty;
    public string Theme { get; set; } = "Dark";
    public string Language { get; set; } = "en-US";
    public string ScanThreatAction { get; set; } = "Manual";
    public string RealtimeThreatAction { get; set; } = "Quarantine";
}

