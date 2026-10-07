namespace ClamGuard.Antivirus.Models;

public sealed record ScanProgress(
    string Path,
    int Completed,
    int Total,
    ClamGuard.Core.ScanResult? Result = null);