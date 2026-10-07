namespace ClamGuard.Antivirus.Models;

public sealed record ProcessSnapshotItem(string Name, int Id, double MemoryMb, string WindowTitle, string ExecutablePath);
public sealed record StartupSnapshotItem(string Name, string Command, string Scope);
public sealed record NetworkSnapshotItem(string Name, string Type, string Addresses, string Status);
public sealed record DriveSnapshotItem(string Name, string Label, double UsedGb, double FreeGb, double TotalGb, double UsedPercent);

public sealed record FileInspectionResult(
    string Path,
    string Name,
    long SizeBytes,
    DateTime LastWriteTime,
    string Sha256,
    string Version,
    string Company,
    string Product,
    string SignatureSubject,
    string SignatureStatus);

public sealed record SystemSnapshot(
    string OperatingSystem,
    string Architecture,
    int LogicalProcessors,
    double TotalMemoryGb,
    double AvailableMemoryGb,
    TimeSpan Uptime,
    IReadOnlyList<DriveSnapshotItem> Drives,
    IReadOnlyList<ProcessSnapshotItem> Processes,
    IReadOnlyList<NetworkSnapshotItem> Networks,
    IReadOnlyList<StartupSnapshotItem> StartupItems);
