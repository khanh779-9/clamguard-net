namespace ClamGuard.Scanner.Hosting;

public sealed record ScanMetricsSnapshot(
    DateTimeOffset CapturedAt,
    TimeSpan Uptime,
    long Started,
    long Completed,
    long Clean,
    long Malicious,
    long Trusted,
    long Errors,
    long Timeouts,
    long QueueTimeouts,
    long BytesScanned,
    long TotalScanMilliseconds,
    int InFlight,
    int Queued);
