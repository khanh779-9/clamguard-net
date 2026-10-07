using ClamGuard.Core;

namespace ClamGuard.Production;

public sealed class ProductionScanOptions
{
    public int MaxConcurrentScans { get; init; } = Math.Max(1, Environment.ProcessorCount);
    public int MaxQueuedScans { get; init; } = 128;
    public TimeSpan QueueWaitTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan ScanTimeout { get; init; } = TimeSpan.FromMinutes(5);
    public bool RequireVerifiedContainerDatabases { get; init; } = true;
    public bool RejectWhenDatabaseUnhealthy { get; init; } = true;

    public void Validate()
    {
        if (MaxConcurrentScans is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(MaxConcurrentScans));
        if (MaxQueuedScans is < 0 or > 100_000) throw new ArgumentOutOfRangeException(nameof(MaxQueuedScans));
        if (QueueWaitTimeout != System.Threading.Timeout.InfiniteTimeSpan && (QueueWaitTimeout <= TimeSpan.Zero || QueueWaitTimeout > TimeSpan.FromHours(24))) throw new ArgumentOutOfRangeException(nameof(QueueWaitTimeout));
        if (ScanTimeout != System.Threading.Timeout.InfiniteTimeSpan && (ScanTimeout <= TimeSpan.Zero || ScanTimeout > TimeSpan.FromHours(24))) throw new ArgumentOutOfRangeException(nameof(ScanTimeout));
    }
}

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

public sealed record ProductionHealthStatus(
    bool Healthy,
    long DatabaseGeneration,
    int DatabaseCount,
    int VerifiedDatabaseCount,
    int SignatureCount,
    int InFlight,
    int Queued,
    string Message);

public interface IScanObserver
{
    void OnStarted(string path);
    void OnCompleted(ScanResult result);
    void OnRejected(string path, string reason);
}
