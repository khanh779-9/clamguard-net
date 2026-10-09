namespace ClamGuard.Scanner.Hosting;

public sealed class ScanHostOptions
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
