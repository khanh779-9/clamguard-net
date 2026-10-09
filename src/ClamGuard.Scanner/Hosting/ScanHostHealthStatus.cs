namespace ClamGuard.Scanner.Hosting;

public sealed record ScanHostHealthStatus(
    bool Healthy,
    long DatabaseGeneration,
    int DatabaseCount,
    int VerifiedDatabaseCount,
    int SignatureCount,
    int InFlight,
    int Queued,
    string Message);
