namespace ClamGuard.Antivirus.Models;

public sealed record QuarantineItem(
    string Id,
    string OriginalPath,
    string StoredPath,
    string Detection,
    long SizeBytes,
    DateTimeOffset QuarantinedAt);
