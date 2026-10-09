using ClamGuard.Core;
using ClamGuard.Database.Storage;

namespace ClamGuard.Database;

public sealed class DatabaseLoadResult
{
    public required SignatureDatabase Database { get; init; }
    public required IReadOnlyList<DatabaseInfo> Files { get; init; }
    public required IReadOnlyList<DatabaseLoadError> Errors { get; init; }
    public int SignatureCount => Database.Signatures.Count;
}
