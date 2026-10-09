namespace ClamGuard.Database;

public sealed record DatabaseLoadError(string FilePath, string Message);
