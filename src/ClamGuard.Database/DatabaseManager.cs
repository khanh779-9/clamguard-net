using ClamGuard.Database.Storage;

namespace ClamGuard.Database;

public sealed class DatabaseManager
{
    private CompiledState _state;
    private long _generation;

    public DatabaseManager(SignatureDatabase? database = null)
    {
        _state = new CompiledState(database ?? new SignatureDatabase(), 0);
    }

    public CompiledState Current => Volatile.Read(ref _state);

    public CompiledState LoadAndCompile(
        string directory,
        bool failOnInvalidFile = true,
        bool includePua = false,
        IReadOnlyCollection<string>? includePuaCategories = null,
        IReadOnlyCollection<string>? excludePuaCategories = null,
        string? cacheDirectory = null)
    {
        var loaded = new DatabaseLoader
        {
            IncludePua = includePua,
            IncludePuaCategories = includePuaCategories ?? Array.Empty<string>(),
            ExcludePuaCategories = excludePuaCategories ?? Array.Empty<string>(),
            CacheDirectory = cacheDirectory
        }.LoadDirectory(directory, failOnInvalidFile);
        var compiled = loaded.Database.Compile();
        var generation = Interlocked.Increment(ref _generation);
        loaded.Database.Generation = generation;
        var next = new CompiledState(loaded.Database, compiled, generation);
        Volatile.Write(ref _state, next);

        // Reclaim transient string parsing and intermediate object allocations from the loader
        GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);

        return next;
    }
}

public sealed record CompiledState(
    SignatureDatabase Database,
    ClamGuard.Signatures.Matching.CompiledSignatureSet Compiled,
    long Generation)
{
    public CompiledState(SignatureDatabase database, long generation)
        : this(database, database.Compile(), generation)
    {
    }
}
