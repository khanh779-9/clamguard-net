using ClamGuard.Antivirus.Models;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Production;
using ClamGuard.Scanner;
using ClamGuard.Update;
using System.Collections.Concurrent;
using System.IO;

namespace ClamGuard.Antivirus.Services;

public sealed class AntivirusEngineService : IAsyncDisposable
{
    private readonly DatabaseManager _databaseManager = new();
    private readonly ScannerEngine _scanner;
    private readonly ProductionScanHost _host;
    private readonly DatabaseUpdater _updater;
    private int _initialized;

    public AntivirusEngineService()
    {
        _scanner = new ScannerEngine(_databaseManager);
        _host = new ProductionScanHost(
            _databaseManager,
            _scanner,
            new ProductionScanOptions
            {
                MaxConcurrentScans = Math.Max(1, Environment.ProcessorCount),
                MaxQueuedScans = 10_000,
                QueueWaitTimeout = System.Threading.Timeout.InfiniteTimeSpan,
                ScanTimeout = System.Threading.Timeout.InfiniteTimeSpan,
                RequireVerifiedContainerDatabases = true,
                RejectWhenDatabaseUnhealthy = true
            });
        _updater = new DatabaseUpdater(options: new UpdateOptions
        {
            BaseUri = new Uri("https://database.clamav.net/"),
            Timeout = TimeSpan.FromSeconds(60),
            MaxAttempts = 2
        });
    }

    public string DatabaseDirectory => App.Settings.DatabaseDirectory;
    public string YaraDirectory => AppPaths.YaraDirectory;
    public string BytecodeDirectory => AppPaths.BytecodeDirectory;
    public ProductionHealthStatus Health => _host.GetHealth();
    public ScanMetricsSnapshot Metrics => _host.GetMetrics();
    public DatabaseInfo? CurrentDatabase => _databaseManager.Current.Database.Databases.FirstOrDefault();

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _initialized, 1) != 0) return;
        AppPaths.EnsureDirectories();
        Directory.CreateDirectory(DatabaseDirectory);
        try
        {
            await ReloadDatabaseAsync(cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _initialized, 1);
        }
        catch
        {
            Volatile.Write(ref _initialized, 0);
            throw;
        }
    }

    public Task ReloadDatabaseAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            _databaseManager.LoadAndCompile(DatabaseDirectory, failOnInvalidFile: true, cacheDirectory: AppPaths.CacheDirectory);
        }, cancellationToken);
    }

    public Task<ScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        return _host.ScanAsync(filePath, CreateScanOptions(), cancellationToken);
    }

    public async Task<IReadOnlyList<ScanResult>> ScanFolderAsync(
        string folderPath,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folderPath);
        if (!Directory.Exists(folderPath))
            throw new DirectoryNotFoundException(folderPath);

        const int maxFiles = 10_000;
        var (files, limited) = await Task.Run(() =>
        {
            var matched = Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories)
                .Where(IsScannablePath)
                .Take(maxFiles + 1)
                .ToArray();
            var isLimited = matched.Length > maxFiles;
            return (isLimited ? matched[..maxFiles] : matched, isLimited);
        }, cancellationToken).ConfigureAwait(false);

        var results = new ConcurrentBag<ScanResult>();
        var completed = 0;
        var total = files.Length;

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, 8))
        };

        await Parallel.ForEachAsync(files, parallelOptions, async (file, ct) =>
        {
            var result = await ScanFileAsync(file, ct).ConfigureAwait(false);
            results.Add(result);
            var currentCompleted = Interlocked.Increment(ref completed);
            progress?.Report(new ScanProgress(file, currentCompleted, total, result));
        }).ConfigureAwait(false);

        if (limited)
            throw new InvalidOperationException("Folder scan reached the 10,000-file safety limit.");

        return results.ToArray();
    }

    public async Task<UpdateResult> UpdateDatabaseAsync(CancellationToken cancellationToken = default)
    {
        var result = await _updater.UpdateCvdAsync(DatabaseDirectory, "daily.cvd", cancellationToken).ConfigureAwait(false);
        if (result.Status == UpdateStatus.Updated)
            await ReloadDatabaseAsync(cancellationToken).ConfigureAwait(false);
        return result;
    }

    public void SetDatabaseDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        Directory.CreateDirectory(directory);
        App.Settings.DatabaseDirectory = Path.GetFullPath(directory);
        App.SaveSettings();
    }

    private ScanOptions CreateScanOptions() => new()
    {
        CollectAllMatches = true,
        YaraRuleDirectory = Directory.Exists(YaraDirectory) ? YaraDirectory : null,
        BytecodeDirectory = Directory.Exists(BytecodeDirectory) ? BytecodeDirectory : null
    };

    private static bool IsScannablePath(string path)
    {
        var name = Path.GetFileName(path);
        return !name.StartsWith(".", StringComparison.Ordinal) &&
               !name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync().ConfigureAwait(false);
    }
}
