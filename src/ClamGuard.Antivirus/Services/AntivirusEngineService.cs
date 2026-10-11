using ClamGuard.Antivirus.Models;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Scanner.Hosting;
using ClamGuard.Scanner;
using ClamGuard.Database.Update;
using System.Collections.Concurrent;
using System.IO;

namespace ClamGuard.Antivirus.Services;

public sealed class AntivirusEngineService : IAsyncDisposable
{
    private readonly DatabaseManager _databaseManager = new();
    private readonly ScannerEngine _scanner;
    private readonly ScanHost _host;
    private readonly DatabaseUpdater _updater;
    private int _initialized;

    public AntivirusEngineService()
    {
        _scanner = new ScannerEngine(_databaseManager);
        _host = new ScanHost(
            _databaseManager,
            _scanner,
            new ScanHostOptions
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
    public ScanHostHealthStatus Health => _host.GetHealth();
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
            _databaseManager.LoadAndCompile(DatabaseDirectory, failOnInvalidFile: true, includePua: true, cacheDirectory: AppPaths.CacheDirectory);
        }, cancellationToken);
    }

    public Task<ScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        => ScanFileAsync(filePath, CreateScanOptions(), cancellationToken);

    /// <summary>Light buffer scan for memory regions (raw patterns + hashes).</summary>
    public Task<ScanResult> ScanMemoryBufferAsync(byte[] data, string label, CancellationToken cancellationToken = default)
        => Task.Run(() => _scanner.ScanMemoryBuffer(data, label, cancellationToken), cancellationToken);

    public async Task<ScanResult> ScanFileAsync(
        string filePath,
        ScanOptions scanOptions,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(scanOptions);
        scanOptions.Validate();
        if (scanOptions.Verbose)
            System.Diagnostics.Trace.WriteLine($"[ClamGuard] File scan requested: {filePath}");

        var result = await _host.ScanAsync(filePath, scanOptions, cancellationToken).ConfigureAwait(false);
        if (scanOptions.Verbose)
            System.Diagnostics.Trace.WriteLine($"[ClamGuard] {result.Verdict}: {result.FilePath} ({result.Duration.TotalMilliseconds:F0} ms; {result.BytesScanned} bytes)");
        return result;
    }

    public Task<IReadOnlyList<ScanResult>> ScanFolderAsync(
        string folderPath,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
        => ScanFolderAsync(folderPath, CreateScanOptions(), progress, cancellationToken);

    public async Task<IReadOnlyList<ScanResult>> ScanFolderAsync(
        string folderPath,
        ScanOptions scanOptions,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folderPath);
        ArgumentNullException.ThrowIfNull(scanOptions);
        scanOptions.Validate();
        if (!Directory.Exists(folderPath))
            throw new DirectoryNotFoundException(folderPath);

        var root = Path.GetFullPath(folderPath);
        if (scanOptions.Verbose)
            System.Diagnostics.Trace.WriteLine($"[ClamGuard] Directory scan requested: {root}; recursive={scanOptions.Recursive}; followSymlinks={scanOptions.FollowSymlinks}");

        var enumeration = await Task.Run(() => EnumerateScanFiles(root, scanOptions, cancellationToken), cancellationToken).ConfigureAwait(false);
        var files = enumeration.Files;
        var results = new ConcurrentBag<ScanResult>();
        var completed = 0;
        var total = files.Length + enumeration.Errors.Length + (enumeration.LimitReached ? 1 : 0);
        if (scanOptions.Verbose)
            System.Diagnostics.Trace.WriteLine($"[ClamGuard] Directory enumeration complete: {total} file(s)");

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = scanOptions.UseMultithreading ? scanOptions.MaxThreads : 1
        };

        await Parallel.ForEachAsync(files, parallelOptions, async (file, ct) =>
        {
            var result = await ScanFileAsync(file, scanOptions, ct).ConfigureAwait(false);
            results.Add(result);
            var currentCompleted = Interlocked.Increment(ref completed);
            var includeResult = !scanOptions.InfectedOnly ||
                result.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator or ScanVerdict.Error or ScanVerdict.Timeout;
            if (scanOptions.ShowProgress)
                progress?.Report(new ScanProgress(file, currentCompleted, total, includeResult ? result : null));
            if (scanOptions.Verbose)
                System.Diagnostics.Trace.WriteLine($"[ClamGuard] {result.Verdict}: {file} ({result.Duration.TotalMilliseconds:F0} ms)");
        }).ConfigureAwait(false);

        foreach (var inaccessiblePath in enumeration.Errors)
        {
            var errorResult = new ScanResult(
                ScanVerdict.Error,
                inaccessiblePath,
                null,
                [],
                0,
                TimeSpan.Zero,
                _databaseManager.Current.Database.Databases.FirstOrDefault());
            results.Add(errorResult);
            var currentCompleted = Interlocked.Increment(ref completed);
            if (scanOptions.ShowProgress)
                progress?.Report(new ScanProgress(inaccessiblePath, currentCompleted, total, errorResult));
            if (scanOptions.Verbose)
                System.Diagnostics.Trace.WriteLine($"[ClamGuard] Error: could not enumerate or access {inaccessiblePath}");
        }

        if (enumeration.LimitReached)
        {
            IReadOnlyList<Detection> limitDetections = Array.Empty<Detection>();
            var limitVerdict = ScanVerdict.Error;
            if (scanOptions.EnableHeuristics && scanOptions.HeuristicExceedsMax)
            {
                limitDetections = [new Detection(
                    "Heuristics.Limits.Exceeded",
                    SignatureType.Metadata,
                    null,
                    "scan-options",
                    $"Directory scan reached MaxFiles={scanOptions.MaxFiles}; additional files were not scanned.")];
                limitVerdict = ScanVerdict.StrongIndicator;
            }
            var limitResult = new ScanResult(
                limitVerdict,
                root,
                "DIRECTORY",
                limitDetections,
                0,
                TimeSpan.Zero,
                _databaseManager.Current.Database.Databases.FirstOrDefault());
            results.Add(limitResult);
            var currentCompleted = Interlocked.Increment(ref completed);
            if (scanOptions.ShowProgress)
                progress?.Report(new ScanProgress(root, currentCompleted, total, limitResult));
        }

        var ordered = results.OrderBy(x => x.FilePath, StringComparer.OrdinalIgnoreCase);
        return (scanOptions.InfectedOnly
                ? ordered.Where(x => x.Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator or ScanVerdict.Error or ScanVerdict.Timeout)
                : ordered)
            .ToArray();
    }

    private static (string[] Files, bool LimitReached, string[] Errors) EnumerateScanFiles(
        string root,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        var files = new List<string>(Math.Min(options.MaxFiles, 4096));
        var errors = new List<string>();
        var pending = new Stack<string>();
        var pathComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var visitedDirectories = new HashSet<string>(pathComparer);
        pending.Push(root);

        while (pending.Count != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();
            if (options.IsExcludedDirectory(current, root)) continue;

            var identity = GetDirectoryIdentity(current, options.FollowSymlinks);
            if (!visitedDirectories.Add(identity)) continue;

            IEnumerable<string> entries;
            try { entries = Directory.EnumerateFileSystemEntries(current); }
            catch (UnauthorizedAccessException) { errors.Add(current); continue; }
            catch (IOException) { errors.Add(current); continue; }

            try
            {
                foreach (var entry in entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    FileAttributes attributes;
                    try { attributes = File.GetAttributes(entry); }
                    catch (UnauthorizedAccessException) { errors.Add(entry); continue; }
                    catch (IOException) { errors.Add(entry); continue; }

                    var isDirectory = (attributes & FileAttributes.Directory) != 0;
                    var isLink = (attributes & FileAttributes.ReparsePoint) != 0;
                    if (isDirectory)
                    {
                        if (!options.Recursive || options.IsExcludedDirectory(entry, root) || (isLink && !options.FollowSymlinks))
                            continue;
                        pending.Push(entry);
                        continue;
                    }

                    if (isLink && !options.FollowSymlinks) continue;
                    if (options.IsExcludedExtension(entry)) continue;
                    files.Add(Path.GetFullPath(entry));
                    if (files.Count > options.MaxFiles)
                        return (files.Take(options.MaxFiles).ToArray(), true, DistinctPaths(errors, pathComparer));
                }
            }
            catch (UnauthorizedAccessException) { errors.Add(current); }
            catch (IOException) { errors.Add(current); }
        }

        return (files.Distinct(pathComparer)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray(), false,
            DistinctPaths(errors, pathComparer));
    }

    private static string[] DistinctPaths(IEnumerable<string> paths, StringComparer comparer)
        => paths.Distinct(comparer).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();

    private static string GetDirectoryIdentity(string path, bool followSymlinks)
    {
        var fullPath = Path.GetFullPath(path);
        if (!followSymlinks) return fullPath;
        try
        {
            var info = new DirectoryInfo(fullPath);
            var target = info.ResolveLinkTarget(returnFinalTarget: true);
            if (target is not null) return Path.GetFullPath(target.FullName);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (PlatformNotSupportedException) { }
        return fullPath;
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

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync().ConfigureAwait(false);
    }
}
