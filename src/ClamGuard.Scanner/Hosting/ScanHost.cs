using System.Diagnostics;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Scanner;

namespace ClamGuard.Scanner.Hosting;

/// <summary>
/// Bounded, timeout-aware production facade around ScannerEngine. It does not mutate
/// caller-owned ScanOptions and keeps admission/concurrency limits outside the scanner.
/// </summary>
public sealed class ScanHost : IDisposable, IAsyncDisposable
{
    private readonly ScannerEngine _scanner;
    private readonly DatabaseManager _databaseManager;
    private readonly ScanHostOptions _options;
    private readonly SemaphoreSlim _concurrency;
    private readonly SemaphoreSlim _admission;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TaskCompletionSource<bool> _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly IScanObserver[] _observers;
    private int _inFlight;
    private int _queued;
    private int _activeOperations;
    private int _disposed;
    private int _resourcesDisposed;
    private long _started;
    private long _completed;
    private long _clean;
    private long _malicious;
    private long _trusted;
    private long _errors;
    private long _timeouts;
    private long _queueTimeouts;
    private long _bytes;
    private long _milliseconds;

    public ScanHost(
        DatabaseManager databaseManager,
        ScannerEngine scanner,
        ScanHostOptions? options = null,
        IEnumerable<IScanObserver>? observers = null)
    {
        _databaseManager = databaseManager ?? throw new ArgumentNullException(nameof(databaseManager));
        _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        _options = options ?? new ScanHostOptions();
        _options.Validate();
        _concurrency = new SemaphoreSlim(_options.MaxConcurrentScans, _options.MaxConcurrentScans);
        _admission = new SemaphoreSlim(_options.MaxConcurrentScans + _options.MaxQueuedScans, _options.MaxConcurrentScans + _options.MaxQueuedScans);
        _observers = observers?.ToArray() ?? [];
    }

    public async Task<ScanResult> ScanAsync(
        string path,
        ScanOptions? scanOptions = null,
        CancellationToken cancellationToken = default)
    {
        EnterOperation();
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            var fullPath = Path.GetFullPath(path);

            Interlocked.Increment(ref _started);

            if (_options.RejectWhenDatabaseUnhealthy)
            {
                var health = GetHealth();
                if (!health.Healthy)
                {
                    var unavailable = new ScanResult(
                        ScanVerdict.Error,
                        fullPath,
                        null,
                        [],
                        0,
                        TimeSpan.Zero,
                        _databaseManager.Current.Database.Databases.FirstOrDefault());
                    Record(unavailable);
                    NotifyRejected(fullPath, health.Message);
                    NotifyCompleted(unavailable);
                    return unavailable;
                }
            }

            NotifyStarted(fullPath);
            using var requestToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
            if (_options.QueueWaitTimeout != Timeout.InfiniteTimeSpan)
            {
                requestToken.CancelAfter(_options.QueueWaitTimeout);
            }
            try
            {
                await _admission.WaitAsync(requestToken.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                Interlocked.Increment(ref _queueTimeouts);
                var timeout = new ScanResult(
                    ScanVerdict.Timeout,
                    fullPath,
                    null,
                    [],
                    0,
                    _options.QueueWaitTimeout,
                    _databaseManager.Current.Database.Databases.FirstOrDefault());
                Record(timeout);
                NotifyRejected(fullPath, "scan queue wait timeout or host shutdown");
                NotifyCompleted(timeout);
                return timeout;
            }

            Interlocked.Increment(ref _queued);
            var enteredConcurrency = false;
            try
            {
                try
                {
                    await _concurrency.WaitAsync(requestToken.Token).ConfigureAwait(false);
                    enteredConcurrency = true;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    Interlocked.Increment(ref _queueTimeouts);
                    var timeout = new ScanResult(
                        ScanVerdict.Timeout,
                        fullPath,
                        null,
                        [],
                        0,
                        _options.QueueWaitTimeout,
                        _databaseManager.Current.Database.Databases.FirstOrDefault());
                    Record(timeout);
                    NotifyRejected(fullPath, "scan concurrency wait timeout or host shutdown");
                    NotifyCompleted(timeout);
                    return timeout;
                }

                Interlocked.Decrement(ref _queued);
                Interlocked.Increment(ref _inFlight);
                try
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
                    if (_options.ScanTimeout != Timeout.InfiniteTimeSpan)
                    {
                        timeout.CancelAfter(_options.ScanTimeout);
                    }
                    ScanResult result;
                    try
                    {
                        result = await _scanner.ScanAsync(fullPath, CloneOptions(scanOptions), timeout.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                    {
                        result = new ScanResult(
                            ScanVerdict.Timeout,
                            fullPath,
                            null,
                            [],
                            0,
                            _options.ScanTimeout,
                            _databaseManager.Current.Database.Databases.FirstOrDefault());
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not AccessViolationException)
                    {
                        result = new ScanResult(
                            ScanVerdict.Error,
                            fullPath,
                            null,
                            [],
                            0,
                            TimeSpan.Zero,
                            _databaseManager.Current.Database.Databases.FirstOrDefault());
                        NotifyRejected(fullPath, $"unexpected scanner error: {ex.GetType().Name}");
                    }

                    Record(result);
                    NotifyCompleted(result);
                    return result;
                }
                finally
                {
                    Interlocked.Decrement(ref _inFlight);
                    _concurrency.Release();
                }
            }
            finally
            {
                if (!enteredConcurrency) Interlocked.Decrement(ref _queued);
                _admission.Release();
            }
        }
        finally
        {
            ExitOperation();
        }
    }

    public ScanHostHealthStatus GetHealth()
    {
        ThrowIfDisposed();
        var state = _databaseManager.Current;
        var databases = state.Database.Databases;
        var containerDatabases = databases
            .Where(static d => d.Format is DatabaseFormat.Cvd or DatabaseFormat.Cld or DatabaseFormat.Cud)
            .ToArray();
        var verified = containerDatabases.Count(static d => d.IsVerified);
        var verifiedOk = !_options.RequireVerifiedContainerDatabases || containerDatabases.All(static d => d.IsVerified);
        var healthy = state.Database.Signatures.Count > 0 && verifiedOk;
        var message = healthy
            ? "scanner ready; active database state is acceptable"
            : state.Database.Signatures.Count == 0
                ? "scanner has no active signatures"
                : "one or more active container databases are not verified";
        return new ScanHostHealthStatus(
            healthy,
            state.Generation,
            databases.Count,
            verified,
            state.Database.Signatures.Count,
            Volatile.Read(ref _inFlight),
            Volatile.Read(ref _queued),
            message);
    }

    public ScanMetricsSnapshot GetMetrics()
        => new(
            DateTimeOffset.UtcNow,
            _uptime.Elapsed,
            Volatile.Read(ref _started),
            Volatile.Read(ref _completed),
            Volatile.Read(ref _clean),
            Volatile.Read(ref _malicious),
            Volatile.Read(ref _trusted),
            Volatile.Read(ref _errors),
            Volatile.Read(ref _timeouts),
            Volatile.Read(ref _queueTimeouts),
            Volatile.Read(ref _bytes),
            Volatile.Read(ref _milliseconds),
            Volatile.Read(ref _inFlight),
            Volatile.Read(ref _queued));

    private static ScanOptions CloneOptions(ScanOptions? source)
    {
        source ??= new ScanOptions();
        // Normalize/validate the private copy so a malformed public byte limit cannot
        // mutate caller-owned configuration or fail every file in a folder scan.
        var copy = new ScanOptions
        {
            CollectAllMatches = source.CollectAllMatches,
            Limits = source.Limits,
            YaraRuleDirectory = source.YaraRuleDirectory,
            BytecodeDirectory = source.BytecodeDirectory,
            ScanArchive = source.ScanArchive,
            ScanELF = source.ScanELF,
            ScanPDF = source.ScanPDF,
            ScanSWF = source.ScanSWF,
            ScanHWP3 = source.ScanHWP3,
            ScanXMLDocs = source.ScanXMLDocs,
            ScanMail = source.ScanMail,
            ScanOLE2 = source.ScanOLE2,
            ScanHTML = source.ScanHTML,
            ScanPE = source.ScanPE,
            ScanOneNote = source.ScanOneNote,
            ScanImage = source.ScanImage,
            ScanImageFuzzyHash = source.ScanImageFuzzyHash,
            EnableHeuristics = source.EnableHeuristics,
            HeuristicPrecedence = source.HeuristicPrecedence,
            HeuristicExceedsMax = source.HeuristicExceedsMax,
            HeuristicEncryptedArchive = source.HeuristicEncryptedArchive,
            HeuristicEncryptedDoc = source.HeuristicEncryptedDoc,
            MaxFileSize = source.MaxFileSize,
            MaxScanSize = source.MaxScanSize,
            MaxFiles = source.MaxFiles,
            MaxRecursion = source.MaxRecursion,
            DetectPUA = source.DetectPUA,
            UseMultithreading = source.UseMultithreading,
            MaxThreads = source.MaxThreads,
            Verbose = source.Verbose,
            ShowProgress = source.ShowProgress,
            InfectedOnly = source.InfectedOnly,
            Recursive = source.Recursive,
            FollowSymlinks = source.FollowSymlinks,
            ExcludeDirectories = [.. source.ExcludeDirectories],
            ExcludeExtensions = [.. source.ExcludeExtensions]
        };
        foreach (var scanner in source.ContentScanners) copy.ContentScanners.Add(scanner);
        copy.Validate();
        return copy;
    }

    private void Record(ScanResult result)
    {
        Interlocked.Increment(ref _completed);
        Interlocked.Add(ref _bytes, Math.Max(0, result.BytesScanned));
        Interlocked.Add(ref _milliseconds, Math.Max(0, (long)result.Duration.TotalMilliseconds));
        switch (result.Verdict)
        {
            case ScanVerdict.Clean: Interlocked.Increment(ref _clean); break;
            case ScanVerdict.Malicious: Interlocked.Increment(ref _malicious); break;
            case ScanVerdict.Trusted: Interlocked.Increment(ref _trusted); break;
            case ScanVerdict.Timeout: Interlocked.Increment(ref _timeouts); break;
            case ScanVerdict.Error: Interlocked.Increment(ref _errors); break;
        }
    }

    private void NotifyStarted(string path)
    {
        foreach (var observer in _observers)
        {
            try { observer.OnStarted(path); } catch { }
        }
    }

    private void NotifyCompleted(ScanResult result)
    {
        foreach (var observer in _observers)
        {
            try { observer.OnCompleted(result); } catch { }
        }
    }

    private void NotifyRejected(string path, string reason)
    {
        foreach (var observer in _observers)
        {
            try { observer.OnRejected(path, reason); } catch { }
        }
    }

    private void EnterOperation()
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(ScanHost));
        Interlocked.Increment(ref _activeOperations);
        if (Volatile.Read(ref _disposed) != 0)
        {
            ExitOperation();
            throw new ObjectDisposedException(nameof(ScanHost));
        }
    }

    private void ExitOperation()
    {
        if (Interlocked.Decrement(ref _activeOperations) == 0)
            TryFinalizeResources();
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(ScanHost));
    }

    private void TryFinalizeResources()
    {
        if (Volatile.Read(ref _disposed) == 0 || Volatile.Read(ref _activeOperations) != 0) return;
        if (Interlocked.Exchange(ref _resourcesDisposed, 1) != 0) return;
        _uptime.Stop();
        _concurrency.Dispose();
        _admission.Dispose();
        _shutdown.Dispose();
        _drained.TrySetResult(true);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _shutdown.Cancel(); } catch (ObjectDisposedException) { }
        TryFinalizeResources();
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { _shutdown.Cancel(); } catch (ObjectDisposedException) { }
        }
        if (Volatile.Read(ref _activeOperations) != 0)
            await _drained.Task.ConfigureAwait(false);
        TryFinalizeResources();
    }
}
