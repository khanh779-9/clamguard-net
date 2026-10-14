using System.Diagnostics;
using System.IO;
using System.Collections.Concurrent;
using ClamGuard.Core;
using ClamGuard.Antivirus.Models;

namespace ClamGuard.Antivirus.Services;

public sealed class RealtimeProtectionService : IAsyncDisposable
{
    private const int MaxRecoveryReschedules = 500;

    private readonly AntivirusEngineService _engine;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _debounce = new(StringComparer.OrdinalIgnoreCase);
    private FileSystemWatcher? _watcher;
    private int _enabled;
    private int _disposed;
    private int _generation;

    public RealtimeProtectionService(AntivirusEngineService engine) => _engine = engine;

    public bool IsEnabled => Volatile.Read(ref _enabled) != 0;
    public string? WatchedDirectory { get; private set; }

    public event EventHandler<ScanResult>? ScanCompleted;
    public event EventHandler<string>? Error;

    public void Start(string directory)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var fullPath = Path.GetFullPath(directory);
        if (!Directory.Exists(fullPath)) throw new DirectoryNotFoundException(fullPath);

        Stop();
        _watcher = new FileSystemWatcher(fullPath)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite | NotifyFilters.Size,
            Filter = "*",
            // The default 8 KiB buffer overflows during write bursts and drops
            // events; 64 KiB makes that far less likely on busy directories.
            InternalBufferSize = 64 * 1024
        };
        _watcher.Created += OnChanged;
        _watcher.Changed += OnChanged;
        _watcher.Renamed += OnRenamed;
        _watcher.Error += OnWatcherError;
        _watcher.EnableRaisingEvents = true;
        WatchedDirectory = fullPath;
        Volatile.Write(ref _enabled, 1);
    }

    public void Stop()
    {
        Volatile.Write(ref _enabled, 0);
        WatchedDirectory = null;
        if (_watcher is not null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Created -= OnChanged;
            _watcher.Changed -= OnChanged;
            _watcher.Renamed -= OnRenamed;
            _watcher.Error -= OnWatcherError;
            _watcher.Dispose();
            _watcher = null;
        }

        // Cancel only, do not dispose: a scan task that already passed its delay
        // still reads its token, so disposing here would turn its benign
        // cancellation into an ObjectDisposedException. Each task disposes its
        // own CTS in its finally block while it is still the dictionary entry;
        // anything left over is just garbage-collected.
        foreach (var pair in _debounce.ToArray())
        {
            if (_debounce.TryRemove(pair.Key, out var cts))
                cts.Cancel();
        }
    }

    private void OnChanged(object sender, FileSystemEventArgs e) => Schedule(e.FullPath);
    private void OnRenamed(object sender, RenamedEventArgs e) => Schedule(e.FullPath);

    private void Schedule(string path)
    {
        if (!IsEnabled || Directory.Exists(path) || !File.Exists(path)) return;
        if (Path.GetFullPath(path).StartsWith(Path.GetFullPath(_engine.DatabaseDirectory) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return;
        if (Path.GetFileName(path).StartsWith(".", StringComparison.Ordinal)) return;

        var cts = new CancellationTokenSource();
        var generation = Interlocked.Increment(ref _generation);
        _ = _debounce.AddOrUpdate(path, cts, (_, old) =>
        {
            // Cancel without dispose: the superseded task may still be reading
            // its token; stale instances are released by their own task's
            // finally block or the GC.
            old.Cancel();
            return cts;
        });
        _ = ScanAfterDelayAsync(path, cts, generation);
    }

    private async Task ScanAfterDelayAsync(string path, CancellationTokenSource cts, int generation)
    {
        try
        {
            await Task.Delay(900, cts.Token).ConfigureAwait(false);
            if (!IsCurrentEntry(path, cts))
            {
                Trace.WriteLine($"[ClamGuard] Realtime scan of '{path}' (generation {generation}) superseded before start; skipped.");
                return;
            }
            if (!await WaitUntilReadableAsync(path, cts.Token).ConfigureAwait(false)) return;
            var result = await _engine.ScanFileAsync(path, cts.Token).ConfigureAwait(false);
            if (!IsCurrentEntry(path, cts))
            {
                Trace.WriteLine($"[ClamGuard] Realtime scan of '{path}' (generation {generation}) superseded while scanning; duplicate result dropped.");
                return;
            }
            ScanCompleted?.Invoke(this, result);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Error?.Invoke(this, $"Realtime scan failed for '{path}': {ex.Message}");
        }
        finally
        {
            if (_debounce.TryRemove(new KeyValuePair<string, CancellationTokenSource>(path, cts)))
                cts.Dispose();
        }
    }

    private bool IsCurrentEntry(string path, CancellationTokenSource cts)
        => _debounce.TryGetValue(path, out var current) && ReferenceEquals(current, cts);

    private async Task<bool> WaitUntilReadableAsync(string path, CancellationToken token)
    {
        long previousLength = -1;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                long length;
                await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 32 * 1024, useAsync: true))
                    length = stream.Length;

                if (length == previousLength) return true;
                previousLength = length;
                await Task.Delay(300, token).ConfigureAwait(false);
            }
            catch (IOException)
            {
                await Task.Delay(350, token).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                await Task.Delay(350, token).ConfigureAwait(false);
            }
        }

        Error?.Invoke(this, $"Realtime scan skipped: '{path}' did not become readable after 5 attempts.");
        return false;
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        Error?.Invoke(this, $"Realtime protection watcher error: {e.GetException().Message}");
        var directory = WatchedDirectory;
        if (directory is null) return;

        // A watcher error is almost always an event-buffer overflow, i.e. events
        // were silently dropped. Restart the watcher first so nothing new is
        // missed, then best-effort reschedule recent existing files.
        try
        {
            Stop();
            Start(directory);
        }
        catch (Exception ex)
        {
            Error?.Invoke(this, $"Realtime protection could not restart the watcher for '{directory}': {ex.Message}");
            return;
        }

        RescheduleRecentFiles(directory);
    }

    private void RescheduleRecentFiles(string directory)
    {
        _ = Task.Run(() =>
        {
            try
            {
                var recent = new List<FileInfo>();
                foreach (var file in new DirectoryInfo(directory).EnumerateFiles(
                             "*",
                             new EnumerationOptions
                             {
                                 RecurseSubdirectories = true,
                                 IgnoreInaccessible = true
                             }))
                {
                    recent.Add(file);
                }

                // Bounded to keep a huge tree from storming the engine; Schedule
                // itself re-filters deleted files, dotfiles and the DB directory.
                foreach (var file in recent
                             .OrderByDescending(static f => f.LastWriteTimeUtc)
                             .Take(MaxRecoveryReschedules))
                {
                    Schedule(file.FullName);
                }
            }
            catch (Exception ex)
            {
                Error?.Invoke(this, $"Realtime protection recovery rescan failed for '{directory}': {ex.Message}");
            }
        });
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(RealtimeProtectionService));
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0) Stop();
        return ValueTask.CompletedTask;
    }
}
