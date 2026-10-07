using System.IO;
using System.Collections.Concurrent;
using ClamGuard.Core;
using ClamGuard.Antivirus.Models;

namespace ClamGuard.Antivirus.Services;

public sealed class RealtimeProtectionService : IAsyncDisposable
{
    private readonly AntivirusEngineService _engine;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _debounce = new(StringComparer.OrdinalIgnoreCase);
    private FileSystemWatcher? _watcher;
    private int _enabled;
    private int _disposed;

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
            Filter = "*"
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

        foreach (var pair in _debounce.ToArray())
        {
            if (_debounce.TryRemove(pair.Key, out var cts))
                cts.Cancel();
            cts?.Dispose();
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
        _ = _debounce.AddOrUpdate(path, cts, (_, old) =>
        {
            old.Cancel();
            old.Dispose();
            return cts;
        });
        _ = ScanAfterDelayAsync(path, cts);
    }

    private async Task ScanAfterDelayAsync(string path, CancellationTokenSource cts)
    {
        try
        {
            await Task.Delay(900, cts.Token).ConfigureAwait(false);
            if (!await WaitUntilReadableAsync(path, cts.Token).ConfigureAwait(false)) return;
            var result = await _engine.ScanFileAsync(path, cts.Token).ConfigureAwait(false);
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

    private static async Task<bool> WaitUntilReadableAsync(string path, CancellationToken token)
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
        return false;
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
        => Error?.Invoke(this, $"Realtime protection watcher error: {e.GetException().Message}");

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
