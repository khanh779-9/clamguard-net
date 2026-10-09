using ClamGuard.Core;
using ClamGuard.Scanner;

sealed class SlowScanner(TimeSpan delay) : IContentScanner
{
    public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public IReadOnlyList<Detection> Scan(ReadOnlySpan<byte> data, string path, CancellationToken cancellationToken = default)
    {
        Entered.TrySetResult(true);
        cancellationToken.ThrowIfCancellationRequested();
        Thread.Sleep(delay);
        cancellationToken.ThrowIfCancellationRequested();
        return [];
    }
}
