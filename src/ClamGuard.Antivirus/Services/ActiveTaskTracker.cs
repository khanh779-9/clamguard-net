using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using ClamGuard.Antivirus.Models;

namespace ClamGuard.Antivirus.Services;

public sealed class ActiveTaskTracker
{
    private int _sequence;

    public ObservableCollection<ActiveTaskItem> ActiveTasks { get; } = [];

    public bool HasActiveTasks => ActiveTasks.Count > 0;
    public bool HasActiveScans => ActiveTasks.Any(t => t.IsScan);

    public event EventHandler? Changed;
    public event EventHandler? ProgressChanged;

    public ActiveTaskItem Start(string kind, string title, string target, bool isCancellable = false, CancellationToken externalToken = default)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        var item = new ActiveTaskItem($"task-{Interlocked.Increment(ref _sequence)}", kind, title, target, isCancellable, cts);
        item.ProgressChanged += (_, _) => ProgressChanged?.Invoke(this, EventArgs.Empty);
        ActiveTasks.Add(item);
        Changed?.Invoke(this, EventArgs.Empty);
        return item;
    }

    public void Complete(ActiveTaskItem item)
    {
        if (ActiveTasks.Remove(item))
            Changed?.Invoke(this, EventArgs.Empty);
    }

    public void CancelScans()
    {
        foreach (var item in ActiveTasks.Where(t => t.IsScan).ToArray())
            item.Cancel();
    }
}
