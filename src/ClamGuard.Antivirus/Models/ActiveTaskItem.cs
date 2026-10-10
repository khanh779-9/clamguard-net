using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;

namespace ClamGuard.Antivirus.Models;

public sealed class ActiveTaskItem : INotifyPropertyChanged
{
    private readonly CancellationTokenSource _cts;
    private readonly bool _isCancellable;
    private int _scannedCount;
    private int _totalToScan;
    private int _threatsFound;
    private double _percent;
    private string _currentFile = string.Empty;
    private string _progressText = string.Empty;
    private bool _cancelled;

    internal ActiveTaskItem(string id, string kind, string title, string target, bool isCancellable, CancellationTokenSource cts)
    {
        Id = id;
        Kind = kind;
        Title = title;
        Target = target;
        _isCancellable = isCancellable;
        _cts = cts;
        StartedAt = DateTimeOffset.Now;
    }

    public string Id { get; }
    public string Kind { get; }
    public string Title { get; }
    public string Target { get; }
    public DateTimeOffset StartedAt { get; }
    public bool IsCancellable => _isCancellable && !_cancelled;
    public bool IsScan => Kind is "ScanFile" or "ScanFolder";

    internal CancellationToken Token => _cts.Token;

    public int ScannedCount { get => _scannedCount; set => SetField(ref _scannedCount, value); }
    public int TotalToScan { get => _totalToScan; set => SetField(ref _totalToScan, value); }
    public int ThreatsFound { get => _threatsFound; set => SetField(ref _threatsFound, value); }
    public double Percent { get => _percent; set => SetField(ref _percent, value); }
    public string CurrentFile { get => _currentFile; set => SetField(ref _currentFile, value); }
    public string ProgressText { get => _progressText; set => SetField(ref _progressText, value); }

    internal event EventHandler? ProgressChanged;

    public void Cancel()
    {
        if (_cancelled) return;
        _cancelled = true;
        OnPropertyChanged(nameof(IsCancellable));
        try { _cts.Cancel(); }
        catch (ObjectDisposedException) { }
        catch (AggregateException) { }
    }

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        OnPropertyChanged(propertyName);
        ProgressChanged?.Invoke(this, EventArgs.Empty);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public event PropertyChangedEventHandler? PropertyChanged;
}
