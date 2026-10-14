using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace ClamGuard.Antivirus.ViewModels;

internal sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private int _running;

    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _running == 0 && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0) return;
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        try { await _execute(); }
        catch (Exception ex)
        {
            // The UI caller owns user-facing error policy, but the failure must
            // not vanish: log so global handlers/trace show what was swallowed.
            System.Diagnostics.Trace.WriteLine($"[ClamGuard] AsyncRelayCommand error: {ex}");
        }
        finally
        {
            Volatile.Write(ref _running, 0);
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public event EventHandler? CanExecuteChanged;
}
