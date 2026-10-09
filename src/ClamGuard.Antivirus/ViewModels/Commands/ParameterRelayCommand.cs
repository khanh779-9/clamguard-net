using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace ClamGuard.Antivirus.ViewModels;

internal sealed class ParameterRelayCommand<T> : ICommand
{
    private readonly Action<T> _execute;
    private readonly Func<bool>? _canExecute;

    public ParameterRelayCommand(Action<T> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => parameter is T && (_canExecute?.Invoke() ?? true);
    public void Execute(object? parameter)
    {
        if (parameter is T value) _execute(value);
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
