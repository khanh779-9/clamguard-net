using System.Collections.ObjectModel;
using System.Windows.Threading;

namespace ClamGuard.Antivirus.Controls;

public partial class ClamGuardToastHost
{
    public ObservableCollection<ClamGuardToast> Items { get; } = [];

    public ClamGuardToastHost() => InitializeComponent();

    public void RefreshTheme()
    {
        foreach (var toast in Items)
            toast.RefreshTheme();
    }

    public void Show(string title, string message, ToastKind kind)
    {
        var toast = new ClamGuardToast { Title = title, Message = message, Kind = kind };
        void Remove(object? sender, EventArgs e)
        {
            toast.CloseRequested -= Remove;
            Items.Remove(toast);
        }

        toast.CloseRequested += Remove;
        Items.Add(toast);

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            Remove(null, EventArgs.Empty);
        };
        timer.Start();
    }
}
