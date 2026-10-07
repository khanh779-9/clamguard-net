using System.Windows;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace ClamGuard.Antivirus.Controls;

public sealed class DesktopToastWindow : Window
{
    private static readonly List<DesktopToastWindow> ActiveToasts = [];
    private static readonly object SyncLock = new();

    private readonly ClamGuardToast _toast;
    private readonly DispatcherTimer _closeTimer;
    private bool _isClosing;

    public DesktopToastWindow(string title, string message, ToastKind kind)
    {
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = System.Windows.Media.Brushes.Transparent;
        Topmost = true;
        ShowInTaskbar = false;
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;

        _toast = new ClamGuardToast
        {
            Title = title,
            Message = message,
            Kind = kind
        };
        _toast.CloseRequested += (_, _) => CloseToastSmoothly();

        Content = _toast;

        _closeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _closeTimer.Tick += (_, _) =>
        {
            _closeTimer.Stop();
            CloseToastSmoothly();
        };

        Loaded += ToastWindow_Loaded;
    }

    public static void ShowDesktop(string title, string message, ToastKind kind)
    {
        var app = Application.Current;
        if (app is null) return;

        if (!app.Dispatcher.CheckAccess())
        {
            app.Dispatcher.BeginInvoke(() => ShowDesktop(title, message, kind));
            return;
        }

        var window = new DesktopToastWindow(title, message, kind);
        lock (SyncLock)
        {
            // Limit stack up to 4 toasts
            if (ActiveToasts.Count >= 4)
            {
                var oldest = ActiveToasts[0];
                oldest.CloseToastSmoothly();
            }
            ActiveToasts.Add(window);
        }

        window.Show();
        RepositionAll();
    }

    private static void RepositionAll()
    {
        lock (SyncLock)
        {
            var workArea = SystemParameters.WorkArea;
            double currentBottom = workArea.Bottom - 18;

            // Iterate newest to oldest from bottom up
            for (int i = ActiveToasts.Count - 1; i >= 0; i--)
            {
                var toastWin = ActiveToasts[i];
                if (toastWin._isClosing) continue;

                double targetLeft = workArea.Right - (toastWin.ActualWidth > 0 ? toastWin.ActualWidth : 390) - 20;
                double toastHeight = toastWin.ActualHeight > 0 ? toastWin.ActualHeight : 70;
                double targetTop = currentBottom - toastHeight;

                toastWin.Left = targetLeft;
                toastWin.Top = Math.Max(workArea.Top + 10, targetTop);

                currentBottom = toastWin.Top - 10;
            }
        }
    }

    private void ToastWindow_Loaded(object sender, RoutedEventArgs e)
    {
        RepositionAll();

        // Slide/fade in animation
        Opacity = 0;
        var animFade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220));
        BeginAnimation(OpacityProperty, animFade);

        _closeTimer.Start();
    }

    private void CloseToastSmoothly()
    {
        if (_isClosing) return;
        _isClosing = true;
        _closeTimer.Stop();

        lock (SyncLock)
        {
            ActiveToasts.Remove(this);
        }

        var animFade = new DoubleAnimation(Opacity, 0, TimeSpan.FromMilliseconds(180));
        animFade.Completed += (_, _) =>
        {
            Close();
            RepositionAll();
        };
        BeginAnimation(OpacityProperty, animFade);
    }
}
