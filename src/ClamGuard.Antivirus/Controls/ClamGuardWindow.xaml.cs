using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shell;
using System.Linq;
using ShapePath = System.Windows.Shapes.Path;

namespace ClamGuard.Antivirus.Controls;

public class ClamGuardWindow : Window
{
    private const string StyleKey = "Style.ClamGuardWindow";
    private const string StylePath = "pack://application:,,,/ClamGuard.Antivirus;component/Controls/ClamGuardWindow.xaml";

    private Border? _titleBar;
    private Button? _minimizeButton;
    private Button? _maximizeButton;
    private ShapePath? _maximizeIcon;
    private ClamGuardToastHost? _toastHost;
    private Grid? _dialogOverlay;
    private ItemsControl? _dialogHost;

    public ClamGuardWindow()
    {
        WindowChrome.SetWindowChrome(this, new WindowChrome
        {
            CaptionHeight = 38,
            ResizeBorderThickness = new Thickness(6),
            CornerRadius = new CornerRadius(0),
            GlassFrameThickness = new Thickness(0),
            UseAeroCaptionButtons = false
        });

        var style = TryFindResource(StyleKey) as Style ?? LoadStyle();
        if (style is not null)
            Style = style;

        StateChanged += (_, _) => UpdateMaximizeIcon();
        App.Theme.ThemeChanged += Theme_Changed;
        Closed += (_, _) => App.Theme.ThemeChanged -= Theme_Changed;
    }

    private static Style? LoadStyle()
    {
        try
        {
            var dictionary = new ResourceDictionary { Source = new Uri(StylePath, UriKind.Absolute) };
            return dictionary[StyleKey] as Style;
        }
        catch
        {
            return null;
        }
    }

    public override void OnApplyTemplate()
    {
        base.OnApplyTemplate();

        if (_titleBar is not null)
            _titleBar.MouseLeftButtonDown -= TitleBar_MouseLeftButtonDown;
        if (_minimizeButton is not null)
            _minimizeButton.Click -= MinimizeButton_Click;
        if (_maximizeButton is not null)
            _maximizeButton.Click -= MaximizeButton_Click;

        _titleBar = GetTemplateChild("PART_TitleBar") as Border;
        _minimizeButton = GetTemplateChild("PART_Minimize") as Button;
        _maximizeButton = GetTemplateChild("PART_Maximize") as Button;
        _maximizeIcon = GetTemplateChild("PART_MaximizeIcon") as ShapePath;
        var closeButton = GetTemplateChild("PART_Close") as Button;
        _toastHost = GetTemplateChild("PART_ToastHost") as ClamGuardToastHost;
        _dialogOverlay = GetTemplateChild("PART_DialogOverlay") as Grid;
        _dialogHost = GetTemplateChild("PART_DialogHost") as ItemsControl;

        if (_titleBar is not null)
            _titleBar.MouseLeftButtonDown += TitleBar_MouseLeftButtonDown;
        if (_minimizeButton is not null)
            _minimizeButton.Click += MinimizeButton_Click;
        if (_maximizeButton is not null)
            _maximizeButton.Click += MaximizeButton_Click;
        if (closeButton is not null)
            closeButton.Click += CloseButton_Click;

        UpdateMaximizeIcon();
    }

    private void Theme_Changed(object? sender, EventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            _toastHost?.RefreshTheme();
            if (_dialogHost is null) return;
            foreach (var dialog in _dialogHost.Items.OfType<ClamGuardDialog>())
                dialog.RefreshTheme();
        });
    }

    private void UpdateMaximizeIcon()
    {
        if (_maximizeIcon is null) return;
        _maximizeIcon.Data = (Geometry)FindResource(WindowState == WindowState.Maximized ? "Icon.Restore" : "Icon.Maximize");
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left)
            return;

        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            e.Handled = true;
            return;
        }

        if (WindowState != WindowState.Maximized)
            DragMove();
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void MaximizeButton_Click(object sender, RoutedEventArgs e) => ToggleMaximize();

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize()
        => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void EnsureTemplate()
    {
        if (_toastHost is null || _dialogOverlay is null || _dialogHost is null)
            ApplyTemplate();
    }

    public void ShowToast(string title, string message, ToastKind kind = ToastKind.Info, bool showOnDesktop = true)
    {
        EnsureTemplate();
        _toastHost?.Show(title, message, kind);

        if (showOnDesktop)
        {
            DesktopToastWindow.ShowDesktop(title, message, kind);
        }
    }

    public async Task<bool> ShowDialogAsync(string title, string message, string primaryText,
        string secondaryText, ToastKind kind = ToastKind.Info)
    {
        EnsureTemplate();
        if (_dialogOverlay is null || _dialogHost is null)
            return false;

        var dialog = new ClamGuardDialog
        {
            Title = title,
            Message = message,
            PrimaryText = primaryText,
            SecondaryText = secondaryText,
            Kind = kind
        };

        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        dialog.Completed += (_, accepted) => completion.TrySetResult(accepted);
        _dialogHost.Items.Add(dialog);
        _dialogOverlay.Visibility = Visibility.Visible;
        KeyboardNavigation.SetTabNavigation(_dialogOverlay, KeyboardNavigationMode.Cycle);
        dialog.FocusPrimary();

        var result = await completion.Task;
        _dialogHost.Items.Remove(dialog);
        if (_dialogHost.Items.Count == 0)
            _dialogOverlay.Visibility = Visibility.Collapsed;
        return result;
    }
}
