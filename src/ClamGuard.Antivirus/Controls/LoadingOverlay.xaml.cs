using System.Windows;
using System.Windows.Controls;

namespace ClamGuard.Antivirus.Controls;

public partial class LoadingOverlay : UserControl
{
    public static readonly DependencyProperty BusyTitleProperty =
        DependencyProperty.Register(
            nameof(BusyTitle),
            typeof(string),
            typeof(LoadingOverlay),
            new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty BusyMessageProperty =
        DependencyProperty.Register(
            nameof(BusyMessage),
            typeof(string),
            typeof(LoadingOverlay),
            new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty ShowProgressProperty =
        DependencyProperty.Register(
            nameof(ShowProgress),
            typeof(bool),
            typeof(LoadingOverlay),
            new PropertyMetadata(true));

    public static readonly DependencyProperty ShowCancelProperty =
        DependencyProperty.Register(
            nameof(ShowCancel),
            typeof(bool),
            typeof(LoadingOverlay),
            new PropertyMetadata(false));

    public LoadingOverlay()
    {
        InitializeComponent();
    }

    public event RoutedEventHandler? CancelClicked;

    public string BusyTitle
    {
        get => (string)GetValue(BusyTitleProperty);
        set => SetValue(BusyTitleProperty, value);
    }

    public string BusyMessage
    {
        get => (string)GetValue(BusyMessageProperty);
        set => SetValue(BusyMessageProperty, value);
    }

    public bool ShowProgress
    {
        get => (bool)GetValue(ShowProgressProperty);
        set => SetValue(ShowProgressProperty, value);
    }

    public bool ShowCancel
    {
        get => (bool)GetValue(ShowCancelProperty);
        set => SetValue(ShowCancelProperty, value);
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        CancelClicked?.Invoke(this, e);
    }
}
