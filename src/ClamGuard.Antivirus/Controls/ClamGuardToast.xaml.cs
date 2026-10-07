using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace ClamGuard.Antivirus.Controls;

public partial class ClamGuardToast : INotifyPropertyChanged
{
    public ClamGuardToast()
    {
        InitializeComponent();
        DataContext = this;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? CloseRequested;

    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(ClamGuardToast),
            new PropertyMetadata(string.Empty, OnVisualPropertyChanged));

    public static readonly DependencyProperty MessageProperty =
        DependencyProperty.Register(nameof(Message), typeof(string), typeof(ClamGuardToast),
            new PropertyMetadata(string.Empty, OnVisualPropertyChanged));

    public static readonly DependencyProperty KindProperty =
        DependencyProperty.Register(nameof(Kind), typeof(ToastKind), typeof(ClamGuardToast),
            new PropertyMetadata(ToastKind.Info, OnVisualPropertyChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public string Message
    {
        get => (string)GetValue(MessageProperty);
        set => SetValue(MessageProperty, value);
    }

    public ToastKind Kind
    {
        get => (ToastKind)GetValue(KindProperty);
        set => SetValue(KindProperty, value);
    }

    private static void OnVisualPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ClamGuardToast toast)
            toast.RefreshTheme();
    }

    public Brush AccentBrush => (Brush)Application.Current.FindResource(Kind switch
    {
        ToastKind.Success => "Brush.Success",
        ToastKind.Warning => "Brush.Warning",
        ToastKind.Error => "Brush.Danger",
        _ => "Brush.Primary"
    });

    public Geometry IconData => (Geometry)Application.Current.FindResource(Kind switch
    {
        ToastKind.Success => "Icon.CheckCircle",
        ToastKind.Warning => "Icon.Warning",
        ToastKind.Error => "Icon.Warning",
        _ => "Icon.Info"
    });

    private void CloseButton_Click(object sender, RoutedEventArgs e) => CloseRequested?.Invoke(this, EventArgs.Empty);

    public void RefreshTheme()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Title)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Message)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(AccentBrush)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IconData)));
    }
}
