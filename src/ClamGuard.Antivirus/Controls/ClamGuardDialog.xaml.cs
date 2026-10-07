using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace ClamGuard.Antivirus.Controls;

public partial class ClamGuardDialog : INotifyPropertyChanged
{
    private string _title = string.Empty;
    private string _message = string.Empty;
    private string _primaryText = "OK";
    private string _secondaryText = "Cancel";
    private ToastKind _kind = ToastKind.Info;

    public ClamGuardDialog()
    {
        InitializeComponent();
        DataContext = this;
    }

    public event EventHandler<bool>? Completed;
    public event PropertyChangedEventHandler? PropertyChanged;

    public string Title
    {
        get => _title;
        set
        {
            if (_title != value)
            {
                _title = value;
                OnPropertyChanged(nameof(Title));
            }
        }
    }

    public string Message
    {
        get => _message;
        set
        {
            if (_message != value)
            {
                _message = value;
                OnPropertyChanged(nameof(Message));
            }
        }
    }

    public string PrimaryText
    {
        get => _primaryText;
        set
        {
            if (_primaryText != value)
            {
                _primaryText = value;
                OnPropertyChanged(nameof(PrimaryText));
            }
        }
    }

    public string SecondaryText
    {
        get => _secondaryText;
        set
        {
            if (_secondaryText != value)
            {
                _secondaryText = value;
                OnPropertyChanged(nameof(SecondaryText));
                OnPropertyChanged(nameof(HasSecondary));
            }
        }
    }

    public bool HasSecondary => !string.IsNullOrWhiteSpace(SecondaryText);

    public ToastKind Kind
    {
        get => _kind;
        set
        {
            if (_kind != value)
            {
                _kind = value;
                OnPropertyChanged(nameof(Kind));
                RefreshTheme();
            }
        }
    }

    private void OnPropertyChanged(string propertyName)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

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

    public void RefreshTheme()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(AccentBrush)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IconData)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HasSecondary)));
    }

    public void FocusPrimary() => Dispatcher.BeginInvoke(() => PrimaryButton.Focus());

    private void PrimaryButton_Click(object sender, RoutedEventArgs e) => Completed?.Invoke(this, true);
    private void SecondaryButton_Click(object sender, RoutedEventArgs e) => Completed?.Invoke(this, false);
    private void CloseButton_Click(object sender, RoutedEventArgs e) => Completed?.Invoke(this, false);
}

