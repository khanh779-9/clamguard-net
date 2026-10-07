using System.Windows.Controls;

namespace ClamGuard.Antivirus.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        Loaded += (_, _) => RefreshSelections();
        App.Localization.LanguageChanged += (_, _) => Dispatcher.Invoke(RefreshSelections);
        App.Theme.ThemeChanged += (_, _) => Dispatcher.Invoke(RefreshSelections);
    }

    public void RefreshSelections()
    {
        if (ThemeComboBox.SelectedValue is null || !string.Equals(ThemeComboBox.SelectedValue.ToString(), App.Settings.Theme, StringComparison.OrdinalIgnoreCase))
            ThemeComboBox.SelectedValue = App.Settings.Theme;

        if (LanguageComboBox.SelectedValue is null || !string.Equals(LanguageComboBox.SelectedValue.ToString(), App.Settings.Language, StringComparison.OrdinalIgnoreCase))
            LanguageComboBox.SelectedValue = App.Settings.Language;
    }

    public void RefreshTheme() => RefreshSelections();
}

