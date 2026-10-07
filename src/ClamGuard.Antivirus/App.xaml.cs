using System.Windows;
using ClamGuard.Antivirus.Services;
using ClamGuard.Antivirus.Localization;

namespace ClamGuard.Antivirus;

public partial class App : Application
{
    public static ThemeService Theme { get; } = new();
    public static JsonSettingsStore SettingsStore { get; } = new();
    public static AppSettings Settings { get; private set; } = new();
    public static LocalizationService Localization => LocalizationService.Instance;

    protected override void OnStartup(StartupEventArgs e)
    {
        Settings = SettingsStore.Load();
        Theme.Apply(Settings.Theme);
        Localization.Apply(Settings.Language);
        base.OnStartup(e);

        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        SettingsStore.Save(Settings);
        base.OnExit(e);
    }

    public static void SaveSettings()
    {
        SettingsStore.Save(Settings);
    }
}
