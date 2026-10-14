using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using ClamGuard.Antivirus.Services;
using ClamGuard.Antivirus.Localization;

namespace ClamGuard.Antivirus;

public partial class App : Application
{
    public static ThemeService Theme { get; } = new();
    public static JsonSettingsStore SettingsStore { get; } = new();
    public static AppSettings Settings { get; private set; } = new();
    public static LocalizationService Localization => LocalizationService.Instance;

    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    // Non-fatal UI faults: log and suppress; the app has no error surface to show.
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Trace.WriteLine($"[ClamGuard] Unhandled UI exception: {e.Exception}");
        e.Handled = true;
    }

    private void OnAppDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        Trace.WriteLine($"[ClamGuard] Unhandled AppDomain exception (terminating: {e.IsTerminating}): {e.ExceptionObject}");
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        Trace.WriteLine($"[ClamGuard] Unobserved task exception: {e.Exception}");
    }

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
