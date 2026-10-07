using System.IO;
using System.Text.Json;

namespace ClamGuard.Antivirus.Services;

public sealed class JsonSettingsStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public AppSettings Load()
    {
        try
        {
            AppPaths.EnsureDirectories();
            if (!File.Exists(AppPaths.SettingsFile)) return new AppSettings();
            var json = File.ReadAllText(AppPaths.SettingsFile);
            var settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            if (string.IsNullOrWhiteSpace(settings.DatabaseDirectory) ||
                settings.DatabaseDirectory.Contains(@"AppData\Local\ClamGuard", StringComparison.OrdinalIgnoreCase))
            {
                settings.DatabaseDirectory = AppPaths.DatabaseDirectory;
            }
            if (settings.RealtimeDirectory is null) settings.RealtimeDirectory = string.Empty;
            settings.Theme = string.Equals(settings.Theme, "Light", StringComparison.OrdinalIgnoreCase) ? "Light" : "Dark";
            return settings;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        try
        {
            AppPaths.EnsureDirectories();
            var json = JsonSerializer.Serialize(settings, Options);
            File.WriteAllText(AppPaths.SettingsFile, json);
        }
        catch
        {
            // Settings should never prevent the application from closing.
        }
    }
}
