using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace ClamGuard.Antivirus.Services;

public sealed class JsonSettingsStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public AppSettings Load()
    {
        var settings = TryRead(AppPaths.SettingsFile);
        if (settings is null)
        {
            // A leftover .tmp means a previous atomic save was interrupted
            // mid-write; prefer its contents over resetting to defaults.
            settings = TryRead(AppPaths.SettingsFile + ".tmp");
        }

        if (settings is null) return new AppSettings();

        if (string.IsNullOrWhiteSpace(settings.DatabaseDirectory) ||
            settings.DatabaseDirectory.Contains(@"AppData\Local\ClamGuard", StringComparison.OrdinalIgnoreCase))
        {
            settings.DatabaseDirectory = AppPaths.DatabaseDirectory;
        }
        if (settings.RealtimeDirectory is null) settings.RealtimeDirectory = string.Empty;
        settings.Theme = string.Equals(settings.Theme, "Light", StringComparison.OrdinalIgnoreCase) ? "Light" : "Dark";
        return settings;
    }

    private static AppSettings? TryRead(string path)
    {
        try
        {
            AppPaths.EnsureDirectories();
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<AppSettings>(json);
            if (settings is null)
            {
                Debug.WriteLine($"[ClamGuard] Settings file '{path}' is empty or invalid; ignored.");
                return null;
            }
            return settings;
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"[ClamGuard] Settings file '{path}' could not be parsed: {ex.Message}");
            return null;
        }
        catch
        {
            return null;
        }
    }

    public void Save(AppSettings settings)
    {
        try
        {
            AppPaths.EnsureDirectories();
            var json = JsonSerializer.Serialize(settings, Options);
            var temp = AppPaths.SettingsFile + ".tmp";
            File.WriteAllText(temp, json);
            File.Move(temp, AppPaths.SettingsFile, overwrite: true);
        }
        catch
        {
            // Settings should never prevent the application from closing.
        }
    }
}
