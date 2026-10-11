using System.Globalization;
using System.IO;
using Microsoft.Win32;

namespace ClamGuard.Antivirus.Services;

/// <summary>
/// Collects autostart locations (Run/RunOnce keys, Startup folders and
/// auto-start services) and resolves the executable files they reference.
/// </summary>
public sealed class StartupScanService
{
    public sealed record StartupEntry(string Name, string Command, string Source, string? FilePath);

    public IReadOnlyList<StartupEntry> Collect()
    {
        var entries = new List<StartupEntry>();
        CollectRunKeys(entries);
        CollectStartupFolders(entries);
        CollectAutoStartServices(entries);
        return entries;
    }

    /// <summary>Distinct existing file paths referenced by the collected entries.</summary>
    public IReadOnlyList<string> ResolveScanTargets(IReadOnlyList<StartupEntry> entries)
    {
        var targets = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var path = entry.FilePath ?? ResolveExecutable(entry.Command);
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                continue;
            var full = Path.GetFullPath(path);
            if (seen.Add(full))
                targets.Add(full);
        }

        return targets;
    }

    private static void CollectRunKeys(List<StartupEntry> entries)
    {
        CollectRunKey(entries, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run");
        CollectRunKey(entries, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce");
        CollectRunKey(entries, Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run");
        CollectRunKey(entries, Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce");
        CollectRunKey(entries, Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32)");
    }

    private static void CollectRunKey(List<StartupEntry> entries, RegistryKey hive, string subKey, string source)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey);
            if (key is null)
                return;
            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName) as string;
                if (string.IsNullOrWhiteSpace(value))
                    continue;
                entries.Add(new StartupEntry(valueName.Length == 0 ? "(default)" : valueName, value, source, ResolveExecutable(value)));
            }
        }
        catch (System.Security.SecurityException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static void CollectStartupFolders(List<StartupEntry> entries)
    {
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        foreach (var folder in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                continue;

            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var name = Path.GetFileName(file);
                entries.Add(new StartupEntry(name, file, "Startup folder", file));
            }
        }
    }

    private static void CollectAutoStartServices(List<StartupEntry> entries)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null)
                return;
            foreach (var serviceName in services.GetSubKeyNames())
            {
                using var service = services.OpenSubKey(serviceName);
                if (service is null)
                    continue;

                var start = service.GetValue("Start");
                if (start is not int startValue || startValue != 2) // auto-start only
                    continue;

                var imagePath = service.GetValue("ImagePath") as string;
                if (string.IsNullOrWhiteSpace(imagePath))
                    continue;

                var resolved = ResolveExecutable(imagePath);
                if (resolved is null)
                    continue;

                entries.Add(new StartupEntry(serviceName, imagePath, "Service (auto)", resolved));
            }
        }
        catch (System.Security.SecurityException) { }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Extracts the executable path from a command line: quoted arguments are
    /// honored and unquoted commands fall back to the longest existing prefix.
    /// </summary>
    public static string? ResolveExecutable(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var value = Environment.ExpandEnvironmentVariables(raw.Trim());
        string candidate;
        if (value.Length > 1 && value[0] == '"')
        {
            var end = value.IndexOf('"', 1);
            candidate = end > 1 ? value[1..end] : value[1..];
        }
        else
        {
            candidate = value;
            while (candidate.Length > 0 && !File.Exists(candidate))
            {
                var lastSpace = candidate.LastIndexOf(' ');
                if (lastSpace <= 0)
                    break;
                candidate = candidate[..lastSpace];
            }
        }

        if (candidate.StartsWith(@"\??\", StringComparison.Ordinal))
            candidate = candidate[4..];

        candidate = candidate.Trim().Trim('"');
        if (candidate.Length == 0)
            return null;

        if (!Path.HasExtension(candidate))
            candidate += ".exe";

        return File.Exists(candidate) ? candidate : null;
    }
}
