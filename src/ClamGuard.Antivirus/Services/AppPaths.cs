using System.IO;

namespace ClamGuard.Antivirus.Services;

public static class AppPaths
{
    public const string AppName = "ClamGuard Antivirus";

    public static string RootDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ClamGuard", "Antivirus");

    // Common system database & cache root in C:\ProgramData\ClamGuard
    public static string CommonDataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "ClamGuard");

    public static string DatabaseDirectory => Path.Combine(CommonDataDirectory, "database");
    public static string CacheDirectory => Path.Combine(CommonDataDirectory, "cache");
    public static string YaraDirectory => Path.Combine(CommonDataDirectory, "yara");
    public static string BytecodeDirectory => Path.Combine(CommonDataDirectory, "bytecode");
    public static string SettingsFile => Path.Combine(RootDirectory, "settings.json");
    public static string QuarantineDirectory => Path.Combine(CommonDataDirectory, "quarantine");

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(RootDirectory);
        Directory.CreateDirectory(CommonDataDirectory);
        Directory.CreateDirectory(DatabaseDirectory);
        Directory.CreateDirectory(CacheDirectory);
        Directory.CreateDirectory(YaraDirectory);
        Directory.CreateDirectory(BytecodeDirectory);
        Directory.CreateDirectory(QuarantineDirectory);
    }
}
