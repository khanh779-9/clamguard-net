using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.IO;

namespace ClamGuard.Antivirus.Localization;

public sealed class LocalizationService : INotifyPropertyChanged
{
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);
    private string _language = "en-US";

    public static LocalizationService Instance { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? LanguageChanged;

    public string Language => _language;

    public string this[string key] => Get(key);

    public IReadOnlyList<string> AvailableLanguages { get; } = ["en-US", "vi-VN"];

    public void Apply(string language)
    {
        var normalized = AvailableLanguages.Contains(language, StringComparer.OrdinalIgnoreCase)
            ? AvailableLanguages.First(x => string.Equals(x, language, StringComparison.OrdinalIgnoreCase))
            : "en-US";

        var parsed = LoadFile(normalized);
        _values.Clear();
        foreach (var pair in parsed)
            _values[pair.Key] = pair.Value;

        _language = normalized;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(normalized);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(normalized);
        }
        catch (CultureNotFoundException)
        {
            // Keep the application usable even when a trimmed runtime does not expose a culture.
        }

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }

    public string Get(string key)
        => _values.TryGetValue(key, out var value) ? value : key;

    public string Format(string key, params object[] args)
    {
        var value = Get(key);
        return args.Length == 0 ? value : string.Format(CultureInfo.CurrentCulture, value, args);
    }

    private static Dictionary<string, string> LoadFile(string language)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Prefer an external .lng file so installations can add or replace translations
        // without recompiling the UI. Fall back to the embedded copy shipped with the project.
        var externalPath = Path.Combine(AppContext.BaseDirectory, "Localization", $"{language}.lng");
        if (File.Exists(externalPath))
        {
            using var externalReader = new StreamReader(externalPath);
            Parse(externalReader, result);
            return result;
        }

        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(x => x.EndsWith($"Localization.{language}.lng", StringComparison.OrdinalIgnoreCase));

        if (resourceName is null)
            return result;

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null) return result;
        using var reader = new StreamReader(stream);
        Parse(reader, result);
        return result;
    }

    private static void Parse(TextReader reader, Dictionary<string, string> result)
    {
        string? section = null;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            line = line.Trim();
            if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#'))
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator <= 0) continue;

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (!string.IsNullOrEmpty(section))
                result[$"{section}.{key}"] = Unescape(value);
            else
                result[key] = Unescape(value);
        }

    }

    private static string Unescape(string value)
        => value.Replace("\\n", "\n", StringComparison.Ordinal)
                .Replace("\\r", "\r", StringComparison.Ordinal)
                .Replace("\\=", "=", StringComparison.Ordinal)
                .Replace("\\\\", "\\", StringComparison.Ordinal);
}
