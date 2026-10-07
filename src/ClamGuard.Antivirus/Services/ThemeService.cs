using System;
using System.Linq;
using System.Windows;
using Microsoft.Win32;

namespace ClamGuard.Antivirus.Services;

public sealed class ThemeService
{
    public event EventHandler? ThemeChanged;

    public string CurrentTheme => App.Settings.Theme;

    public bool IsDark
    {
        get
        {
            var current = App.Settings.Theme;
            if (string.Equals(current, "Auto", StringComparison.OrdinalIgnoreCase))
                return IsWindowsDarkTheme();
            return string.Equals(current, "Dark", StringComparison.OrdinalIgnoreCase);
        }
    }

    public void Apply(string theme)
    {
        string normalized = theme switch
        {
            _ when string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase) => "Light",
            _ when string.Equals(theme, "Auto", StringComparison.OrdinalIgnoreCase) => "Auto",
            _ => "Dark"
        };

        App.Settings.Theme = normalized;

        var effectiveTheme = string.Equals(normalized, "Auto", StringComparison.OrdinalIgnoreCase)
            ? (IsWindowsDarkTheme() ? "Dark" : "Light")
            : normalized;

        var dictionaries = Application.Current.Resources.MergedDictionaries;
        var themeDictionary = dictionaries.FirstOrDefault(d =>
            d.Source?.OriginalString.EndsWith("LightTheme.xaml", StringComparison.OrdinalIgnoreCase) == true ||
            d.Source?.OriginalString.EndsWith("DarkTheme.xaml", StringComparison.OrdinalIgnoreCase) == true);

        var newDictionary = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/ClamGuard.Antivirus;component/Theme/{effectiveTheme}Theme.xaml", UriKind.Absolute)
        };

        if (themeDictionary is null)
        {
            dictionaries.Insert(0, newDictionary);
        }
        else
        {
            var index = dictionaries.IndexOf(themeDictionary);
            dictionaries[index] = newDictionary;
        }

        ThemeChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Toggle() => Apply(IsDark ? "Light" : "Dark");

    private static bool IsWindowsDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            var val = key?.GetValue("AppsUseLightTheme");
            if (val is int intVal)
                return intVal == 0;
        }
        catch
        {
            // Fallback default
        }
        return true;
    }
}

