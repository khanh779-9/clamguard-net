using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace ClamGuard.Antivirus.Converters;

public sealed class NavIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string tag) return DependencyProperty.UnsetValue;
        var key = tag switch
        {
            "Overview" => "Icon.Home",
            "Scan" => "Icon.Scan",
            "Update" => "Icon.Update",
            "Security" => "Icon.Security",
            "History" => "Icon.History",
            "Quarantine" => "Icon.Quarantine",
            "Tools" => "Icon.Tools",
            "System" => "Icon.Memory",
            "Settings" => "Icon.Settings",
            _ => "Icon.Home"
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}