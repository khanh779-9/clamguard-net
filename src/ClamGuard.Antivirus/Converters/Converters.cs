using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using ClamGuard.Antivirus.Localization;
using ClamGuard.Core;

namespace ClamGuard.Antivirus.Converters;

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b && !b;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : Binding.DoNothing;
}

public sealed class InverseBooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b && b ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is Visibility v && v != Visibility.Visible;
}

public sealed class ActionTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value switch
        {
            Models.ThreatResolutionAction.Quarantine => LocalizationService.Instance.Get("scan.act_quarantine"),
            Models.ThreatResolutionAction.Delete => LocalizationService.Instance.Get("scan.act_delete"),
            Models.ThreatResolutionAction.Ignore => LocalizationService.Instance.Get("scan.act_ignore"),
            _ => value?.ToString() ?? string.Empty
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class BoolTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => LocalizationService.Instance.Get(value is bool b && b ? "common.on" : "common.off");

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ReadyTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => LocalizationService.Instance.Get(value is bool b && b ? "common.ready" : "common.not_ready");

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ReadyBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => Application.Current.FindResource(value is bool b && b ? "Brush.Success" : "Brush.Danger");

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class ReadySoftBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => Application.Current.FindResource(value is bool b && b ? "Brush.SuccessSoft" : "Brush.DangerSoft");

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class VerdictBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var verdict = value is ScanVerdict v ? v : ScanVerdict.Error;
        var brush = verdict switch
        {
            ScanVerdict.Clean or ScanVerdict.Trusted => "Brush.Success",
            ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator => "Brush.Danger",
            _ => "Brush.Warning"
        };
        return Application.Current.FindResource(brush);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class VerdictTextConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        var verdict = values.Length > 0 && values[0] is ScanVerdict v ? v : ScanVerdict.Error;
        var key = verdict switch
        {
            ScanVerdict.Clean => "history.verdict_clean",
            ScanVerdict.Trusted => "history.verdict_trusted",
            ScanVerdict.Malicious => "history.verdict_threat",
            ScanVerdict.PotentiallyUnwanted => "history.verdict_pua",
            ScanVerdict.StrongIndicator => "history.verdict_indicator",
            ScanVerdict.Timeout => "history.verdict_timeout",
            _ => "history.verdict_error"
        };
        return LocalizationService.Instance.Get(key);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => new[] { Binding.DoNothing, Binding.DoNothing };
}
