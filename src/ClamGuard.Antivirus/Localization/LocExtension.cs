using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;

namespace ClamGuard.Antivirus.Localization;

[MarkupExtensionReturnType(typeof(object))]
public sealed class LocExtension : MarkupExtension
{
    public LocExtension() { }
    public LocExtension(string key) => Key = key;

    public string Key { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding
        {
            Source = LocalizationService.Instance,
            Path = new PropertyPath($"[{Key}]"),
            Mode = BindingMode.OneWay,
            FallbackValue = Key,
            TargetNullValue = Key
        };
        return binding.ProvideValue(serviceProvider);
    }
}
