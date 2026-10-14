using System;
using System.Text;
using System.Windows.Controls;
using ClamGuard.Antivirus.Models;

namespace ClamGuard.Antivirus.Views;

public partial class HistoryView : UserControl
{
    public HistoryView()
    {
        InitializeComponent();
        App.Localization.LanguageChanged += OnLanguageChanged;
        Unloaded += (_, _) => App.Localization.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        if (HistoryGrid.SelectedItem is ScanHistoryItem item)
            HistoryDetailText.Text = FormatDetail(item);
        else
            HistoryDetailText.Text = App.Localization.Get("history.select_entry");
    }

    private void HistoryGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (HistoryGrid.SelectedItem is not ScanHistoryItem item)
        {
            HistoryDetailText.Text = App.Localization.Get("history.select_entry");
            return;
        }

        HistoryDetailText.Text = FormatDetail(item);
    }

    private static string FormatDetail(ScanHistoryItem item)
    {
        var loc = App.Localization;
        var sb = new StringBuilder();
        sb.AppendLine($"{loc.Get("history.kind")}: {item.Kind}");
        sb.AppendLine($"{loc.Get("history.time")}: {item.Time.LocalDateTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"{loc.Get("history.target")}: {item.FullPath}");
        sb.AppendLine($"{loc.Get("history.process")}: {item.ProcessName}");
        sb.AppendLine($"{loc.Get("history.result")}: {item.VerdictText}");
        sb.AppendLine($"{loc.Get("history.duration")}: {item.Duration.TotalMilliseconds:N0} ms");
        sb.AppendLine($"{loc.Get("history.detections")}: {item.DetectionCount}");
        if (!string.IsNullOrWhiteSpace(item.PrimaryDetection))
            sb.Append($"{loc.Get("history.signature")}: {item.PrimaryDetection}");

        return sb.ToString();
    }
}
