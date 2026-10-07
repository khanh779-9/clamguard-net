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
    }

    private void HistoryGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (HistoryGrid.SelectedItem is not ScanHistoryItem item)
        {
            HistoryDetailText.Text = "Select an entry to see details";
            return;
        }

        var sb = new StringBuilder();
        sb.AppendLine($"Kind        : {item.Kind}");
        sb.AppendLine($"Time        : {item.Time.LocalDateTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Target      : {item.FullPath}");
        sb.AppendLine($"Process     : {item.ProcessName}");
        sb.AppendLine($"Result      : {item.VerdictText}");
        sb.AppendLine($"Duration    : {item.Duration.TotalMilliseconds:N0} ms");
        sb.AppendLine($"Detections  : {item.DetectionCount}");
        if (!string.IsNullOrWhiteSpace(item.PrimaryDetection))
            sb.Append($"Signature   : {item.PrimaryDetection}");

        HistoryDetailText.Text = sb.ToString();
    }
}