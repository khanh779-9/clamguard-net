using System.ComponentModel;
using System.Runtime.CompilerServices;
using ClamGuard.Core;

namespace ClamGuard.Antivirus.Models;

public enum ThreatResolutionAction
{
    Quarantine,
    Delete,
    Ignore
}

public sealed class ScanResultRowItem : INotifyPropertyChanged
{
    private ThreatResolutionAction _selectedAction;
    private string _status = "Pending";
    private bool _isProcessed;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string FilePath { get; set; } = string.Empty;
    public string FileName => System.IO.Path.GetFileName(FilePath);
    public ScanVerdict Verdict { get; set; }
    public string ThreatName { get; set; } = string.Empty;
    public TimeSpan Duration { get; set; }
    public long FileSizeBytes { get; set; }

    public bool IsThreat => Verdict is ScanVerdict.Malicious or ScanVerdict.PotentiallyUnwanted or ScanVerdict.StrongIndicator;

    public ThreatResolutionAction SelectedAction
    {
        get => _selectedAction;
        set
        {
            if (_selectedAction != value)
            {
                _selectedAction = value;
                OnPropertyChanged();
            }
        }
    }

    public string Status
    {
        get => _status;
        set
        {
            if (_status != value)
            {
                _status = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsProcessed
    {
        get => _isProcessed;
        set
        {
            if (_isProcessed != value)
            {
                _isProcessed = value;
                OnPropertyChanged();
            }
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? prop = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
}
