namespace ClamGuard.Signatures;

/// <summary>One ClamAV .idb perceptual icon metric.</summary>
public sealed record IconMetric(
    int Side,
    uint[] ColorAvg, byte[] ColorX, byte[] ColorY,
    uint[] GrayAvg, byte[] GrayX, byte[] GrayY,
    byte[] BrightAvg, byte[] BrightX, byte[] BrightY,
    byte[] DarkAvg, byte[] DarkX, byte[] DarkY,
    byte[] EdgeAvg, byte[] EdgeX, byte[] EdgeY,
    byte[] NoEdgeAvg, byte[] NoEdgeX, byte[] NoEdgeY,
    byte RSum, byte GSum, byte BSum, byte CCount);

public sealed record IconDatabaseEntry(string Name, string Group1, string Group2, IconMetric Metric)
{
    /// <summary>Original database line, retained only while applying .ign/.ign2 rules during load.</summary>
    public string? SourceEntry { get; set; }
}

public sealed class IconDatabase
{
    private readonly List<IconDatabaseEntry> _entries = [];
    public IReadOnlyList<IconDatabaseEntry> Entries => _entries;

    public void Add(IconDatabaseEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _entries.Add(entry);
    }
}
