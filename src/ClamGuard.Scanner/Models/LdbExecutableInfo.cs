namespace ClamGuard.Scanner;

internal sealed class LdbExecutableInfo
{
    public long EntryPoint { get; init; }
    public int NumberOfSections { get; init; }
    public IReadOnlyList<LdbSection> Sections { get; init; } = [];
    public IReadOnlyList<(int Start, int End)> VersionInfoRegions { get; init; } = [];
    public IReadOnlyList<LdbIconGroup> IconGroups { get; init; } = [];
}
