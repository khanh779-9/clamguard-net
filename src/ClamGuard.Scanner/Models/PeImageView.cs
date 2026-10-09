namespace ClamGuard.Scanner;

internal sealed class PeImageView
{
    public required bool IsPe32Plus { get; init; }
    public required int NumberOfSections { get; init; }
    public required int OptionalHeaderOffset { get; init; }
    public required int OptionalHeaderSize { get; init; }
    public required int DataDirectoryOffset { get; init; }
    public required IReadOnlyList<PeSectionView> Sections { get; init; }
    public required uint ImportRva { get; init; }
    public required uint ImportSize { get; init; }
    public required long OverlayOffset { get; init; }
    public required long OverlaySize { get; init; }
}
