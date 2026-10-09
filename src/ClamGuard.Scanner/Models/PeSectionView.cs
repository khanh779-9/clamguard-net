namespace ClamGuard.Scanner;

internal sealed record PeSectionView(string Name, long RawOffset, long RawSize, long VirtualAddress, long VirtualSize);
