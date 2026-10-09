namespace ClamGuard.Scanner;

internal sealed record LdbSection(long RawOffset, long RawSize, long VirtualAddress, long VirtualSize);
