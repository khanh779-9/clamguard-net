namespace ClamGuard.Scanner;

internal readonly record struct LdbOffsetRange(int Start, int EndInclusive, int MaxBound = int.MaxValue)
{
    public bool IsValid => Start >= 0 && EndInclusive >= Start;
}
