namespace ClamGuard.Scanner;

internal sealed class ArchiveScanBudget
{
    public int Entries;
    public long ExpandedBytes;
    public bool LimitExceeded;
}
