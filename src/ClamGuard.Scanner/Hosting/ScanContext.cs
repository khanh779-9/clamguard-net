namespace ClamGuard.Scanner;

/// <summary>
/// Recursion depth and shared expansion budget threaded through every nested
/// layer re-entry (specialized handlers → ScanNestedBytes → ScanBuffer, and
/// container expansion). Without a shared context each re-entry restarted at
/// depth 0 with a fresh ArchiveScanBudget, so a crafted cycle
/// (zip → OneNote → zip → …) could recurse until StackOverflowException.
/// The budget is intentionally only consumed at materialization points
/// (TryReadStream/ConsumeBudget); layer sizes already materialized by a parent
/// are not consumed twice.
/// </summary>
internal sealed class ScanContext
{
    internal ScanContext(int depth, ArchiveScanBudget? budget)
    {
        Depth = depth;
        Budget = budget;
    }

    public int Depth { get; }

    public ArchiveScanBudget? Budget { get; }

    public static ScanContext CreateRoot() => new(0, null);

    public ScanContext Descend() => new(Depth + 1, Budget);
}
