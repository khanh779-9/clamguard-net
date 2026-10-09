namespace ClamGuard.Scanner;

internal sealed record LdbScanContext(
    string FileType,
    long FileSize,
    LdbExecutableInfo? Executable,
    IReadOnlyList<string> ParentTypes,
    bool Retyped = false);
