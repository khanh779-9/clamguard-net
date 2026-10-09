namespace ClamGuard.Signatures;

public sealed record LdbByteCompareSubSignature(
    int Index,
    int ReferenceSubSignature,
    int Shift,
    ByteCompareOptions Options,
    int ByteLength,
    IReadOnlyList<ByteCompareComparison> Comparisons);
