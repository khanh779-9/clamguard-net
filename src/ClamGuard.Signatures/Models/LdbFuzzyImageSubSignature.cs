namespace ClamGuard.Signatures;

public sealed record LdbFuzzyImageSubSignature(
    int Index,
    byte[] Hash,
    uint HammingDistance);
