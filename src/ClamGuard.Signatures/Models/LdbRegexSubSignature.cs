namespace ClamGuard.Signatures;

public sealed record LdbRegexSubSignature(
    int Index,
    string Trigger,
    string Pattern,
    string Flags,
    string OffsetExpression);
