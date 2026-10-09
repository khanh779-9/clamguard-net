namespace ClamGuard.Signatures.Patterns;

public sealed record GapAtom(int MinBytes, int MaxBytes) : PatternAtom
{
    public override int MinLength => MinBytes;
    public override int MaxLength => MaxBytes;
}
