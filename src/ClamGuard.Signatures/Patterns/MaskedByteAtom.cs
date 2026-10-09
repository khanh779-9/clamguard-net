namespace ClamGuard.Signatures.Patterns;

public sealed record MaskedByteAtom(byte Value, byte Mask) : PatternAtom
{
    public override int MinLength => 1;
    public override int MaxLength => 1;
}
