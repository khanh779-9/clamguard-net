namespace ClamGuard.Signatures.Patterns;

public sealed record ExactByteAtom(byte Value) : PatternAtom
{
    public override int MinLength => 1;
    public override int MaxLength => 1;
}
