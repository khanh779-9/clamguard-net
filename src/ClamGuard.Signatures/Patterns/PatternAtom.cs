namespace ClamGuard.Signatures.Patterns;

public abstract record PatternAtom
{
    public abstract int MinLength { get; }
    public abstract int MaxLength { get; }
}
