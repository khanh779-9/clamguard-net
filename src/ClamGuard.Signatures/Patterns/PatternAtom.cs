namespace ClamGuard.Signatures.Patterns;

public abstract record PatternAtom
{
    public abstract int MinLength { get; }
    public abstract int MaxLength { get; }
}

public sealed record ExactByteAtom(byte Value) : PatternAtom
{
    public override int MinLength => 1;
    public override int MaxLength => 1;
}

public sealed record MaskedByteAtom(byte Value, byte Mask) : PatternAtom
{
    public override int MinLength => 1;
    public override int MaxLength => 1;
}

public sealed record GapAtom(int MinBytes, int MaxBytes) : PatternAtom
{
    public override int MinLength => MinBytes;
    public override int MaxLength => MaxBytes;
}

public enum CharacterClassKind
{
    WordBoundary,
    LineBoundary,
    NonAlphanumeric
}

/// <summary>
/// ClamAV body-signature character classes: (B), (L), and (W).
/// B and L are zero-width assertions; W consumes one non-alphanumeric byte.
/// </summary>
public sealed record CharacterClassAtom(CharacterClassKind Kind) : PatternAtom
{
    public override int MinLength => Kind switch
    {
        CharacterClassKind.NonAlphanumeric => 1,
        CharacterClassKind.WordBoundary => 0,
        CharacterClassKind.LineBoundary => 0,
        _ => 0
    };

    public override int MaxLength => MinLength;
}

/// <summary>
/// Generic alternate. Alternatives can be variable-length and may themselves contain
/// wildcards/ranges. Negated alternates are only valid for the fixed-length legacy form.
/// </summary>
public sealed record AlternatePatternAtom(
    IReadOnlyList<HexPattern> Alternatives,
    bool Negated = false) : PatternAtom
{
    public override int MinLength => Alternatives.Count == 0 ? 0 : Alternatives.Min(x => x.MinLength);
    public override int MaxLength => Alternatives.Count == 0
        ? 0
        : Alternatives.Any(x => x.MaxLength == int.MaxValue)
            ? int.MaxValue
            : Alternatives.Max(x => x.MaxLength);
}
