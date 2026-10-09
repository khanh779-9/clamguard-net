namespace ClamGuard.Signatures.Patterns;

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
