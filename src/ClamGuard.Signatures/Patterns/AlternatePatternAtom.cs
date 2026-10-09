namespace ClamGuard.Signatures.Patterns;

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
