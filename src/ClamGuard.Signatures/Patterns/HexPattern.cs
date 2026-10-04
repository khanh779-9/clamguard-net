namespace ClamGuard.Signatures.Patterns;

public readonly record struct PatternMatchOptions(
    bool IgnoreCase = false,
    bool FullWord = false);

public sealed class HexPattern
{
    private const int MaxBacktrackingStates = 250_000;

    public IReadOnlyList<PatternAtom> Atoms { get; }
    public int MinLength => Atoms.Sum(static x => x.MinLength);
    public int MaxLength => Atoms.Any(static x => x.MaxLength == int.MaxValue)
        ? int.MaxValue
        : Atoms.Sum(static x => x.MaxLength);
    public bool IsFixed => Atoms.All(static x => x is ExactByteAtom);
    public bool IsLegacyFixedNegatedAlternate => Atoms.Count == 1 &&
                                                   Atoms[0] is AlternatePatternAtom { Negated: true } alternate &&
                                                   alternate.Alternatives.All(static x => x.IsFixed) &&
                                                   alternate.Alternatives.Select(static x => x.MinLength).Distinct().Count() == 1;

    public HexPattern(IEnumerable<PatternAtom> atoms)
    {
        ArgumentNullException.ThrowIfNull(atoms);
        Atoms = atoms.ToArray();
        if (Atoms.Count == 0)
            throw new ArgumentException("A pattern cannot be empty.", nameof(atoms));
    }

    public byte[] ToFixedBytes()
    {
        if (!IsFixed)
            throw new InvalidOperationException("The pattern contains wildcards, ranges, classes or alternates.");

        return Atoms.Cast<ExactByteAtom>().Select(static x => x.Value).ToArray();
    }


    public HexPattern ToWideVariant()
    {
        var expanded = new List<PatternAtom>();
        foreach (var atom in Atoms)
        {
            switch (atom)
            {
                case ExactByteAtom exact:
                    expanded.Add(exact);
                    expanded.Add(new ExactByteAtom(0));
                    break;
                case MaskedByteAtom masked:
                    expanded.Add(masked);
                    expanded.Add(new ExactByteAtom(0));
                    break;
                case AlternatePatternAtom alternate when !alternate.Negated:
                    expanded.Add(new AlternatePatternAtom(alternate.Alternatives.Select(static x => x.ToWideVariant()).ToArray()));
                    break;
                case AlternatePatternAtom:
                    throw new InvalidOperationException("Negated alternates cannot be widened.");
                case GapAtom gap when gap.MinBytes != int.MaxValue && gap.MaxBytes != int.MaxValue:
                    expanded.Add(new GapAtom(checked(gap.MinBytes * 2), checked(gap.MaxBytes * 2)));
                    break;
                case GapAtom gap when gap.MinBytes == int.MaxValue:
                    expanded.Add(gap);
                    break;
                case GapAtom gap:
                    expanded.Add(new GapAtom(checked(gap.MinBytes * 2), int.MaxValue));
                    break;
                default:
                    expanded.Add(atom);
                    break;
            }
        }
        return new HexPattern(expanded);
    }

    public bool Matches(ReadOnlySpan<byte> data, int start, out int consumed, PatternMatchOptions options = default)
    {
        consumed = 0;
        if (start < 0 || start > data.Length)
            return false;

        var stack = new Stack<(int AtomIndex, int Position)>();
        var visited = new HashSet<(int AtomIndex, int Position)>();
        stack.Push((0, start));
        var states = 0;

        while (stack.Count != 0)
        {
            if (++states > MaxBacktrackingStates)
                return false;

            var (atomIndex, position) = stack.Pop();
            if (!visited.Add((atomIndex, position)))
                continue;

            if (atomIndex == Atoms.Count)
            {
                if (options.FullWord && !IsFullWordBoundary(data, start, position))
                    continue;
                consumed = position - start;
                return true;
            }

            switch (Atoms[atomIndex])
            {
                case ExactByteAtom exact when position < data.Length &&
                    EqualByte(data[position], exact.Value, options.IgnoreCase):
                    stack.Push((atomIndex + 1, position + 1));
                    break;

                case MaskedByteAtom masked when position < data.Length &&
                    MaskedEquals(data[position], masked.Value, masked.Mask, options.IgnoreCase):
                    stack.Push((atomIndex + 1, position + 1));
                    break;

                case GapAtom gap:
                {
                    var available = data.Length - position;
                    var max = gap.MaxBytes == int.MaxValue
                        ? available
                        : Math.Min(gap.MaxBytes, available);

                    if (max >= gap.MinBytes)
                    {
                        for (var n = max; n >= gap.MinBytes; n--)
                            stack.Push((atomIndex + 1, position + n));
                    }
                    break;
                }

                case CharacterClassAtom cls:
                    if (TryMatchCharacterClass(cls.Kind, data, position, out var classConsumed))
                        stack.Push((atomIndex + 1, position + classConsumed));
                    break;

                case AlternatePatternAtom alternate:
                    MatchAlternate(alternate, data, atomIndex + 1, position, options, stack);
                    break;
            }
        }

        return false;
    }

    private static void MatchAlternate(
        AlternatePatternAtom alternate,
        ReadOnlySpan<byte> data,
        int nextAtom,
        int position,
        PatternMatchOptions options,
        Stack<(int AtomIndex, int Position)> stack)
    {
        if (alternate.Negated)
        {
            // ClamAV only permits negated legacy fixed-length alternates.
            if (!TryGetCommonFixedLength(alternate.Alternatives, out var length) || position + length > data.Length)
                return;

            var nestedOptions = options with { FullWord = false };
            var isMember = false;
            foreach (var pattern in alternate.Alternatives)
            {
                if (pattern.Matches(data, position, out var consumed, nestedOptions) && consumed == length)
                {
                    isMember = true;
                    break;
                }
            }
            if (!isMember)
                stack.Push((nextAtom, position + length));
            return;
        }

        foreach (var alternative in alternate.Alternatives)
        {
            if (position + alternative.MinLength > data.Length)
                continue;
            var nestedOptions = options with { FullWord = false };
            if (alternative.Matches(data, position, out var consumed, nestedOptions))
                stack.Push((nextAtom, position + consumed));
        }
    }

    private static bool TryGetCommonFixedLength(IReadOnlyList<HexPattern> alternatives, out int length)
    {
        length = 0;
        if (alternatives.Count == 0 || alternatives.Any(static x => !x.IsFixed))
            return false;
        var commonLength = alternatives[0].MinLength;
        foreach (var x in alternatives)
        {
            if (x.MinLength != commonLength)
                return false;
        }
        length = commonLength;
        return true;
    }

    private static bool TryMatchCharacterClass(CharacterClassKind kind, ReadOnlySpan<byte> data, int position, out int consumed)
    {
        consumed = 0;
        switch (kind)
        {
            case CharacterClassKind.NonAlphanumeric:
                if (position < data.Length && !IsAsciiAlphaNumeric(data[position]))
                {
                    consumed = 1;
                    return true;
                }
                return false;

            case CharacterClassKind.WordBoundary:
            {
                var leftWord = position > 0 && IsAsciiWord(data[position - 1]);
                var rightWord = position < data.Length && IsAsciiWord(data[position]);
                return leftWord != rightWord;
            }

            case CharacterClassKind.LineBoundary:
                if (position == 0 || position == data.Length) return true;
                if (position < data.Length && data[position] == (byte)'\r')
                {
                    consumed = position + 1 < data.Length && data[position + 1] == (byte)'\n' ? 2 : 1;
                    return true;
                }
                if (position < data.Length && data[position] == (byte)'\n')
                {
                    consumed = 1;
                    return true;
                }
                return false;

            default:
                return false;
        }
    }

    private static bool IsFullWordBoundary(ReadOnlySpan<byte> data, int start, int end)
    {
        // ClamAV's full-word modifier is implemented as (W)pattern(W), where
        // W means non-alphanumeric. Unlike the B word-boundary class, '_' is
        // therefore treated as a separator here.
        var leftWord = start > 0 && IsAsciiAlphaNumeric(data[start - 1]);
        var rightWord = end < data.Length && IsAsciiAlphaNumeric(data[end]);
        return !leftWord && !rightWord;
    }

    private static bool IsAsciiWord(byte value) =>
        (value >= (byte)'A' && value <= (byte)'Z') ||
        (value >= (byte)'a' && value <= (byte)'z') ||
        (value >= (byte)'0' && value <= (byte)'9') ||
        value == (byte)'_';

    private static bool IsAsciiAlphaNumeric(byte value) =>
        (value >= (byte)'A' && value <= (byte)'Z') ||
        (value >= (byte)'a' && value <= (byte)'z') ||
        (value >= (byte)'0' && value <= (byte)'9');

    private static bool EqualByte(byte actual, byte expected, bool ignoreCase)
    {
        if (!ignoreCase)
            return actual == expected;
        if (actual is >= (byte)'A' and <= (byte)'Z')
            actual = (byte)(actual + ('a' - 'A'));
        if (expected is >= (byte)'A' and <= (byte)'Z')
            expected = (byte)(expected + ('a' - 'A'));
        return actual == expected;
    }

    private static bool MaskedEquals(byte actual, byte expected, byte mask, bool ignoreCase)
    {
        if (!ignoreCase)
            return (actual & mask) == (expected & mask);

        if (actual is >= (byte)'A' and <= (byte)'Z')
            actual = (byte)(actual + 32);
        if (expected is >= (byte)'A' and <= (byte)'Z')
            expected = (byte)(expected + 32);
        return (actual & mask) == (expected & mask);
    }

    public override string ToString() => string.Concat(Atoms.Select(FormatAtom));

    private static string FormatAtom(PatternAtom atom) => atom switch
    {
        ExactByteAtom x => x.Value.ToString("x2"),
        MaskedByteAtom x when x.Mask == 0 => "??",
        MaskedByteAtom x when x.Mask == 0xF0 => (x.Value >> 4).ToString("x") + "?",
        MaskedByteAtom x when x.Mask == 0x0F => "?" + (x.Value & 0x0F).ToString("x"),
        CharacterClassAtom { Kind: CharacterClassKind.WordBoundary } => "(B)",
        CharacterClassAtom { Kind: CharacterClassKind.LineBoundary } => "(L)",
        CharacterClassAtom { Kind: CharacterClassKind.NonAlphanumeric } => "(W)",
        AlternatePatternAtom x when x.Negated => "!(" + string.Join('|', x.Alternatives.Select(static y => y.ToString())) + ")",
        AlternatePatternAtom x => "(" + string.Join('|', x.Alternatives.Select(static y => y.ToString())) + ")",
        GapAtom x when x.MinBytes == 0 && x.MaxBytes == int.MaxValue => "*",
        GapAtom x when x.MaxBytes == int.MaxValue => $"{{{x.MinBytes}-}}",
        GapAtom x when x.MinBytes == x.MaxBytes => $"{{{x.MinBytes}}}",
        GapAtom x => $"{{{x.MinBytes}-{x.MaxBytes}}}",
        _ => "?"
    };
}
