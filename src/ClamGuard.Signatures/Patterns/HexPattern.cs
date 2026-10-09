namespace ClamGuard.Signatures.Patterns;

public readonly record struct PatternMatchOptions(
    bool IgnoreCase = false,
    bool FullWord = false);

/// <summary>
/// Represents a parsed hexadecimal pattern. Exact-byte-only patterns are stored
/// as a compact byte array rather than a reference to an atom object per byte.
/// The polymorphic atom view is materialized lazily only for callers that need it.
/// </summary>
public sealed class HexPattern
{
    private const int MaxBacktrackingStates = 250_000;

    private readonly byte[]? _fixedBytes;
    private PatternAtom[]? _atoms;
    private readonly int _minLength;
    private readonly int _maxLength;

    public IReadOnlyList<PatternAtom> Atoms => GetAtoms();
    public int MinLength => _minLength;
    public int MaxLength => _maxLength;
    public bool IsFixed => _fixedBytes is not null;
    internal ReadOnlySpan<byte> FixedBytesSpan => _fixedBytes ??
        throw new InvalidOperationException("The pattern is not fixed-length exact bytes.");

    public bool IsLegacyFixedNegatedAlternate =>
        _atoms is { Length: 1 } &&
        _atoms[0] is AlternatePatternAtom { Negated: true } alternate &&
        alternate.Alternatives.All(static x => x.IsFixed) &&
        alternate.Alternatives.Select(static x => x.MinLength).Distinct().Count() == 1;

    public HexPattern(IEnumerable<PatternAtom> atoms)
    {
        ArgumentNullException.ThrowIfNull(atoms);
        var materialized = atoms.ToArray();
        if (materialized.Length == 0)
            throw new ArgumentException("A pattern cannot be empty.", nameof(atoms));

        if (materialized.All(static atom => atom is ExactByteAtom))
        {
            _fixedBytes = new byte[materialized.Length];
            for (var index = 0; index < materialized.Length; index++)
                _fixedBytes[index] = ((ExactByteAtom)materialized[index]).Value;
            _minLength = _fixedBytes.Length;
            _maxLength = _fixedBytes.Length;
            // The temporary atom array is intentionally not retained.
        }
        else
        {
            _atoms = materialized;
            _minLength = materialized.Sum(static atom => atom.MinLength);
            _maxLength = materialized.Any(static atom => atom.MaxLength == int.MaxValue)
                ? int.MaxValue
                : materialized.Sum(static atom => atom.MaxLength);
        }
    }

    public byte[] ToFixedBytes()
    {
        if (_fixedBytes is null)
            throw new InvalidOperationException("The pattern contains wildcards, ranges, classes or alternates.");

        // Do not expose the internal storage to callers that may mutate the array.
        return (byte[])_fixedBytes.Clone();
    }

    public HexPattern ToWideVariant()
    {
        if (_fixedBytes is not null)
        {
            var wideBytes = new byte[checked(_fixedBytes.Length * 2)];
            for (var index = 0; index < _fixedBytes.Length; index++)
                wideBytes[index * 2] = _fixedBytes[index];
            return new HexPattern(wideBytes.Select(ExactByteAtom.From));
        }

        var expanded = new List<PatternAtom>();
        foreach (var atom in Atoms)
        {
            switch (atom)
            {
                case ExactByteAtom exact:
                    expanded.Add(exact);
                    expanded.Add(ExactByteAtom.From(0));
                    break;
                case MaskedByteAtom masked:
                    expanded.Add(masked);
                    expanded.Add(ExactByteAtom.From(0));
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

        if (_fixedBytes is not null)
            return MatchesFixed(data, start, options, out consumed);

        var stack = new Stack<(int AtomIndex, int Position)>();
        var visited = new HashSet<(int AtomIndex, int Position)>();
        stack.Push((0, start));
        var states = 0;
        var atoms = _atoms!;

        while (stack.Count != 0)
        {
            if (++states > MaxBacktrackingStates)
                return false;

            var (atomIndex, position) = stack.Pop();
            if (!visited.Add((atomIndex, position)))
                continue;

            if (atomIndex == atoms.Length)
            {
                if (options.FullWord && !IsFullWordBoundary(data, start, position))
                    continue;
                consumed = position - start;
                return true;
            }

            switch (atoms[atomIndex])
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

    private bool MatchesFixed(ReadOnlySpan<byte> data, int start, PatternMatchOptions options, out int consumed)
    {
        consumed = 0;
        var fixedBytes = _fixedBytes!;
        if (fixedBytes.Length > data.Length - start)
            return false;

        for (var index = 0; index < fixedBytes.Length; index++)
        {
            if (!EqualByte(data[start + index], fixedBytes[index], options.IgnoreCase))
                return false;
        }

        var end = start + fixedBytes.Length;
        if (options.FullWord && !IsFullWordBoundary(data, start, end))
            return false;

        consumed = fixedBytes.Length;
        return true;
    }

    private PatternAtom[] GetAtoms()
    {
        var existing = Volatile.Read(ref _atoms);
        if (existing is not null)
            return existing;

        var bytes = _fixedBytes ?? throw new InvalidOperationException("Pattern atom storage is unavailable.");
        var created = new PatternAtom[bytes.Length];
        for (var index = 0; index < bytes.Length; index++)
            created[index] = ExactByteAtom.From(bytes[index]);

        return Interlocked.CompareExchange(ref _atoms, created, null) ?? created;
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
                if (position > 0 && (data[position - 1] == (byte)'\n' || data[position - 1] == (byte)'\r'))
                    return true;
                if (position < data.Length && (data[position] == (byte)'\r' || data[position] == (byte)'\n'))
                    return true;
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

    public override string ToString() => _fixedBytes is not null
        ? Convert.ToHexString(_fixedBytes).ToLowerInvariant()
        : string.Concat(Atoms.Select(FormatAtom));

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
