using System.Buffers.Binary;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Builds a compact fragment index for logical signatures whose expression
/// requires every subsignature (pure AND). It only filters candidates; the full
/// LDB evaluator remains authoritative for targets, offsets, modifiers, and the
/// final Boolean expression.
/// </summary>
internal sealed class LogicalSignaturePrefilter
{
    private const int SeedLength = sizeof(ulong);
    private const ulong FnvOffsetBasis = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;

    private readonly List<LogicalSignature> _signatures = [];
    private readonly Dictionary<ulong, List<LogicalSignature>> _signaturesBySeed = [];
    private readonly HashSet<LogicalSignature> _indexed = new(ReferenceEqualityComparer.Instance);
    private bool _built;

    internal void Add(LogicalSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        _signatures.Add(signature);
        _built = false;
    }

    internal void Build()
    {
        if (_built)
            return;

        _signaturesBySeed.Clear();
        _indexed.Clear();

        var eligible = new List<(LogicalSignature Signature, byte[][] Variants)>();
        foreach (var signature in _signatures)
        {
            if (!TryGetAnchorVariants(signature, out var variants))
                continue;
            eligible.Add((signature, variants));
        }

        // Pick one exact 8-byte fragment from each possible anchor representation.
        // Reusing an existing key is allowed, but the fragment selector prefers a
        // currently unused key to keep candidate buckets small without a second
        // large n-gram-frequency table.
        var seedFrequency = new Dictionary<ulong, int>();
        foreach (var (signature, variants) in eligible)
        {
            var selectedSeeds = new HashSet<ulong>();
            foreach (var variant in variants)
                selectedSeeds.Add(SelectSeed(variant, seedFrequency));

            _indexed.Add(signature);
            foreach (var seed in selectedSeeds)
            {
                if (!_signaturesBySeed.TryGetValue(seed, out var matches))
                    _signaturesBySeed[seed] = matches = [];
                matches.Add(signature);
                seedFrequency[seed] = matches.Count;
            }
        }

        _built = true;
    }

    internal HashSet<LogicalSignature> FindCandidates(ReadOnlySpan<byte> data)
    {
        Build();
        var candidates = new HashSet<LogicalSignature>(ReferenceEqualityComparer.Instance);
        if (data.Length < SeedLength || _signaturesBySeed.Count == 0)
            return candidates;

        for (var offset = 0; offset <= data.Length - SeedLength; offset++)
        {
            var seed = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, SeedLength));
            if (!_signaturesBySeed.TryGetValue(seed, out var signatures))
                continue;

            foreach (var signature in signatures)
                candidates.Add(signature);

            if (candidates.Count == _indexed.Count)
                break;
        }

        return candidates;
    }

    internal bool IsIndexed(LogicalSignature signature)
    {
        Build();
        return _indexed.Contains(signature);
    }

    private static bool TryGetAnchorVariants(LogicalSignature signature, out byte[][] variants)
    {
        variants = [];

        // Targets 3 (HTML) and 7 (ASCII) can be scanned after normalization.
        // Searching the raw layer could reject a rule whose anchor only appears
        // after normalization, so keep those signatures on the ordinary path.
        if (signature.Target?.Target is 3 or 7 ||
            !TryGetRequiredContentIndices(signature, out var requiredIndices))
        {
            return false;
        }

        var contentByIndex = signature.SubSignatures.ToDictionary(GetSubsigIndex);
        if (requiredIndices.Any(index => !contentByIndex.ContainsKey(index) || HasSpecialSubsignature(signature, index)))
            return false;

        var anchor = requiredIndices
            .Select(index => contentByIndex[index])
            .Where(IsIndexable)
            .OrderByDescending(GetLongestVariantLength)
            .FirstOrDefault();

        if (anchor is null)
            return false;

        var candidateVariants = GetVariants(anchor).Select(static pattern => pattern.ToFixedBytes()).ToArray();
        if (candidateVariants.Length == 0 || candidateVariants.Any(static bytes => bytes.Length < SeedLength))
            return false;

        variants = candidateVariants;
        return true;
    }

    private static ulong SelectSeed(ReadOnlySpan<byte> pattern, IReadOnlyDictionary<ulong, int> frequency)
    {
        var lastOffset = pattern.Length - SeedLength;
        var offset = GetInitialSeedOffset(pattern, lastOffset + 1);
        ulong bestSeed = 0;
        var bestFrequency = int.MaxValue;

        for (var checkedOffsets = 0; checkedOffsets <= lastOffset; checkedOffsets++)
        {
            var currentOffset = (offset + checkedOffsets) % (lastOffset + 1);
            var seed = BinaryPrimitives.ReadUInt64LittleEndian(pattern.Slice(currentOffset, SeedLength));
            frequency.TryGetValue(seed, out var currentFrequency);

            if (currentFrequency == 0)
                return seed;

            if (currentFrequency < bestFrequency)
            {
                bestSeed = seed;
                bestFrequency = currentFrequency;
            }
        }

        return bestSeed;
    }

    private static int GetInitialSeedOffset(ReadOnlySpan<byte> pattern, int possibleOffsets)
    {
        unchecked
        {
            var hash = FnvOffsetBasis;
            foreach (var value in pattern)
            {
                hash ^= value;
                hash *= FnvPrime;
            }
            return (int)(hash % (ulong)possibleOffsets);
        }
    }

    private static bool TryGetRequiredContentIndices(LogicalSignature signature, out int[] indices)
    {
        indices = [];
        var terms = signature.Expression.Split('&', StringSplitOptions.TrimEntries);
        if (terms.Length < 2)
            return false;

        var parsed = new HashSet<int>();
        foreach (var term in terms)
        {
            if (term.Length == 0 || term.Any(static character => !char.IsAsciiDigit(character)) ||
                !int.TryParse(term, out var index) || index < 0 || index >= 64)
                return false;
            parsed.Add(index);
        }

        if (parsed.Count < 2)
            return false;

        indices = parsed.ToArray();
        return true;
    }

    private static bool HasSpecialSubsignature(LogicalSignature signature, int index)
        => signature.MacroSubSignatures?.ContainsKey(index) == true ||
           signature.RegexSubSignatures?.ContainsKey(index) == true ||
           signature.ByteCompareSubSignatures?.ContainsKey(index) == true ||
           signature.FuzzyImageSubSignatures?.ContainsKey(index) == true;

    private static int GetSubsigIndex(ContentSignature signature)
    {
        var hash = signature.Name.LastIndexOf('#');
        return hash >= 0 && int.TryParse(signature.Name[(hash + 1)..], out var index) ? index : 0;
    }

    private static bool IsIndexable(ContentSignature signature)
        => signature.Pattern.IsFixed &&
           !signature.MatchOptions.HasFlag(ContentMatchOptions.IgnoreCase);

    private static int GetLongestVariantLength(ContentSignature signature)
    {
        var length = signature.Pattern.MinLength;
        return signature.MatchOptions.HasFlag(ContentMatchOptions.Wide)
            ? checked(length * 2)
            : length;
    }

    private static IEnumerable<HexPattern> GetVariants(ContentSignature signature)
    {
        if (!signature.MatchOptions.HasFlag(ContentMatchOptions.Wide) ||
            signature.MatchOptions.HasFlag(ContentMatchOptions.Ascii))
        {
            yield return signature.Pattern;
        }

        if (signature.MatchOptions.HasFlag(ContentMatchOptions.Wide))
            yield return signature.Pattern.ToWideVariant();
    }
}
