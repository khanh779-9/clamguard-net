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

    private readonly IReadOnlyList<LogicalSignature> _signatures;
    private readonly Dictionary<ulong, SeedBucket> _signaturesBySeed = [];
    private readonly List<SeedEntry> _seedEntries = [];
    private readonly HashSet<LogicalSignature> _indexed = new(ReferenceEqualityComparer.Instance);
    private int _builtSignatureCount = -1;
    private bool _built;

    internal LogicalSignaturePrefilter(IReadOnlyList<LogicalSignature> signatures)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        _signatures = signatures;
    }

    internal void Build()
    {
        if (_built && _builtSignatureCount == _signatures.Count)
            return;

        _signaturesBySeed.Clear();
        _seedEntries.Clear();
        _indexed.Clear();

        // Process one signature at a time. Keeping every signature's materialized
        // anchor bytes in a staging list caused avoidable peak memory during load.
        foreach (var signature in _signatures)
        {
            if (!TryGetAnchorVariants(signature, out var variants))
                continue;

            var selectedSeeds = new HashSet<ulong>();
            foreach (var variant in variants)
                selectedSeeds.Add(SelectSeed(variant, _signaturesBySeed));

            _indexed.Add(signature);
            foreach (var seed in selectedSeeds)
            {
                var exists = _signaturesBySeed.TryGetValue(seed, out var existing);
                var entryIndex = _seedEntries.Count;
                _seedEntries.Add(new SeedEntry(signature, exists ? existing.Head : -1));
                _signaturesBySeed[seed] = new SeedBucket(entryIndex, existing.Count + 1);
            }
        }

        _builtSignatureCount = _signatures.Count;
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
            if (!_signaturesBySeed.TryGetValue(seed, out var bucket))
                continue;

            for (var entryIndex = bucket.Head; entryIndex >= 0; entryIndex = _seedEntries[entryIndex].Next)
                candidates.Add(_seedEntries[entryIndex].Signature);

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

    private static ulong SelectSeed(
        ReadOnlySpan<byte> pattern,
        IReadOnlyDictionary<ulong, SeedBucket> frequency)
    {
        var lastOffset = pattern.Length - SeedLength;
        var offset = GetInitialSeedOffset(pattern, lastOffset + 1);
        ulong bestSeed = 0;
        var bestFrequency = int.MaxValue;

        for (var checkedOffsets = 0; checkedOffsets <= lastOffset; checkedOffsets++)
        {
            var currentOffset = (offset + checkedOffsets) % (lastOffset + 1);
            var seed = BinaryPrimitives.ReadUInt64LittleEndian(pattern.Slice(currentOffset, SeedLength));
            var currentFrequency = frequency.TryGetValue(seed, out var bucket) ? bucket.Count : 0;

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

    private readonly record struct SeedBucket(int Head, int Count);
    private readonly record struct SeedEntry(LogicalSignature Signature, int Next);
}
