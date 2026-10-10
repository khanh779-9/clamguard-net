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
    // A 4-byte seed keeps the candidate dictionary compact (one entry per
    // anchor variant) while still rejecting the overwhelming majority of
    // non-matching files with a single dictionary probe per 4-byte window.
    private const int SeedLength = sizeof(uint);
    private const ulong FnvOffsetBasis = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;

    private readonly IReadOnlyList<LogicalSignature> _signatures;
    private readonly Dictionary<uint, SeedBucket> _signaturesBySeed = [];
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

            _indexed.Add(signature);
            foreach (var variant in variants)
            {
                var (seed, seedOffset) = SelectSeed(variant, _signaturesBySeed);
                var exists = _signaturesBySeed.TryGetValue(seed, out var existing);
                var entryIndex = _seedEntries.Count;
                // Retain the chosen fixed anchor bytes and seed offset. A seed hit
                // is only a candidate; confirming the whole anchor here prevents
                // thousands of false candidates from triggering full LDB scans.
                _seedEntries.Add(new SeedEntry(signature, variant, seedOffset, exists ? existing.Head : -1));
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
            var seed = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, SeedLength));
            if (!_signaturesBySeed.TryGetValue(seed, out var bucket))
                continue;

            for (var entryIndex = bucket.Head; entryIndex >= 0; entryIndex = _seedEntries[entryIndex].Next)
            {
                var entry = _seedEntries[entryIndex];
                var candidateStart = offset - entry.SeedOffset;
                if (candidateStart < 0 || candidateStart > data.Length - entry.AnchorBytes.Length)
                    continue;
                if (!data.Slice(candidateStart, entry.AnchorBytes.Length).SequenceEqual(entry.AnchorBytes))
                    continue;
                candidates.Add(entry.Signature);
            }

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

        var candidateVariants = GetVariants(anchor).ToArray();
        if (candidateVariants.Length == 0 || candidateVariants.Any(static bytes => bytes.Length < SeedLength))
            return false;

        variants = candidateVariants;
        return true;
    }

    private static (uint Seed, int Offset) SelectSeed(
        ReadOnlySpan<byte> pattern,
        IReadOnlyDictionary<uint, SeedBucket> frequency)
    {
        var lastOffset = pattern.Length - SeedLength;
        var offset = GetInitialSeedOffset(pattern, lastOffset + 1);
        uint bestSeed = 0;
        var bestOffset = 0;
        var bestFrequency = int.MaxValue;

        for (var checkedOffsets = 0; checkedOffsets <= lastOffset; checkedOffsets++)
        {
            var currentOffset = (offset + checkedOffsets) % (lastOffset + 1);
            var seed = BinaryPrimitives.ReadUInt32LittleEndian(pattern.Slice(currentOffset, SeedLength));
            var currentFrequency = frequency.TryGetValue(seed, out var bucket) ? bucket.Count : 0;

            if (currentFrequency == 0)
                return (seed, currentOffset);

            if (currentFrequency < bestFrequency)
            {
                bestSeed = seed;
                bestOffset = currentOffset;
                bestFrequency = currentFrequency;
            }
        }

        return (bestSeed, bestOffset);
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

        // A single required subsignature is still a pure conjunction: the rule
        // can only match when that subsignature matches, so a single-term
        // expression is indexable just like a multi-term AND.
        if (parsed.Count < 1)
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
    {
        if (signature.MatchOptions.HasFlag(ContentMatchOptions.IgnoreCase))
            return false;
        if (signature.Pattern.IsFixed)
            return true;

        // Flexible (wildcard) patterns can still be anchored: any match must
        // contain the pattern's longest fixed-byte run, so an anchor miss
        // soundly rejects the signature.
        return signature.Pattern.TryGetSearchAnchor(out _, out var anchor) && anchor.Length >= SeedLength;
    }

    private static int GetLongestVariantLength(ContentSignature signature)
    {
        if (!signature.Pattern.TryGetSearchAnchor(out _, out var anchor))
            return 0;
        var length = anchor.Length;
        return signature.MatchOptions.HasFlag(ContentMatchOptions.Wide)
            ? checked(length * 2)
            : length;
    }

    private static IEnumerable<byte[]> GetVariants(ContentSignature signature)
    {
        if (!signature.MatchOptions.HasFlag(ContentMatchOptions.Wide) ||
            signature.MatchOptions.HasFlag(ContentMatchOptions.Ascii))
        {
            yield return GetAnchorBytes(signature.Pattern);
        }

        if (signature.MatchOptions.HasFlag(ContentMatchOptions.Wide))
            yield return GetAnchorBytes(signature.Pattern.ToWideVariant());
    }

    private static byte[] GetAnchorBytes(HexPattern pattern)
    {
        if (pattern.TryGetSearchAnchor(out _, out var anchor) && anchor.Length != 0)
            return anchor;
        throw new InvalidOperationException("Signature has no usable search anchor.");
    }

    private readonly record struct SeedBucket(int Head, int Count);
    private readonly record struct SeedEntry(LogicalSignature Signature, byte[] AnchorBytes, int SeedOffset, int Next);
}
