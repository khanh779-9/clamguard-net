using System.Buffers.Binary;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Builds a compact fragment index for logical signatures whose expression
/// requires every subsignature (pure AND). It only filters candidates; the full
/// LDB evaluator remains authoritative for targets, offsets, modifiers, and the
/// final Boolean expression.
/// </summary>
public sealed class LogicalSignaturePrefilter
{
    // 6-byte seeds make accidental co-occurrence in large binaries vanishingly
    // rare, which keeps the active rule set tiny on multi-megabyte inputs.
    private const int SeedLength = 6;
    private const ulong FnvOffsetBasis = 14695981039346656037UL;
    private const ulong FnvPrime = 1099511628211UL;

    private readonly IReadOnlyList<LogicalSignature> _signatures;
    private readonly Dictionary<ulong, SeedBucket> _signaturesBySeed = [];
    private readonly List<SeedEntry> _seedEntries = [];
    private readonly Dictionary<LogicalSignature, ulong> _secondarySeedBySignature = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<LogicalSignature, List<SeedEntry>> _entriesBySignature = new(ReferenceEqualityComparer.Instance);
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
        _secondarySeedBySignature.Clear();
        _entriesBySignature.Clear();
        _indexed.Clear();

        foreach (var signature in _signatures)
        {
            if (!TryGetAnchorVariants(signature, out var variants, out var anchorSubsig))
                continue;

            _indexed.Add(signature);
            var signatureEntries = new List<SeedEntry>();
            _entriesBySignature[signature] = signatureEntries;
            foreach (var variant in variants)
            {
                // All prefilter seeds are case-folded: the sliding pass folds
                // each window byte before lookup, so case-sensitive anchors
                // still match their exact-case occurrences (the per-subsig
                // anchor index re-verifies case exactly for its own hints).
                var folded = variant.Select(FoldByte).ToArray();
                var (seed, seedOffset) = SelectSeed(folded, _signaturesBySeed);
                var exists = _signaturesBySeed.TryGetValue(seed, out var existing);
                var entryIndex = _seedEntries.Count;
                var entry = new SeedEntry(signature, seed, seedOffset, exists ? existing.Head : -1);
                _seedEntries.Add(entry);
                signatureEntries.Add(entry);
                _signaturesBySeed[seed] = new SeedBucket(entryIndex, existing.Count + 1);
            }

            // Single-variant signatures get a second independent necessary seed:
            // the longest run of a different required subsignature, or another
            // run of the same subsignature pattern. Multi-variant signatures
            // (wide+ascii) keep single-seed behavior because per-variant runs
            // are only necessary for the variant that actually matches.
            if (variants.Count == 1)
            {
                var secondarySeed = SelectSecondarySeed(signature, anchorSubsig);
                if (secondarySeed != 0 && !_signaturesBySeed.ContainsKey(secondarySeed))
                {
                    // Register the secondary seed so the sliding pass can detect
                    // its occurrence alongside the primary seed.
                    var secondaryEntryIndex = _seedEntries.Count;
                    var secondaryEntry = new SeedEntry(signature, secondarySeed, 0, -1);
                    _seedEntries.Add(secondaryEntry);
                    _signaturesBySeed[secondarySeed] = new SeedBucket(secondaryEntryIndex, 1);
                }
                _secondarySeedBySignature[signature] = secondarySeed;
                var primarySeed = _entriesBySignature[signature][0].Seed;
                var primaryBytes = new byte[6];
                for (var i = 0; i < 6; i++)
                    primaryBytes[i] = (byte)(primarySeed >> (8 * i));
                var secondaryBytes = new byte[6];
                var secondary = _secondarySeedBySignature.TryGetValue(signature, out var sec) ? sec : 0;
                for (var i = 0; i < 6; i++)
                    secondaryBytes[i] = (byte)(secondary >> (8 * i));
                LastSeedDebug = $"primary='{Encoding.ASCII.GetString(primaryBytes)}' secondary='{Encoding.ASCII.GetString(secondaryBytes)}'";
            }
        }

        _builtSignatureCount = _signatures.Count;
        _built = true;
    }

    public HashSet<LogicalSignature> FindCandidates(ReadOnlySpan<byte> data)
    {
        Build();
        var candidates = new HashSet<LogicalSignature>(ReferenceEqualityComparer.Instance);
        if (data.Length < SeedLength || _signaturesBySeed.Count == 0)
            return candidates;

        // Pass 1: one sliding-window pass collecting every registered seed that
        // occurs anywhere in the byte layer. Nocase seeds are case-folded at
        // registration, so each window byte is folded before the seed lookup.
        var presentSeeds = new HashSet<ulong>();
        Span<byte> window = stackalloc byte[SeedLength];
        for (var offset = 0; offset <= data.Length - SeedLength; offset++)
        {
            var slice = data.Slice(offset, SeedLength);
            var fold = false;
            for (var i = 0; i < SeedLength; i++)
            {
                if (slice[i] is >= (byte)'A' and <= (byte)'Z')
                {
                    fold = true;
                    break;
                }
            }

            ulong seed;
            if (fold)
            {
                for (var i = 0; i < SeedLength; i++)
                    window[i] = slice[i] is >= (byte)'A' and <= (byte)'Z' ? (byte)(slice[i] + 32) : slice[i];
                seed = ReadSeed(window);
            }
            else
            {
                seed = ReadSeed(slice);
            }

            if (_signaturesBySeed.ContainsKey(seed))            {                presentSeeds.Add(seed);                LastPresentSeedsDebug += " 0x" + seed.ToString("X12");            }        }

        LastPresentSeedCount = presentSeeds.Count;
        LastPresentPrimary = false;
        LastPresentSecondary = false;
        foreach (var pair in _entriesBySignature)
        {
            var primaryPresent = false;
            foreach (var entry in pair.Value)
            {
                if (presentSeeds.Contains(entry.Seed))
                {
                    primaryPresent = true;
                    break;
                }
            }

            if (!primaryPresent)
                continue;

            if (_secondarySeedBySignature.TryGetValue(pair.Key, out var secondary) &&
                secondary != 0 &&
                !presentSeeds.Contains(secondary))
            {
                continue;
            }

            if (ReferenceEquals(pair.Key, _debugSignature))
            {
                LastPresentPrimary = true;
                LastPresentSecondary = _secondarySeedBySignature.TryGetValue(pair.Key, out var s2) == false || s2 == 0 || presentSeeds.Contains(s2);
            }

            candidates.Add(pair.Key);
        }

        return candidates;
    }

    public int LastPresentSeedCount { get; private set; }
    public bool LastPresentPrimary { get; private set; }
    public bool LastPresentSecondary { get; private set; }
    public LogicalSignature? _debugSignature;
    public string LastSeedDebug { get; private set; } = string.Empty;
    public string LastPresentSeedsDebug { get; private set; } = string.Empty;

    /// <summary>
    /// Picks a second independent necessary seed: the longest run of a different
    /// required single-variant subsignature, or another run of the same
    /// subsignature pattern. Returns 0 when no independent run exists.
    /// Wide+ascii subsignatures have two alternative encodings, so a single
    /// run of theirs is NOT a necessary condition and must not be used here.
    /// </summary>
    private ulong SelectSecondarySeed(LogicalSignature signature, ContentSignature primarySubsig)
    {
        foreach (var sub in signature.SubSignatures)
        {
            if (ReferenceEquals(sub, primarySubsig))
                continue;
            if (sub.MatchOptions.HasFlag(ContentMatchOptions.Wide) &&
                sub.MatchOptions.HasFlag(ContentMatchOptions.Ascii))
                continue; // two alternative variants: neither run is necessary
            if (!IsIndexable(sub))
                continue;

            // Runs must come from the variants that will actually be matched:
            // a wide-only subsignature never matches its base bytes.
            foreach (var anchor in GetVariants(sub))
            {
                foreach (var run in GetRunsFromAnchor(anchor))
                {
                    var seed = RunSeed(run);
                    if (seed != 0)
                        return seed;
                }
            }
        }

        // Same subsignature, a different run of the same pattern.
        foreach (var anchor in GetVariants(primarySubsig))
        {
            foreach (var run in GetRunsFromAnchor(anchor))
            {
                var seed = RunSeed(run);
                if (seed != 0)
                    return seed;
            }
        }

        return 0;
    }

    private static IEnumerable<byte[]> GetRunsFromAnchor(byte[] anchor)
    {
        if (anchor.Length < SeedLength)
            yield break;
        yield return anchor;
    }

    private static IEnumerable<(byte[] Bytes, int Offset)> GetRuns(HexPattern pattern)
    {
        if (!pattern.TryGetSearchRuns(out var runs, SeedLength))
            yield break;
        foreach (var run in runs)
            yield return (run.Bytes, run.Offset);
    }

    private static ulong RunSeed(byte[] run)
    {
        if (run.Length < SeedLength)
            return 0;
        Span<byte> folded = stackalloc byte[SeedLength];
        for (var i = 0; i < SeedLength; i++)
            folded[i] = FoldByte(run[i]);
        return ReadSeed(folded);
    }

    private static ulong ReadSeed(ReadOnlySpan<byte> bytes)
    {
        ulong seed = 0;
        for (var i = 0; i < SeedLength; i++)
            seed |= (ulong)bytes[i] << (8 * i);
        return seed;
    }

    internal bool IsIndexed(LogicalSignature signature)
    {
        Build();
        return _indexed.Contains(signature);
    }

    internal (bool Indexed, ulong PrimarySeed, ulong SecondarySeed) DebugSeedState(LogicalSignature signature)
    {
        Build();
        ulong primary = 0;
        if (_entriesBySignature.TryGetValue(signature, out var entries) && entries.Count != 0)
            primary = entries[0].Seed;
        _secondarySeedBySignature.TryGetValue(signature, out var secondary);
        return (_indexed.Contains(signature), primary, secondary);
    }

    private bool TryGetAnchorVariants(LogicalSignature signature, out List<byte[]> variants, out ContentSignature anchorSubsig)
    {
        variants = [];
        anchorSubsig = null!;

        // Targets 3 (HTML) and 7 (ASCII) can be scanned after normalization.
        // Searching the raw layer could reject a rule whose anchor only appears
        // after normalization, so keep those signatures on the ordinary path.
        if (signature.Target?.Target is SignatureTargetType.Html or SignatureTargetType.Ascii ||
            !TryGetRequiredContentIndices(signature, out var requiredIndices))
        {
            return false;
        }

        var contentByIndex = signature.SubSignatures.ToDictionary(GetSubsigIndex);

        // A pure-AND rule requires EVERY subsignature in the expression to match,
        // so ANY one required plain-content subsignature is a necessary
        // condition — even when other required indices are PCRE/macro/etc.
        // This indexes the large PCRE-heavy portion of daily.ldb.
        var anchor = requiredIndices
            .Select(index => contentByIndex.TryGetValue(index, out var content) ? content : null)
            .Where(content => content is not null && IsIndexable(content) && !HasSpecialSubsignature(signature, GetSubsigIndex(content)))
            .OrderByDescending(GetLongestVariantLength)
            .FirstOrDefault();

        if (anchor is null)
            return false;

        var candidateVariants = GetVariants(anchor).ToArray();
        if (candidateVariants.Length == 0 || candidateVariants.Any(static bytes => bytes.Length < SeedLength))
            return false;

        variants = [.. candidateVariants];
        anchorSubsig = anchor;
        return true;
    }

    private static (ulong Seed, int Offset) SelectSeed(
        ReadOnlySpan<byte> pattern,
        IReadOnlyDictionary<ulong, SeedBucket> frequency)
    {
        var lastOffset = pattern.Length - SeedLength;
        var offset = GetInitialSeedOffset(pattern, lastOffset + 1);
        ulong bestSeed = 0;
        var bestOffset = 0;
        var bestFrequency = int.MaxValue;

        for (var checkedOffsets = 0; checkedOffsets <= lastOffset; checkedOffsets++)
        {
            var currentOffset = (offset + checkedOffsets) % (lastOffset + 1);
            var seed = ReadSeed(pattern.Slice(currentOffset, SeedLength));
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
        // nocase subsignatures index through case-folded seeds: the sliding
        // pass folds each window byte before computing the seed.
        if (signature.Pattern.IsFixed)
            return true;

        // Flexible (wildcard) patterns can still be anchored: any match must
        // contain the pattern's longest fixed-byte run, so an anchor miss
        // soundly rejects the signature.
        return signature.Pattern.TryGetSearchAnchor(out _, out var anchor) && anchor.Length >= SeedLength;
    }

    private static int GetLongestVariantLength(ContentSignature? signature)
    {
        if (signature is null || !signature.Pattern.TryGetSearchAnchor(out _, out var anchor))            return 0;
        var length = anchor.Length;
        return signature.MatchOptions.HasFlag(ContentMatchOptions.Wide)
            ? checked(length * 2)
            : length;
    }

    private static IEnumerable<byte[]> GetVariants(ContentSignature signature)
    {
        var ignoreCase = signature.MatchOptions.HasFlag(ContentMatchOptions.IgnoreCase);
        if (!signature.MatchOptions.HasFlag(ContentMatchOptions.Wide) ||
            signature.MatchOptions.HasFlag(ContentMatchOptions.Ascii))
        {
            yield return GetAnchorBytes(signature.Pattern, ignoreCase);
        }

        if (signature.MatchOptions.HasFlag(ContentMatchOptions.Wide))
            yield return GetAnchorBytes(signature.Pattern.ToWideVariant(), ignoreCase);
    }

    private static byte[] GetAnchorBytes(HexPattern pattern, bool ignoreCase)
    {
        if (!pattern.TryGetSearchAnchor(out _, out var anchor) || anchor.Length == 0)
            throw new InvalidOperationException("Signature has no usable search anchor.");

        return ignoreCase ? anchor.Select(FoldByte).ToArray() : anchor;
    }

    private static byte FoldByte(byte value)
        => value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;

    private readonly record struct SeedBucket(int Head, int Count);
    private readonly record struct SeedEntry(LogicalSignature Signature, ulong Seed, int SeedOffset, int Next);
}

