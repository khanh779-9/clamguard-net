using System.Security.Cryptography;
using ClamGuard.Core;
using ClamGuard.Signatures;

namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Holds immutable-at-scan-time indexes built from parsed signatures.
/// Besides in-memory matching this type supports true chunked stream matching:
/// fixed signatures keep Aho-Corasick state across reads, hashes are incremental,
/// and flexible signatures use a bounded rolling window.
/// </summary>
public sealed partial class CompiledSignatureSet
{
    private readonly List<ContentSignature> _content = [];
    private readonly List<ContentSignature> _flexibleContent = [];
    private readonly List<NdbSignature> _ndb = [];
    private readonly List<NdbSignature> _flexibleNdb = [];
    private readonly List<LogicalSignature> _logical = [];
    private readonly LogicalSignaturePrefilter _logicalPrefilter;
    private readonly List<MetadataSignature> _metadata = [];
    private sealed class HashBucket
    {
        public Dictionary<byte[], List<HashSignature>> ByDigest { get; } = new(ByteArrayContentComparer.Instance);
        public IEnumerable<HashSignature> Signatures => ByDigest.Values.SelectMany(static x => x);

        public void Add(HashSignature signature)
        {
            if (!ByDigest.TryGetValue(signature.Hash, out var signatures))
                ByDigest[signature.Hash] = signatures = [];
            signatures.Add(signature);
        }
    }

    private readonly Dictionary<(HashAlgorithmKind Algorithm, long? Size), HashBucket> _hashBuckets = new();
    private readonly Dictionary<(HashAlgorithmKind Algorithm, long? Size), HashBucket> _falsePositiveBuckets = new();
    private readonly List<HashSignature> _specializedHashes = [];
    private readonly HashSet<HashAlgorithmKind> _hashAlgorithms = [];
    private readonly HashSet<HashAlgorithmKind> _falsePositiveAlgorithms = [];
    // IDs are assigned in insertion order and never removed; lists are smaller
    // than integer-key dictionaries and keep the NDB metadata aligned by ID.
    private readonly List<ContentSignature> _acEntries = [];
    private readonly List<NdbSignature?> _ndbAcEntries = [];
    private readonly List<ContentSignature> _contentAcEntries = [];
    private AhoCorasickMatcher _ac = new();
    private AhoCorasickMatcher _contentAc = new();
    private BoyerMooreHorspoolMatcher? _singleFixedMatcher;
    private ContentSignature? _singleFixedEntry;
    private bool _built;

    public CompiledSignatureSet()
    {
        _logicalPrefilter = new LogicalSignaturePrefilter(_logical);
    }

    public IReadOnlyList<Signature> AllSignatures =>
        _content.Cast<Signature>()
            .Concat(_ndb)
            .Concat(_logical)
            .Concat(_metadata)
            .Concat(_hashBuckets.Values.SelectMany(static x => x.Signatures))
            .Concat(_falsePositiveBuckets.Values.SelectMany(static x => x.Signatures))
            .Concat(_specializedHashes)
            .ToArray();

    public bool HasFalsePositiveRules => _falsePositiveBuckets.Count != 0;

    /// <summary>Largest finite pattern length used by the rolling stream matcher.</summary>
    public int MaxFinitePatternLength
    {
        get
        {
            var lengths = _content.Concat<Signature>(_ndb)
                .Select(static s => s is ContentSignature c ? c.Pattern.MaxLength : ((NdbSignature)s).Pattern.MaxLength)
                .Where(static x => x != int.MaxValue)
                .DefaultIfEmpty(1);
            return Math.Max(1, lengths.Max());
        }
    }

    public bool HasUnboundedPattern => _content.Any(static x => x.Pattern.MaxLength == int.MaxValue) ||
                                       _ndb.Any(static x => x.Pattern.MaxLength == int.MaxValue);

    public void Add(Signature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        _built = false;

        switch (signature)
        {
            case HashSignature hash when hash.Type == SignatureType.Trust:
            {
                var key = (hash.Algorithm, hash.FileSize);
                if (!_falsePositiveBuckets.TryGetValue(key, out var bucket))
                    _falsePositiveBuckets[key] = bucket = new HashBucket();
                bucket.Add(hash);
                _falsePositiveAlgorithms.Add(hash.Algorithm);
                break;
            }
            case HashSignature hash:
            {
                var extension = Path.GetExtension(hash.SourceFile).ToLowerInvariant();
                if (extension is ".mdb" or ".msb" or ".mdu" or ".msu" or ".imp")
                {
                    // PE section/import hashes are hashes of derived PE structures,
                    // not of the complete file. Keep them visible to the database
                    // but route matching to the PE-specialized scanner.
                    _specializedHashes.Add(hash);
                    break;
                }

                var key = (hash.Algorithm, hash.FileSize);
                if (!_hashBuckets.TryGetValue(key, out var bucket))
                    _hashBuckets[key] = bucket = new HashBucket();
                bucket.Add(hash);
                _hashAlgorithms.Add(hash.Algorithm);
                break;
            }
            case NdbSignature ndb:
                _ndb.Add(ndb);
                if (ndb.MacroGroup is null)
                {
                    if (ndb.Pattern.IsFixed)
                    {
                        var entry = new ContentSignature(ndb.Name, SignatureType.Ndb, ndb.SourceFile, ndb.Pattern, ndb.OffsetExpression);
                        AddFixedPattern(entry, ndb);
                    }
                    else
                    {
                        _flexibleNdb.Add(ndb);
                    }
                }
                break;
            case ContentSignature content:
                _content.Add(content);
                if (content.Pattern.IsFixed)
                    AddFixedPattern(content);
                else
                    _flexibleContent.Add(content);
                break;
            case LogicalSignature logical:
                _logical.Add(logical);
                break;
            case MetadataSignature metadata:
                _metadata.Add(metadata);
                break;
        }
    }

    private void AddFixedPattern(ContentSignature entry, NdbSignature? ndb = null)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _acEntries.Add(entry);
        _ndbAcEntries.Add(ndb);
        if (entry.Type != SignatureType.Ndb)
            _contentAcEntries.Add(entry);
    }

    public void Build()
    {
        if (_built) return;

        // Rebuild the trie from the canonical signature index. This makes Add()
        // safe even when signatures arrive in multiple database-loading passes.
        _ac = new AhoCorasickMatcher();
        for (var id = 0; id < _acEntries.Count; id++)
            _ac.Add(_acEntries[id].Pattern.FixedBytesSpan, id);
        _ac.Build();

        // Raw Content signatures need a separate, much smaller automaton when a
        // caller deliberately excludes NDB rules. Scanning the combined NDB trie
        // and discarding every NDB hit afterward wastes time and can produce a
        // very large temporary hit list on multi-megabyte files.
        if (_contentAcEntries.Count == _acEntries.Count)
        {
            // If no NDB entries were added, the shared automaton already has the
            // same ID order. Reuse it instead of duplicating the index in memory.
            _contentAc = _ac;
        }
        else
        {
            _contentAc = new AhoCorasickMatcher();
            for (var id = 0; id < _contentAcEntries.Count; id++)
                _contentAc.Add(_contentAcEntries[id].Pattern.FixedBytesSpan, id);
            _contentAc.Build();
        }
        _logicalPrefilter.Build();

        // Match a single long exact signature with the BM backend rather than
        // paying the AC state-machine cost. With multiple signatures, AC remains
        // the multi-pattern engine and keeps its cross-pattern sharing.
        if (_acEntries.Count == 1)
        {
            _singleFixedEntry = _acEntries[0];
            if (_singleFixedEntry.Pattern.ToFixedBytes() is { Length: >= 8 } bytes)
                _singleFixedMatcher = new BoyerMooreHorspoolMatcher(bytes);
        }
        else
        {
            _singleFixedEntry = null;
            _singleFixedMatcher = null;
        }

        _built = true;
    }

    /// <summary>
    /// Returns indexed logical signatures whose fixed-byte anchor occurs in this
    /// byte layer. Unsupported/normalized signatures are not returned and must
    /// still be evaluated through the ordinary LDB path. This is not a verdict.
    /// </summary>
    public HashSet<LogicalSignature> FindLogicalCandidates(ReadOnlySpan<byte> data)
    {
        Build();
        return _logicalPrefilter.FindCandidates(data);
    }

    /// <summary>Indicates whether a logical signature is safe to reject on an anchor miss.</summary>
    public bool IsLogicalSignaturePrefiltered(LogicalSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        Build();
        return _logicalPrefilter.IsIndexed(signature);
    }

    public IReadOnlyList<Detection> Match(
        ReadOnlySpan<byte> data,
        string databaseLabel,
        bool includeNdb = true,
        bool collectAllMatches = true,
        Func<NdbSignature, bool>? ndbFilter = null,
        ISet<NdbSignature>? ndbPatternCandidates = null,
        Func<NdbSignature, bool>? ndbCandidateFilter = null)
    {
        Build();
        var hits = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
        if (_singleFixedMatcher is not null && _singleFixedEntry is not null &&
            ndbFilter is null && ndbPatternCandidates is null && ndbCandidateFilter is null)
        {
            var singleNdb = _ndbAcEntries.Count == 1 ? _ndbAcEntries[0] : null;
            MatchSingleFixed(
                _singleFixedMatcher, _singleFixedEntry, singleNdb, data, hits,
                includeNdb, ndbFilter, ndbPatternCandidates, ndbCandidateFilter);
        }
        else if (includeNdb)
            MatchAho(
                _ac, _acEntries, _ndbAcEntries, data, hits, 0, data.Length,
                collectAllMatches, true, ndbFilter, ndbPatternCandidates, ndbCandidateFilter);
        else if (_contentAcEntries.Count != 0)
            MatchAho(
                _contentAc, _contentAcEntries, null, data, hits, 0, data.Length,
                collectAllMatches, false, null, null, null);
        if (!collectAllMatches && hits.Count != 0)
            return hits.Values.Take(1).ToArray();

        foreach (var content in _flexibleContent)
        {
            MatchFlexible(content, data, hits, 0);
            if (!collectAllMatches && hits.Count != 0)
                return hits.Values.Take(1).ToArray();
        }

        if (includeNdb)
        {
            foreach (var ndb in _flexibleNdb)
            {
                if (ndbFilter is not null && !ndbFilter(ndb))
                    continue;
                MatchFlexible(ndb, data, hits, 0, data.Length);
                if (!collectAllMatches && hits.Count != 0)
                    return hits.Values.Take(1).ToArray();
            }
        }

        var digestCache = new Dictionary<HashAlgorithmKind, byte[]>();
        foreach (var algorithm in _hashAlgorithms)
        {
            var hasExact = TryGetApplicableBucket(_hashBuckets, algorithm, data.Length, out var exactBucket);
            var hasWildcard = TryGetApplicableBucket(_hashBuckets, algorithm, null, out var wildcardBucket);
            if (!hasExact && !hasWildcard)
                continue;

            if (!digestCache.TryGetValue(algorithm, out var digest))
            {
                digest = ComputeHash(algorithm, data);
                digestCache[algorithm] = digest;
            }

            MatchHashBucket(exactBucket, digest, hits);
            if (!collectAllMatches && hits.Count != 0)
                return hits.Values.Take(1).ToArray();
            MatchHashBucket(wildcardBucket, digest, hits);
            if (!collectAllMatches && hits.Count != 0)
                return hits.Values.Take(1).ToArray();
        }

        return collectAllMatches ? hits.Values.ToArray() : hits.Values.Take(1).ToArray();
    }

    public async Task<(IReadOnlyList<Detection> Detections, bool Trusted, long BytesRead)> MatchStreamAsync(
        Stream input,
        int chunkSize,
        int maxFlexibleLookbehind,
        string databaseLabel,
        CancellationToken cancellationToken = default,
        bool includeNdb = true,
        bool collectAllMatches = true,
        Func<NdbSignature, bool>? ndbFilter = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead) throw new ArgumentException("Stream must be readable.", nameof(input));
        if (chunkSize < 1) throw new ArgumentOutOfRangeException(nameof(chunkSize));
        if (maxFlexibleLookbehind < 1) throw new ArgumentOutOfRangeException(nameof(maxFlexibleLookbehind));

        Build();
        var hits = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
        var buffer = new byte[chunkSize];
        var scratch = Array.Empty<byte>();
        var acState = 0;
        var ignoredPatternIds = new HashSet<int>();
        long absoluteOffset = 0;
        long totalBytes = 0;
        var expectedLength = input.CanSeek ? input.Length : (long?)null;
        var rollingSize = HasUnboundedPattern
            ? maxFlexibleLookbehind
            : Math.Max(0, Math.Min(maxFlexibleLookbehind, MaxFinitePatternLength - 1));
        var rolling = rollingSize == 0 ? Array.Empty<byte>() : new byte[rollingSize];
        var rollingCount = 0;

        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var sawMd5 = NeedsHash(HashAlgorithmKind.Md5, expectedLength);
        var sawSha1 = NeedsHash(HashAlgorithmKind.Sha1, expectedLength);
        var sawSha256 = NeedsHash(HashAlgorithmKind.Sha256, expectedLength);
        var mustFinishForFalsePositiveCheck = HasApplicableFalsePositiveRules(expectedLength);

        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0) break;
            totalBytes += read;

            if (sawMd5) md5.AppendData(buffer, 0, read);
            if (sawSha1) sha1.AppendData(buffer, 0, read);
            if (sawSha256) sha256.AppendData(buffer, 0, read);

            if (collectAllMatches || hits.Count == 0)
            {
                // Do not scan the combined NDB automaton when this pass only needs
                // ordinary Content signatures. Large databases can have many NDB
                // outputs for common byte sequences, even though the caller discards
                // every one of them.
                var matcher = includeNdb ? _ac : _contentAc;
                var entries = includeNdb ? _acEntries : _contentAcEntries;
                var ndbEntries = includeNdb ? _ndbAcEntries : null;
                matcher.ScanUntil(buffer.AsSpan(0, read), ref acState, absoluteOffset, (id, endOffset) =>
                {
                    var item = entries[id];
                    if (hits.ContainsKey(item.Name))
                    {
                        ignoredPatternIds.Add(id);
                        return false;
                    }
                    if (item.Type == SignatureType.Ndb)
                    {
                        var ndb = ndbEntries is not null ? ndbEntries[id] : null;
                        if (ndb is null || (ndbFilter is not null && !ndbFilter(ndb)))
                        {
                            // Target-inapplicable fixed patterns can never be useful
                            // on this scan's byte layer. Ignore their later outputs.
                            ignoredPatternIds.Add(id);
                            return false;
                        }
                    }
                    var start = endOffset - item.Pattern.MinLength + 1;
                    // The AC automaton has already compared every byte of a fixed signature, including
                    // bytes that crossed a chunk boundary. Only the offset constraint remains to check.
                    if (start < 0 || !OffsetAllowsStreaming(item.OffsetExpression, start, endOffset, expectedLength))
                        return false;

                    hits.TryAdd(item.Name,
                        new Detection(item.Name, item.Type, start, item.SourceFile, "Content pattern matched while streaming."));
                    ignoredPatternIds.Add(id);
                    return !collectAllMatches && !mustFinishForFalsePositiveCheck;
                }, ignoredPatternIds);
                if (!collectAllMatches && hits.Count != 0 && !mustFinishForFalsePositiveCheck)
                    return (hits.Values.ToArray(), false, totalBytes);
            }

            if (_flexibleContent.Count != 0 || (includeNdb && _flexibleNdb.Count != 0))
            {
                var combinedLength = rollingCount + read;
                if (combinedLength > 0)
                {
                    scratch = scratch.Length >= combinedLength ? scratch : new byte[Math.Max(combinedLength, 4096)];
                    if (rollingCount > 0) Buffer.BlockCopy(rolling, 0, scratch, 0, rollingCount);
                    buffer.AsSpan(0, read).CopyTo(scratch.AsSpan(rollingCount));
                    var view = scratch.AsSpan(0, combinedLength);
                    var viewStartOffset = absoluteOffset - rollingCount;

                    foreach (var content in _flexibleContent)
                    {
                        var before = hits.Count;
                        MatchFlexible(content, view, hits, viewStartOffset);
                        if (!collectAllMatches && hits.Count != before && !mustFinishForFalsePositiveCheck)
                        {
                            return (hits.Values.ToArray(), false, totalBytes);
                        }
                    }
                    if (includeNdb)
                    {
                        foreach (var ndb in _flexibleNdb)
                        {
                            if (ndbFilter is not null && !ndbFilter(ndb))
                                continue;

                            var before = hits.Count;
                            MatchFlexible(ndb, view, hits, viewStartOffset);
                            if (!collectAllMatches && hits.Count != before && !mustFinishForFalsePositiveCheck)
                            {
                                return (hits.Values.ToArray(), false, totalBytes);
                            }
                        }
                    }

                    if (rollingSize > 0)
                    {
                        var keep = Math.Min(rollingSize, combinedLength);
                        view[^keep..].CopyTo(rolling);
                        rollingCount = keep;
                    }
                }
            }

            absoluteOffset += read;
        }

        var digests = new Dictionary<HashAlgorithmKind, byte[]>();
        if (sawMd5) digests[HashAlgorithmKind.Md5] = md5.GetHashAndReset();
        if (sawSha1) digests[HashAlgorithmKind.Sha1] = sha1.GetHashAndReset();
        if (sawSha256) digests[HashAlgorithmKind.Sha256] = sha256.GetHashAndReset();

        var trusted = false;
        foreach (var algorithm in _hashAlgorithms)
        {
            if (!digests.TryGetValue(algorithm, out var digest)) continue;
            if (TryGetApplicableBucket(_hashBuckets, algorithm, totalBytes, out var exactBucket))
            {
                MatchHashBucket(exactBucket, digest, hits);
                if (!collectAllMatches && hits.Count != 0 && !mustFinishForFalsePositiveCheck)
                    return (hits.Values.ToArray(), false, totalBytes);
            }
            if (TryGetApplicableBucket(_hashBuckets, algorithm, null, out var wildcardBucket))
            {
                MatchHashBucket(wildcardBucket, digest, hits);
                if (!collectAllMatches && hits.Count != 0 && !mustFinishForFalsePositiveCheck)
                    return (hits.Values.ToArray(), false, totalBytes);
            }
        }

        foreach (var algorithm in _falsePositiveAlgorithms)
        {
            if (!digests.TryGetValue(algorithm, out var digest)) continue;
            if (TryGetApplicableBucket(_falsePositiveBuckets, algorithm, totalBytes, out var exactBucket) &&
                HashBucketMatches(exactBucket, digest))
            {
                trusted = true;
                break;
            }
            if (TryGetApplicableBucket(_falsePositiveBuckets, algorithm, null, out var wildcardBucket) &&
                HashBucketMatches(wildcardBucket, digest))
            {
                trusted = true;
                break;
            }
        }

        // A matching .fp/.sfp rule verifies this whole scan layer. ClamAV clears any
        // alert evidence already generated for the layer and stops descending into it.
        if (trusted)
            return ([], true, totalBytes);

        return (hits.Values.ToArray(), false, totalBytes);
    }

    public bool MatchesFalsePositive(ReadOnlySpan<byte> data)
    {
        if (_falsePositiveAlgorithms.Count == 0) return false;

        foreach (var algorithm in _falsePositiveAlgorithms)
        {
            HashBucket? exactBucket = null;
            HashBucket? wildcardBucket = null;
            var hasExact = TryGetApplicableBucket(_falsePositiveBuckets, algorithm, data.Length, out exactBucket);
            var hasWildcard = TryGetApplicableBucket(_falsePositiveBuckets, algorithm, null, out wildcardBucket);
            if (!hasExact && !hasWildcard)
                continue;

            var digest = ComputeHash(algorithm, data);
            if (HashBucketMatches(exactBucket, digest) || HashBucketMatches(wildcardBucket, digest))
                return true;
        }
        return false;
    }

    private bool HasApplicableFalsePositiveRules(long? knownLength)
    {
        if (_falsePositiveAlgorithms.Count == 0) return false;
        if (knownLength is null) return true;

        foreach (var algorithm in _falsePositiveAlgorithms)
        {
            if (_falsePositiveBuckets.ContainsKey((algorithm, knownLength.Value)) ||
                _falsePositiveBuckets.ContainsKey((algorithm, null)))
                return true;
        }
        return false;
    }

    private bool NeedsHash(HashAlgorithmKind algorithm, long? knownLength)
    {
        // With a seekable source we know the final size before reading. Avoid
        // computing an algorithm when neither its exact-size bucket nor wildcard
        // bucket can possibly match. For non-seekable streams we must keep the
        // algorithm alive until EOF because a size-specific rule may match.
        var hasDetection = _hashAlgorithms.Contains(algorithm) &&
                           (knownLength is null ||
                            _hashBuckets.ContainsKey((algorithm, knownLength.Value)) ||
                            _hashBuckets.ContainsKey((algorithm, null)));
        var hasTrust = _falsePositiveAlgorithms.Contains(algorithm) &&
                       (knownLength is null ||
                        _falsePositiveBuckets.ContainsKey((algorithm, knownLength.Value)) ||
                        _falsePositiveBuckets.ContainsKey((algorithm, null)));
        return hasDetection || hasTrust;
    }
}
