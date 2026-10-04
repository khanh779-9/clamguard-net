using System.Security.Cryptography;
using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Holds immutable-at-scan-time indexes built from parsed signatures.
/// Besides in-memory matching this type supports true chunked stream matching:
/// fixed signatures keep Aho-Corasick state across reads, hashes are incremental,
/// and flexible signatures use a bounded rolling window.
/// </summary>
public sealed class CompiledSignatureSet
{
    private readonly List<ContentSignature> _content = [];
    private readonly List<NdbSignature> _ndb = [];
    private readonly List<LogicalSignature> _logical = [];
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
    private readonly Dictionary<int, ContentSignature> _acEntries = new();
    private readonly Dictionary<int, NdbSignature> _ndbAcEntries = new();
    private AhoCorasickMatcher _ac = new();
    private BoyerMooreHorspoolMatcher? _singleFixedMatcher;
    private ContentSignature? _singleFixedEntry;
    private bool _built;

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
                if (ndb.MacroGroup is null && ndb.Pattern.IsFixed)
                {
                    var id = AddFixedPattern(ndb.Name, SignatureType.Ndb, ndb.SourceFile, ndb.Pattern, ndb.OffsetExpression);
                    _ndbAcEntries[id] = ndb;
                }
                break;
            case ContentSignature content:
                _content.Add(content);
                if (content.Pattern.IsFixed)
                    AddFixedPattern(content.Name, content.Type, content.SourceFile, content.Pattern, content.OffsetExpression);
                break;
            case LogicalSignature logical:
                _logical.Add(logical);
                break;
            case MetadataSignature metadata:
                _metadata.Add(metadata);
                break;
        }
    }

    private int AddFixedPattern(
        string name,
        SignatureType type,
        string sourceFile,
        HexPattern pattern,
        string offsetExpression)
    {
        var id = _acEntries.Count;
        _acEntries[id] = new ContentSignature(name, type, sourceFile, pattern, offsetExpression);
        return id;
    }

    public void Build()
    {
        if (_built) return;

        // Rebuild the trie from the canonical signature index. This makes Add()
        // safe even when signatures arrive in multiple database-loading passes.
        _ac = new AhoCorasickMatcher();
        foreach (var (id, entry) in _acEntries.OrderBy(static x => x.Key))
            _ac.Add(entry.Pattern.ToFixedBytes(), id);
        _ac.Build();

        // Match a single long exact signature with the BM backend rather than
        // paying the AC state-machine cost. With multiple signatures, AC remains
        // the multi-pattern engine and keeps its cross-pattern sharing.
        if (_acEntries.Count == 1)
        {
            _singleFixedEntry = _acEntries.Values.First();
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

    public IReadOnlyList<Detection> Match(ReadOnlySpan<byte> data, string databaseLabel, bool includeNdb = true, bool collectAllMatches = true)
    {
        Build();
        var hits = new Dictionary<string, Detection>(StringComparer.OrdinalIgnoreCase);
        if (_singleFixedMatcher is not null && _singleFixedEntry is not null)
            MatchSingleFixed(_singleFixedMatcher, _singleFixedEntry, data, hits);
        else
            MatchAho(data, databaseLabel, hits, 0, data.Length);
        if (!collectAllMatches && hits.Count != 0)
            return hits.Values.ToArray();

        foreach (var content in _content.Where(x => !x.Pattern.IsFixed))
        {
            MatchFlexible(content, data, hits, 0);
            if (!collectAllMatches && hits.Count != 0)
                return hits.Values.ToArray();
        }

        if (includeNdb)
        {
            foreach (var ndb in _ndb.Where(x => x.MacroGroup is null && !x.Pattern.IsFixed))
            {
                var content = new ContentSignature(ndb.Name, SignatureType.Ndb, ndb.SourceFile, ndb.Pattern, ndb.OffsetExpression);
                MatchFlexible(content, data, hits, 0, data.Length);
                if (!collectAllMatches && hits.Count != 0)
                    return hits.Values.ToArray();
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
                return hits.Values.ToArray();
            MatchHashBucket(wildcardBucket, digest, hits);
            if (!collectAllMatches && hits.Count != 0)
                return hits.Values.ToArray();
        }

        return hits.Values.ToArray();
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
        var acMatches = new List<(int Id, long EndOffset)>(64);
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

            acMatches.Clear();
            _ac.Scan(buffer.AsSpan(0, read), ref acState, absoluteOffset, acMatches);
            foreach (var (id, endOffset) in acMatches)
            {
                var item = _acEntries[id];
                if (item.Type == SignatureType.Ndb)
                {
                    if (!includeNdb || !_ndbAcEntries.TryGetValue(id, out var ndb) || (ndbFilter is not null && !ndbFilter(ndb)))
                        continue;
                }
                var start = endOffset - item.Pattern.MinLength + 1;
                // The AC automaton has already compared every byte of a fixed signature, including
                // bytes that crossed a chunk boundary. Only the offset constraint remains to check.
                if (start < 0 || !OffsetAllowsStreaming(item.OffsetExpression, start, endOffset, expectedLength))
                    continue;

                if (hits.TryAdd(item.Name,
                    new Detection(item.Name, item.Type, start, item.SourceFile, "Content pattern matched while streaming.")) &&
                    !collectAllMatches && !mustFinishForFalsePositiveCheck)
                {
                    return (hits.Values.ToArray(), false, totalBytes);
                }
            }

            if (_content.Any(static x => !x.Pattern.IsFixed) ||
                (includeNdb && _ndb.Any(static x => x.MacroGroup is null && !x.Pattern.IsFixed)))
            {
                var combinedLength = rollingCount + read;
                if (combinedLength > 0)
                {
                    scratch = scratch.Length >= combinedLength ? scratch : new byte[Math.Max(combinedLength, 4096)];
                    if (rollingCount > 0) Buffer.BlockCopy(rolling, 0, scratch, 0, rollingCount);
                    buffer.AsSpan(0, read).CopyTo(scratch.AsSpan(rollingCount));
                    var view = scratch.AsSpan(0, combinedLength);
                    var viewStartOffset = absoluteOffset - rollingCount;

                    foreach (var content in _content.Where(x => !x.Pattern.IsFixed))
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
                        foreach (var ndb in _ndb.Where(x => x.MacroGroup is null && !x.Pattern.IsFixed &&
                                                               (ndbFilter is null || ndbFilter(x))))
                        {
                            var before = hits.Count;
                            MatchFlexible(new ContentSignature(ndb.Name, SignatureType.Ndb, ndb.SourceFile, ndb.Pattern, ndb.OffsetExpression),
                                          view, hits, viewStartOffset);
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

    private static bool TryGetApplicableBucket(
        Dictionary<(HashAlgorithmKind Algorithm, long? Size), HashBucket> buckets,
        HashAlgorithmKind algorithm,
        long? size,
        out HashBucket? bucket)
    {
        if (buckets.TryGetValue((algorithm, size), out var found))
        {
            bucket = found;
            return true;
        }
        bucket = null;
        return false;
    }

    private static bool HashBucketMatches(HashBucket? bucket, ReadOnlySpan<byte> digest)
        => bucket is not null && bucket.ByDigest.TryGetValue(digest.ToArray(), out _);

    private static void MatchHashBucket(HashBucket? bucket, ReadOnlySpan<byte> digest, Dictionary<string, Detection> hits)
    {
        if (bucket is null) return;
        if (!bucket.ByDigest.TryGetValue(digest.ToArray(), out var signatures)) return;
        foreach (var sig in signatures)
            hits.TryAdd(sig.Name, new Detection(sig.Name, sig.Type, null, sig.SourceFile, $"{sig.Algorithm} whole-file hash matched."));
    }

    private static void MatchSingleFixed(
        BoyerMooreHorspoolMatcher matcher,
        ContentSignature entry,
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits)
    {
        var start = matcher.FindFirst(data);
        if (start >= 0 && OffsetAllows(entry.OffsetExpression, start, data.Length))
        {
            hits.TryAdd(entry.Name, new Detection(entry.Name, entry.Type, start, entry.SourceFile, "Fixed content pattern matched by BM fast path."));
        }
    }

    private void MatchAho(ReadOnlySpan<byte> data, string databaseLabel, Dictionary<string, Detection> hits, long baseOffset, long totalLength)
    {
        var state = 0;
        var matches = new List<(int Id, long EndOffset)>();
        _ac.Scan(data, ref state, baseOffset, matches);
        foreach (var (id, endOffset) in matches)
        {
            var item = _acEntries[id];
            var start = endOffset - item.Pattern.MinLength + 1;
            if (start < baseOffset || !OffsetAllows(item.OffsetExpression, start, totalLength)) continue;
            var relative = start - baseOffset;
            if (relative < 0 || relative > int.MaxValue || relative >= data.Length) continue;
            if (!item.Pattern.Matches(data, (int)relative, out var consumed)) continue;
            if ((long)relative + consumed > data.Length) continue;
            hits.TryAdd(item.Name, new Detection(item.Name, item.Type, start, item.SourceFile, "Content pattern matched."));
        }
    }

    private static void MatchFlexible(ContentSignature signature, ReadOnlySpan<byte> data, Dictionary<string, Detection> hits, long baseOffset, long? knownLength = null)
    {
        var maxStart = data.Length - signature.Pattern.MinLength;
        if (maxStart < 0) return;

        for (var position = 0; position <= maxStart; position++)
        {
            var absolute = baseOffset + position;
            if (!OffsetAllows(signature.OffsetExpression, absolute, knownLength ?? (baseOffset + data.Length))) continue;
            if (!signature.Pattern.Matches(data, position, out _)) continue;
            hits.TryAdd(signature.Name,
                new Detection(signature.Name, signature.Type, absolute, signature.SourceFile, "Flexible content pattern matched."));
            return;
        }
    }

    private static bool OffsetAllows(string expression, long offset, long length)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression == "*") return true;
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase)) return offset == length;
        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(expression[4..], out var eofShift))
            return offset == length - eofShift;
        if (long.TryParse(expression, out var exact)) return offset == exact;
        var parts = expression.Split(',', 2, StringSplitOptions.TrimEntries);
        if (parts.Length == 2 && long.TryParse(parts[0], out var minimum) && long.TryParse(parts[1], out var maximum))
            return offset >= minimum && offset <= maximum;
        return false;
    }

    private static bool OffsetAllowsStreaming(string expression, long offset, long endOffset, long? expectedLength)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression == "*") return true;
        if (long.TryParse(expression, out var exact)) return offset == exact;
        var parts = expression.Split(',', 2, StringSplitOptions.TrimEntries);
        if (parts.Length == 2 && long.TryParse(parts[0], out var minimum) && long.TryParse(parts[1], out var maximum))
            return offset >= minimum && offset <= maximum;
        if (!expectedLength.HasValue) return false;
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
            return endOffset == expectedLength.Value - 1;
        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(expression[4..], out var eofShift))
            return offset == expectedLength.Value - eofShift;
        return false;
    }

    private static byte[] ComputeHash(HashAlgorithmKind algorithm, ReadOnlySpan<byte> data) => algorithm switch
    {
        HashAlgorithmKind.Md5 => MD5.HashData(data),
        HashAlgorithmKind.Sha1 => SHA1.HashData(data),
        HashAlgorithmKind.Sha256 => SHA256.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

}
