using System.Security.Cryptography;
using ClamGuard.Core;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Matching;

public sealed partial class CompiledSignatureSet
{
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
        NdbSignature? ndbSignature,
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        bool includeNdb,
        Func<NdbSignature, bool>? ndbFilter,
        ISet<NdbSignature>? ndbPatternCandidates,
        Func<NdbSignature, bool>? ndbCandidateFilter)
    {
        var start = matcher.FindFirst(data);
        if (start < 0)
            return;

        if (entry.Type == SignatureType.Ndb && ndbSignature is not null &&
            ndbPatternCandidates is not null &&
            !ndbPatternCandidates.Contains(ndbSignature) &&
            (ndbCandidateFilter is null || ndbCandidateFilter(ndbSignature)))
        {
            ndbPatternCandidates.Add(ndbSignature);
        }

        if (entry.Type == SignatureType.Ndb &&
            (!includeNdb || ndbSignature is null || (ndbFilter is not null && !ndbFilter(ndbSignature))))
            return;

        if (OffsetAllows(entry.OffsetExpression, start, data.Length))
        {
            hits.TryAdd(entry.Name, new Detection(entry.Name, entry.Type, start, entry.SourceFile, "Fixed content pattern matched by BM fast path."));
        }
    }

    private const int MinAnchorLength = 4;
    private const int MaxAnchorVerificationsPerPattern = 64;

    private void MatchAho(
        AhoCorasickMatcher matcher,
        IReadOnlyList<ContentSignature> entries,
        IReadOnlyList<NdbSignature?>? ndbEntries,
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        long baseOffset,
        long totalLength,
        bool collectAllMatches,
        bool includeNdb,
        Func<NdbSignature, bool>? ndbFilter,
        ISet<NdbSignature>? ndbPatternCandidates,
        Func<NdbSignature, bool>? ndbCandidateFilter)
    {
        var state = 0;
        var dataLength = data.Length;
        var ignoredPatternIds = new HashSet<int>();
        matcher.ScanUntil(data, ref state, baseOffset, (id, endOffset) =>
        {
            var item = entries[id];
            if (hits.ContainsKey(item.Name))
            {
                ignoredPatternIds.Add(id);
                return false;
            }

            if (item.Type == SignatureType.Ndb)
            {
                var ndb = ndbEntries is not null && (uint)id < (uint)ndbEntries.Count
                    ? ndbEntries[id]
                    : null;
                if (!includeNdb || ndb is null)
                {
                    ignoredPatternIds.Add(id);
                    return false;
                }

                var passesNdbFilter = ndbFilter is null || ndbFilter(ndb);
                if (!passesNdbFilter)
                {
                    if (ndbPatternCandidates is not null &&
                        (ndbCandidateFilter is null || ndbCandidateFilter(ndb)))
                    {
                        // One raw occurrence is enough to admit a fixed pattern to
                        // the later target/offset-aware evaluator. Further raw hits
                        // for the same rule do not add information.
                        ndbPatternCandidates.Add(ndb);
                    }
                    ignoredPatternIds.Add(id);
                    return false;
                }
            }

            var start = endOffset - item.Pattern.MinLength + 1;
            if (start < baseOffset || !OffsetAllows(item.OffsetExpression, start, totalLength))
                return false;
            var relative = start - baseOffset;
            if (relative < 0 || relative > int.MaxValue || (long)relative + item.Pattern.MinLength > dataLength)
                return false;

            // The automaton has already matched every byte in this fixed pattern.
            // One valid occurrence per signature is enough for the detection list.
            hits.TryAdd(item.Name, new Detection(item.Name, item.Type, start, item.SourceFile, "Content pattern matched."));
            ignoredPatternIds.Add(id);
            return !collectAllMatches;
        }, ignoredPatternIds);
    }

    private static void MatchFlexible(
        ContentSignature signature,
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        long baseOffset,
        long? knownLength = null)
        => MatchFlexibleCore(
            signature.Name,
            signature.Type,
            signature.SourceFile,
            signature.Pattern,
            signature.OffsetExpression,
            data,
            hits,
            baseOffset,
            knownLength);

    private static void MatchFlexible(
        NdbSignature signature,
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        long baseOffset,
        long? knownLength = null)
        => MatchFlexibleCore(
            signature.Name,
            SignatureType.Ndb,
            signature.SourceFile,
            signature.Pattern,
            signature.OffsetExpression,
            data,
            hits,
            baseOffset,
            knownLength);

    private static void MatchFlexibleCore(
        string name,
        SignatureType type,
        string sourceFile,
        HexPattern pattern,
        string offsetExpression,
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        long baseOffset,
        long? knownLength)
    {
        var maxStart = data.Length - pattern.MinLength;
        if (maxStart < 0)
            return;

        var fileLength = knownLength ?? (baseOffset + data.Length);

        // Anchor fast path: wildcard-heavy patterns previously forced a full
        // backtracking attempt at every byte position, which dominates scan time
        // on real ClamAV databases. Locating the longest exact-byte run with a
        // span search reduces the matcher to a handful of candidate positions.
        if (pattern.TryGetSearchAnchor(out var anchorOffset, out var anchor) && anchor.Length >= 4)
        {
            var searchStart = 0;
            var attempts = 0;
            while (searchStart + anchor.Length <= data.Length)
            {
                var relative = data.Slice(searchStart).IndexOf(anchor);
                if (relative < 0)
                    break;

                var anchorPosition = searchStart + relative;
                searchStart = anchorPosition + 1;
                if (++attempts > MaxAnchorVerificationsPerPattern)
                    break;

                var candidate = anchorPosition - anchorOffset;
                if (candidate < 0 || candidate > maxStart)
                    continue;
                var absoluteOffset = baseOffset + candidate;
                if (!OffsetAllows(offsetExpression, absoluteOffset, fileLength) ||
                    !pattern.Matches(data, candidate, out _))
                {
                    continue;
                }

                hits.TryAdd(name,
                    new Detection(name, type, absoluteOffset, sourceFile, "Flexible content pattern matched."));
                return;
            }

            return;
        }

        for (var position = 0; position <= maxStart; position++)
        {
            var absoluteOffset = baseOffset + position;
            if (!OffsetAllows(offsetExpression, absoluteOffset, fileLength) ||
                !pattern.Matches(data, position, out _))
            {
                continue;
            }

            hits.TryAdd(name,
                new Detection(name, type, absoluteOffset, sourceFile, "Flexible content pattern matched."));
            return;
        }
    }

    private static bool OffsetAllows(string expression, long offset, long length)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression == "*") return true;
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase)) return offset == length;
        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(expression.AsSpan(4), out var eofShift))
            return offset == length - eofShift;
        if (long.TryParse(expression, out var exact)) return offset == exact;
        // Avoid string.Split() allocation — this method is called per-match in the
        // inner scan loop and the previous Split(",") allocated a string[] each time.
        var comma = expression.IndexOf(',');
        if (comma > 0 && comma < expression.Length - 1 &&
            long.TryParse(expression.AsSpan(0, comma).Trim(), out var minimum) &&
            long.TryParse(expression.AsSpan(comma + 1).Trim(), out var maximum))
            return offset >= minimum && offset <= maximum;
        return false;
    }

    private static bool OffsetAllowsStreaming(string expression, long offset, long endOffset, long? expectedLength)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression == "*") return true;
        if (long.TryParse(expression, out var exact)) return offset == exact;
        // Allocation-free range check — avoid string.Split() in the streaming hot path.
        var comma = expression.IndexOf(',');
        if (comma > 0 && comma < expression.Length - 1 &&
            long.TryParse(expression.AsSpan(0, comma).Trim(), out var minimum) &&
            long.TryParse(expression.AsSpan(comma + 1).Trim(), out var maximum))
            return offset >= minimum && offset <= maximum;
        if (!expectedLength.HasValue) return false;
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
            return endOffset == expectedLength.Value - 1;
        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(expression.AsSpan(4), out var eofShift))
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
