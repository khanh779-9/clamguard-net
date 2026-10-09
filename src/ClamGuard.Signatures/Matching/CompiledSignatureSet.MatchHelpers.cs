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
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        bool includeNdb)
    {
        if (!includeNdb && entry.Type == SignatureType.Ndb)
            return;

        var start = matcher.FindFirst(data);
        if (start >= 0 && OffsetAllows(entry.OffsetExpression, start, data.Length))
        {
            hits.TryAdd(entry.Name, new Detection(entry.Name, entry.Type, start, entry.SourceFile, "Fixed content pattern matched by BM fast path."));
        }
    }

    private void MatchAho(
        ReadOnlySpan<byte> data,
        Dictionary<string, Detection> hits,
        long baseOffset,
        long totalLength,
        bool collectAllMatches,
        bool includeNdb)
    {
        var state = 0;
        var matches = new List<(int Id, long EndOffset)>();
        _ac.Scan(data, ref state, baseOffset, matches);
        foreach (var (id, endOffset) in matches)
        {
            var item = _acEntries[id];
            if (!includeNdb && item.Type == SignatureType.Ndb)
                continue;

            var start = endOffset - item.Pattern.MinLength + 1;
            if (start < baseOffset || !OffsetAllows(item.OffsetExpression, start, totalLength)) continue;
            var relative = start - baseOffset;
            if (relative < 0 || relative > int.MaxValue || relative + item.Pattern.MinLength > data.Length) continue;
            // Only fixed patterns enter the AC index. The automaton has already
            // matched all bytes, so re-running the general pattern matcher is redundant.
            if (hits.TryAdd(item.Name, new Detection(item.Name, item.Type, start, item.SourceFile, "Content pattern matched.")) && !collectAllMatches)
                return;
        }
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
