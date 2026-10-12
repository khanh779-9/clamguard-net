using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Scanner;

/// <summary>
/// Matcher SIMD / AVX2 cho content subsignatures (fixed + wildcard patterns).
/// </summary>
internal static class LogicalContentMatcher
{
    internal static List<int> FindContentMatches(ContentSignature signature, ReadOnlySpan<byte> data, LdbScanContext context, int maxMatches, IReadOnlyDictionary<int, List<int>>? macroPositions = null)
    {
        if (maxMatches <= 0 || data.IsEmpty)
            return [];
        var patterns = new List<HexPattern>(2);
        // ClamAV's `w` creates a wide pattern, while `a` requests the ASCII
        // variant in addition to wide when both are present.
        if (!signature.MatchOptions.HasFlag(ContentMatchOptions.Wide) || signature.MatchOptions.HasFlag(ContentMatchOptions.Ascii))
            patterns.Add(signature.Pattern);
        if (signature.MatchOptions.HasFlag(ContentMatchOptions.Wide))
            patterns.Add(signature.Pattern.ToWideVariant());
        if (patterns.Count == 0) patterns.Add(signature.Pattern);
        var ranges = LdbRuntime.ResolveOffset(signature.OffsetExpression, context, macroPositions: macroPositions);
        var results = new List<int>();
        var options = new PatternMatchOptions(signature.MatchOptions.HasFlag(ContentMatchOptions.IgnoreCase), signature.MatchOptions.HasFlag(ContentMatchOptions.FullWord));
        foreach (var range in ranges)
        {
            var start = Math.Clamp(range.Start, 0, data.Length);
            // A zero-length EOF/EOF-n anchor at file.Length is a valid calculated
            // offset, but it cannot contain a content pattern.
            if (start >= data.Length)
                continue;
            var end = Math.Clamp(range.EndInclusive, start, data.Length - 1);
            var maxBound = Math.Min(range.MaxBound, data.Length);
            foreach (var pattern in patterns)
            {
                var patternMinLen = Math.Max(1, pattern.MinLength);
                var last = pattern.MaxLength == int.MaxValue ? end : Math.Min(end, data.Length - patternMinLen);

                // Hardware-accelerated SIMD / AVX2 fast path for fixed-byte patterns without full-word constraint
                if (pattern.IsFixed && !options.IgnoreCase && !options.FullWord)
                {
                    var targetBytes = pattern.ToFixedBytes().AsSpan();
                    if (targetBytes.IsEmpty) continue;
                    var searchSlice = data.Slice(start, Math.Min(data.Length - start, (last - start) + targetBytes.Length));
                    var offset = 0;
                    while (offset <= searchSlice.Length - targetBytes.Length)
                    {
                        var found = searchSlice[offset..].IndexOf(targetBytes);
                        if (found < 0) break;
                        var absPos = start + offset + found;
                        if (absPos > last) break;
                        if ((long)absPos + targetBytes.Length <= maxBound)
                        {
                            results.Add(absPos);
                            if (results.Count >= maxMatches) return results;
                        }
                        offset += found + 1;
                    }
                    continue;
                }

                // Anchor fast path for wildcard patterns: any match contains the
                // pattern's longest fixed-byte run, so a span search over the
                // range restricts the general matcher to candidate positions
                // instead of attempting it at every byte.
                if (!options.IgnoreCase && !options.FullWord &&
                    pattern.TryGetSearchAnchor(out var anchorOffset, out var anchor) && anchor.Length >= 4)
                {
                    var anchorSearchStart = start;
                    var attempts = 0;
                    while (anchorSearchStart + anchor.Length <= data.Length)
                    {
                        var relative = data.Slice(anchorSearchStart).IndexOf(anchor);
                        if (relative < 0)
                            break;
                        var anchorPos = anchorSearchStart + relative;
                        anchorSearchStart = anchorPos + 1;
                        if (anchorPos > last)
                            break;
                        if (++attempts > 64)
                            break;

                        var candidate = anchorPos - anchorOffset;
                        if (candidate < start || candidate > last)
                            continue;
                        if (!pattern.Matches(data, candidate, out var consumed, options))
                            continue;
                        if (consumed <= 0 || (long)candidate + consumed > maxBound)
                            continue;
                        results.Add(candidate);
                        if (results.Count >= maxMatches)
                            return results;
                    }
                    continue;
                }

                // General fallback path for wildcards / classes / alternates / word-boundaries
                for (var pos = start; pos <= last && pos < data.Length; pos++)
                {
                    if (!pattern.Matches(data, pos, out var consumed, options)) continue;
                    if (consumed <= 0 || (long)pos + consumed > maxBound) continue;
                    results.Add(pos);
                    if (results.Count >= maxMatches) return results;
                }
            }
        }
        return results;
    }
}
