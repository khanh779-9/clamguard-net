using System.Text;
using System.Text.RegularExpressions;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

/// <summary>
/// Matcher PCRE cho regex subsignatures của chữ ký logic LDB.
/// </summary>
internal static class RegexContentMatcher
{
    internal static List<int> FindRegexMatches(LdbRegexSubSignature signature, ReadOnlySpan<byte> data, LdbScanContext context, int maxMatches)
    {
        if (maxMatches <= 0 || data.IsEmpty)
            return [];

        RegexOptions options = RegexOptions.Compiled | RegexOptions.CultureInvariant;
        if (signature.Flags.Contains('i')) options |= RegexOptions.IgnoreCase;
        if (signature.Flags.Contains('s')) options |= RegexOptions.Singleline;
        if (signature.Flags.Contains('m')) options |= RegexOptions.Multiline;
        if (signature.Flags.Contains('x')) options |= RegexOptions.IgnorePatternWhitespace;

        Regex regex;
        try
        {
            var regexPattern = signature.Flags.Contains('U') ? MakeUngreedyRegex(signature.Pattern) : signature.Pattern;
            if (signature.Flags.Contains('E'))
                regexPattern = MakeDollarEndOnlyRegex(regexPattern);
            regex = new Regex(regexPattern, options, TimeSpan.FromMilliseconds(250));
        }
        catch (ArgumentException)
        {
            return [];
        }

        var input = Encoding.Latin1.GetString(data);
        var ranges = LdbRuntime.ResolveOffset(signature.OffsetExpression, context);
        if (ranges.Count == 0)
            return [];

        var rolling = signature.Flags.Contains('r');
        // ClamAV's r flag is a rolling search modifier and is ignored when the
        // offset expression already supplies a maximum shift range.
        var hasMaxShift = signature.OffsetExpression.Contains(",", StringComparison.Ordinal);
        var global = signature.Flags.Contains('g');
        var encompass = signature.Flags.Contains('e') && hasMaxShift;
        var result = new List<int>();

        foreach (var range in ranges)
        {
            var start = Math.Clamp(range.Start, 0, data.Length);
            if (start >= data.Length)
                continue;
            var end = Math.Clamp(range.EndInclusive, start, data.Length - 1);
            // A single-point offset normally anchors the PCRE at that point.
            // The A flag forces anchoring even for wildcard/shifted offsets.
            var anchored = signature.Flags.Contains('A') || (!global && !rolling && !hasMaxShift && range.Start == range.EndInclusive);
            var scanLimit = ((global || rolling) && !encompass) ? data.Length : end;
            try
            {
                var match = regex.Match(input, start);
                while (match.Success)
                {
                    var matchStart = match.Index;
                    var matchEndExclusive = match.Index + match.Length;
                    var matchEndInclusive = match.Length == 0 ? match.Index : matchEndExclusive - 1;
                    var allowed = matchStart >= start && (global && !encompass || matchStart <= scanLimit) &&
                                  (!anchored || matchStart == start) &&
                                  (!encompass || matchEndExclusive <= range.EndInclusive);
                    if (allowed)
                    {
                        result.Add(matchStart);
                        if (result.Count >= maxMatches || !global)
                            return result;
                    }
                    if (anchored)
                        break;
                    var next = match.Index + Math.Max(match.Length, 1);
                    if (next > scanLimit || next > input.Length)
                        break;
                    match = regex.Match(input, next);
                }
            }
            catch (RegexMatchTimeoutException) { }
        }
        return result;
    }

    private static string MakeUngreedyRegex(string pattern)
    {
        var sb = new StringBuilder(pattern.Length + 16);
        var escaped = false;
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (escaped) { sb.Append(c); escaped = false; continue; }
            if (c == '\\') { sb.Append(c); escaped = true; continue; }
            if (c == '[') inClass = true;
            if (c == ']') inClass = false;
            if (!inClass && (c == '*' || c == '+'))
            {
                sb.Append(c);
                if (i + 1 >= pattern.Length || pattern[i + 1] != '?') sb.Append('?');
                continue;
            }
            if (!inClass && c == '{')
            {
                var close = pattern.IndexOf('}', i + 1);
                if (close > i)
                {
                    sb.Append(pattern, i, close - i + 1);
                    if (close + 1 >= pattern.Length || pattern[close + 1] != '?') sb.Append('?');
                    i = close;
                    continue;
                }
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    private static string MakeDollarEndOnlyRegex(string pattern)
    {
        var sb = new StringBuilder(pattern.Length + 8);
        var escaped = false;
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (escaped)
            {
                sb.Append(c);
                escaped = false;
                continue;
            }
            if (c == '\\')
            {
                sb.Append(c);
                escaped = true;
                continue;
            }
            if (c == '[') inClass = true;
            if (c == ']' && inClass) inClass = false;
            if (c == '$' && !inClass)
                sb.Append("\\z");
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
