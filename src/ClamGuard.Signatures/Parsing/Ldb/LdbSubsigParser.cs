using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Parsing;

internal static class LdbSubsigParser
{
    internal static (int MinDistance, int MaxDistance, int MacroGroup) ParseMacroSubSignature(int subsigIndex, string token, string path)
    {
        var inner = token[2..^1];
        var close = inner.IndexOf('}');
        if (close <= 0 || close + 1 >= inner.Length)
            throw new FormatException($"Invalid LDB macro subsignature in {path}: {token}");
        var range = inner[..close];
        var groupText = inner[(close + 1)..];
        var dash = range.IndexOf('-');
        if (dash <= 0 || !int.TryParse(range[..dash], out var minDistance) || !int.TryParse(range[(dash + 1)..], out var maxDistance) ||
            minDistance < 0 || maxDistance < minDistance || !int.TryParse(groupText, out var groupId) || groupId is < 0 or >= 32)
            throw new FormatException($"Invalid LDB macro subsignature in {path}: {token}");
        if (subsigIndex == 0)
            throw new FormatException($"LDB macro subsignature cannot be the first subsignature: {token}");
        return (minDistance, maxDistance, groupId);
    }

    internal static ContentSignature ParseContentSubSignature(int subsigIndex, string name, string token, string path, string line)
    {
        var fields = token.Split(':');
        string offset;
        string patternText;
        string? modifierText = null;
        switch (fields.Length)
        {
            case 1:
                offset = "*";
                patternText = fields[0];
                break;
            case 2:
                offset = fields[0].Length == 0 ? "*" : fields[0];
                patternText = fields[1];
                break;
            case 3 when fields[1].Length == 0:
                offset = "*";
                patternText = fields[0];
                modifierText = fields[2].Length > 0 ? fields[2] : null;
                break;
            case 3:
                offset = fields[0].Length == 0 ? "*" : fields[0];
                patternText = fields[1];
                modifierText = fields[2].Length > 0 ? fields[2] : null;
                break;
            case 4:
                offset = fields[0].Length == 0 ? "*" : fields[0];
                patternText = fields[1];
                modifierText = fields[3].Length > 0 ? fields[3] : null;
                break;
            default:
                throw new FormatException($"Invalid LDB content subsignature format in {path}: {token}");
        }

        if (string.IsNullOrWhiteSpace(patternText))
            throw new FormatException($"Empty LDB sub-signature pattern in {path}: {line}");
        ValidateLdbOffsetExpression(offset, path, line);

        return new ContentSignature(
            $"{name}#{subsigIndex}",
            SignatureType.Content,
            path,
            HexPatternParser.Parse(patternText),
            offset,
            ParseContentMatchOptions(modifierText, path, line));
    }

    internal static void ValidateLdbOffsetExpression(string expression, string path, string line)
    {
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Unsupported LDB offset '{expression}' in {path}: {line}");
    }

    internal static bool LooksLikeRegexSubSignature(string token)
    {
        var delimiters = FindRegexDelimiters(token);
        return delimiters.HasValue && delimiters.Value.Start > 0;
    }

    private static (int Start, int End)? FindRegexDelimiters(string token)
    {
        var first = token.IndexOf('/');
        if (first <= 0) return null;
        var last = token.LastIndexOf('/');
        if (last <= first) return null;
        return (first, last);
    }

    internal static LdbRegexSubSignature ParseRegexSubSignature(int index, string token, string path, string line)
    {
        var delimiters = FindRegexDelimiters(token);
        if (delimiters is null)
            throw new FormatException($"Invalid LDB PCRE subsignature in {path}: {token}");

        var firstSlash = delimiters.Value.Start;
        var lastSlash = delimiters.Value.End;
        var prefix = token[..firstSlash];
        var colon = prefix.IndexOf(':');
        var offset = colon >= 0 ? prefix[..colon] : "*";
        var trigger = colon >= 0 ? prefix[(colon + 1)..] : prefix;
        if (string.IsNullOrWhiteSpace(trigger) || string.IsNullOrWhiteSpace(token[(firstSlash + 1)..lastSlash]))
            throw new FormatException($"Invalid LDB PCRE trigger or pattern in {path}: {line}");
        if (offset.Length == 0) offset = "*";
        ValidateLdbOffsetExpression(offset, path, line);

        var flags = token[(lastSlash + 1)..];
        const string supported = "greismxAEU";
        foreach (var flag in flags)
        {
            if (!supported.Contains(flag))
                throw new FormatException($"Unsupported LDB PCRE flag '{flag}' in {path}: {line}");
        }
        if (flags.Distinct().Count() != flags.Length)
            throw new FormatException($"Duplicate LDB PCRE flag in {path}: {line}");
        if (flags.Contains('w') || flags.Contains('W'))
            throw new FormatException($"Wide modifier is not supported for PCRE LDB subsignatures: {path}: {line}");
        return new LdbRegexSubSignature(index, trigger, token[(firstSlash + 1)..lastSlash], flags, offset);
    }

    internal static bool LooksLikeByteCompareSubSignature(string token)
    {
        var open = token.IndexOf('(');
        return open > 0 && token.EndsWith(')') &&
               int.TryParse(token[..open], out _) &&
               token.IndexOf('#', open) > open;
    }

    internal static LdbByteCompareSubSignature ParseByteCompareSubSignature(int index, string token, string path, string line)
    {
        var open = token.IndexOf('(');
        var close = token.LastIndexOf(')');
        if (open <= 0 || close != token.Length - 1 || !int.TryParse(token[..open], out var reference) || reference is < 0 or >= 64)
            throw new FormatException($"Invalid byte-compare LDB subsignature in {path}: {line}");

        var parts = token[(open + 1)..close].Split('#');
        if (parts.Length != 3)
            throw new FormatException($"Byte-compare LDB subsignature requires offset#options#comparisons: {path}: {line}");

        var shift = ParseByteCompareShift(parts[0], path, line);
        var (options, byteLength) = ParseByteCompareOptions(parts[1], path, line);
        var comparisons = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => ParseByteCompareComparison(x, path, line))
            .ToArray();
        if (comparisons.Length is < 1 or > 2)
            throw new FormatException($"Byte-compare LDB subsignature supports one or two comparisons: {path}: {line}");

        return new LdbByteCompareSubSignature(index, reference, shift, options, byteLength, comparisons);
    }

    private static int ParseByteCompareShift(string value, string path, string line)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException($"Invalid byte-compare offset '{value}': {path}: {line}");
        if (value.StartsWith(">>", StringComparison.Ordinal))
        {
            var n = ParseNonNegativeInt(value[2..], path, line);
            if (n <= 0) throw new FormatException($"Byte-compare offset must be positive: {path}: {line}");
            return n;
        }
        if (value.StartsWith("<<", StringComparison.Ordinal))
        {
            var n = ParseNonNegativeInt(value[2..], path, line);
            if (n <= 0) throw new FormatException($"Byte-compare offset must be positive: {path}: {line}");
            return checked(-n);
        }
        throw new FormatException($"Invalid byte-compare offset '{value}': {path}: {line}");
    }

    private static (ByteCompareOptions Options, int ByteLength) ParseByteCompareOptions(string value, string path, string line)
    {
        var i = 0;
        var numeric = ByteCompareOptions.None;
        while (i < value.Length && !char.IsDigit(value[i]))
        {
            numeric |= value[i] switch
            {
                'h' => ByteCompareOptions.Hex,
                'd' => ByteCompareOptions.Decimal,
                'a' => ByteCompareOptions.Auto,
                'i' => ByteCompareOptions.Binary,
                'l' => ByteCompareOptions.LittleEndian,
                'b' => ByteCompareOptions.BigEndian,
                'e' => ByteCompareOptions.Exact,
                _ => throw new FormatException($"Invalid byte-compare option '{value[i]}': {path}: {line}")
            };
            i++;
        }

        var numericKinds = new[] { ByteCompareOptions.Hex, ByteCompareOptions.Decimal, ByteCompareOptions.Auto, ByteCompareOptions.Binary }
            .Count(flag => numeric.HasFlag(flag));
        var endianKinds = new[] { ByteCompareOptions.LittleEndian, ByteCompareOptions.BigEndian }
            .Count(flag => numeric.HasFlag(flag));
        if (numericKinds != 1 || endianKinds != 1 || i >= value.Length)
            throw new FormatException($"Invalid byte-compare options '{value}': {path}: {line}");

        var byteLength = ParseNonNegativeInt(value[i..], path, line);
        if (byteLength <= 0)
            throw new FormatException($"Byte-compare length must be positive: {path}: {line}");
        if (numeric.HasFlag(ByteCompareOptions.Decimal) && numeric.HasFlag(ByteCompareOptions.LittleEndian))
            throw new FormatException($"Decimal byte-compare cannot use little-endian: {path}: {line}");
        if (numeric.HasFlag(ByteCompareOptions.Binary) && byteLength is not (1 or 2 or 4 or 8))
            throw new FormatException($"Binary byte-compare length must be 1, 2, 4 or 8: {path}: {line}");
        if (numeric.HasFlag(ByteCompareOptions.Binary)) numeric |= ByteCompareOptions.Exact;
        return (numeric, byteLength);
    }

    private static ByteCompareComparison ParseByteCompareComparison(string value, string path, string line)
    {
        if (value.Length < 2 || value[0] is not ('<' or '>' or '='))
            throw new FormatException($"Invalid byte-compare comparison '{value}': {path}: {line}");
        var number = ParseNumericLong(value[1..], path, line);
        return new ByteCompareComparison(value[0], number);
    }

    internal static LdbFuzzyImageSubSignature ParseFuzzyImageSubSignature(int index, string token, string path, string line)
    {
        var parts = token.Split('#');
        if (parts.Length is < 2 or > 3 || !Core.HexCodec.TryDecode(parts[1], out var hash) || hash.Length != 8)
            throw new FormatException($"Invalid fuzzy_img LDB subsignature: {path}: {line}");
        uint distance = 0;
        if (parts.Length == 3 && (!uint.TryParse(parts[2], out distance) || distance != 0))
            throw new FormatException($"ClamAV 1.5 image fuzzy hashes require hamming distance 0: {path}: {line}");
        return new LdbFuzzyImageSubSignature(index, hash, distance);
    }

    private static int ParseNonNegativeInt(string value, string path, string line)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) && hex >= 0)
            return hex;
        if (int.TryParse(value, out var dec) && dec >= 0)
            return dec;
        throw new FormatException($"Invalid non-negative integer '{value}': {path}: {line}");
    }

    private static long ParseNumericLong(string value, string path, string line)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) && hex >= 0)
            return hex;
        if (long.TryParse(value, out var dec) && dec >= 0)
            return dec;
        throw new FormatException($"Invalid numeric value '{value}': {path}: {line}");
    }

    private static ContentMatchOptions ParseContentMatchOptions(string? text, string path, string line)
    {
        if (string.IsNullOrEmpty(text)) return ContentMatchOptions.None;
        var result = ContentMatchOptions.None;
        foreach (var option in text)
        {
            result |= option switch
            {
                'i' => ContentMatchOptions.IgnoreCase,
                'w' => ContentMatchOptions.Wide,
                'f' => ContentMatchOptions.FullWord,
                'a' => ContentMatchOptions.Ascii,
                _ => throw new FormatException($"Unsupported LDB subsignature modifier '{option}' in {path}: {line}")
            };
        }
        return result;
    }
}
