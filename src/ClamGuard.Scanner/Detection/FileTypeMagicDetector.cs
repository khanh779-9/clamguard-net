using System.Collections.Concurrent;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures.Patterns;
using ClamGuard.Signatures.Parsing;

namespace ClamGuard.Scanner;

/// <summary>
/// Runtime evaluator for ClamAV File Type Magic (FTM) rules.
/// FTM is the primary file-typing mechanism in libclamav; the detector deliberately
/// stays bounded to the available probe so file typing does not force a whole-file
/// materialization.
/// </summary>
internal static class FileTypeMagicDetector
{
    private const int MaxSearchCandidates = 65_536;
    private static readonly ConcurrentDictionary<string, HexPattern> PatternCache = new(StringComparer.Ordinal);

    public static bool TryDetectDirect(
        ReadOnlySpan<byte> data,
        IReadOnlyList<FileTypeMagicRule>? rules,
        out string fileType)
    {
        fileType = string.Empty;
        if (data.IsEmpty || rules is null || rules.Count == 0)
            return false;

        foreach (var rule in rules)
        {
            if (rule.IsPartition || rule.Mode != 0)
                continue;
            // cli_loadftm() stores rtype for mode-1 content signatures. The
            // native mode-0 list only retains type/offset/magic, so rtype does
            // not participate in direct memcmp file typing.
            //
            if (!MatchesRule(rule, data))
                continue;

            var mapped = MapType(rule.Type);
            if (mapped is null || mapped.Equals("IGNORED", StringComparison.OrdinalIgnoreCase))
                continue;

            fileType = mapped;
            return true;
        }
        return false;
    }

    public static bool TryDetectContent(
        ReadOnlySpan<byte> data,
        IReadOnlyList<FileTypeMagicRule>? rules,
        string currentType,
        out string fileType)
    {
        fileType = string.Empty;
        if (data.IsEmpty || rules is null || rules.Count == 0)
            return false;

        foreach (var rule in rules)
        {
            if (rule.IsPartition || rule.Mode != 1)
                continue;
            if (!MatchesRealType(rule.RealType, currentType))
                continue;
            if (!MatchesRule(rule, data))
                continue;

            var mapped = MapType(rule.Type);
            if (mapped is null || mapped.Equals("IGNORED", StringComparison.OrdinalIgnoreCase))
                continue;

            fileType = mapped;
            return true;
        }
        return false;
    }

    private static bool MatchesRule(FileTypeMagicRule rule, ReadOnlySpan<byte> data)
    {
        if (rule.Mode is 0 or 4)
        {
            if (rule.NumericOffset is null || rule.MagicBytes is null)
                return false;
            var offset = rule.NumericOffset.Value;
            return offset >= 0 && offset <= data.Length - rule.MagicBytes.Length &&
                   data.Slice(offset, rule.MagicBytes.Length).SequenceEqual(rule.MagicBytes);
        }

        if (rule.Mode != 1 || string.IsNullOrWhiteSpace(rule.OffsetExpression))
            return false;

        var pattern = GetPattern(rule.MagicExpression);
        if (pattern is null)
            return false;

        var offsetExpression = rule.OffsetExpression.Trim();
        if (TryGetExactOffset(offsetExpression, data.Length, out var exact))
            return exact >= 0 && exact <= data.Length && pattern.Matches(data, exact, out _);

        if (TryGetOffsetRange(offsetExpression, out var minimum, out var maximum))
        {
            maximum = Math.Min(maximum, Math.Max(-1, data.Length - Math.Max(1, pattern.MinLength)));
            return MatchesAtPositions(data, pattern, minimum, maximum);
        }

        if (!offsetExpression.Equals("*", StringComparison.Ordinal))
            return false;

        // Fast path for fixed FTM patterns: use Span.IndexOf instead of invoking
        // the general backtracking matcher at every byte.
        if (pattern.IsFixed)
            return data.IndexOf(pattern.ToFixedBytes()) >= 0;

        // Only the first atom is a safe candidate pre-filter. Looking for a later
        // exact atom could skip valid matches when the pattern begins with a wildcard.
        if (pattern.Atoms.FirstOrDefault() is ExactByteAtom firstExact)
        {
            var candidates = 0;
            var search = 0;
            while (search < data.Length && candidates++ < MaxSearchCandidates)
            {
                var relative = data[search..].IndexOf(firstExact.Value);
                if (relative < 0) break;
                var position = search + relative;
                if (pattern.Matches(data, position, out _))
                    return true;
                search = position + 1;
            }
            return false;
        }

        var maxStart = data.Length - Math.Max(1, pattern.MinLength);
        return MatchesAtPositions(data, pattern, 0, Math.Min(maxStart, MaxSearchCandidates - 1));
    }

    private static bool TryGetOffsetRange(string expression, out int minimum, out int maximum)
    {
        minimum = maximum = 0;
        var parts = expression.Split(',', 2, StringSplitOptions.TrimEntries);
        return parts.Length == 2 &&
               int.TryParse(parts[0], out minimum) &&
               int.TryParse(parts[1], out maximum) &&
               minimum >= 0 && maximum >= minimum;
    }

    private static bool MatchesAtPositions(ReadOnlySpan<byte> data, HexPattern pattern, int minimum, int maximum)
    {
        if (maximum < minimum || minimum >= data.Length) return false;
        minimum = Math.Max(0, minimum);
        maximum = Math.Min(data.Length, maximum);
        var candidates = 0;
        for (var position = minimum; position <= maximum && candidates++ < MaxSearchCandidates; position++)
        {
            if (pattern.Matches(data, position, out _))
                return true;
        }
        return false;
    }

    private static HexPattern? GetPattern(string expression)
    {
        try
        {
            return PatternCache.GetOrAdd(expression, static text => HexPatternParser.Parse(text));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static bool MatchesRealType(string realType, string? currentType)
    {
        if (string.IsNullOrWhiteSpace(realType) || realType.Equals("CL_TYPE_ANY", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.IsNullOrWhiteSpace(currentType))
            return false;
        return FileTypeEquals(MapType(realType), currentType);
    }

    private static bool TryGetExactOffset(string expression, int dataLength, out int offset)
    {
        offset = 0;
        if (int.TryParse(expression, out var absolute) && absolute >= 0)
        {
            offset = absolute;
            return true;
        }
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
        {
            offset = dataLength;
            return true;
        }
        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(expression[4..], out var shift) && shift >= 0)
        {
            offset = dataLength - shift;
            return true;
        }
        return false;
    }

    public static string? MapType(string clamType)
    {
        if (string.IsNullOrWhiteSpace(clamType)) return null;
        var value = clamType.Trim();
        if (value.StartsWith("CL_TYPE_", StringComparison.OrdinalIgnoreCase))
            value = value[8..];

        return value.ToUpperInvariant() switch
        {
            "ANY" => "ANY",
            "MSEXE" => "PE",
            "ELF" => "ELF",
            "MACHO" or "MACHO_UNIBIN" => "MACH-O",
            "MSOLE2" => "OLE2",
            "MSWORD" or "MSWORD2" => "OLE2",
            "BINARY_DATA" => "OTHER",
            "POSIX_TAR" or "OLD_TAR" or "CPIO_OLD" or "CPIO_ODC" or "CPIO_NEWC" or "CPIO_CRC" => value,
            "ISO9660" => "ISO",
            "MSSZDD" => "SZDD",
            "MSCAB" => "CAB",
            "MSCHM" => "CHM",
            "TEXT_ASCII" or "TEXT_UTF8" => "ASCII",
            "TEXT_UTF16LE" => "TEXT_UTF16LE",
            "TEXT_UTF16BE" => "TEXT_UTF16BE",
            "OOXML_WORD" => "OOXML_WORD",
            "OOXML_PPT" => "OOXML_PPT",
            "OOXML_XL" => "OOXML_XL",
            "OOXML_HWP" => "OOXML_HWP",
            "XML_WORD" => "XML_WORD",
            "XML_XL" => "XML_XL",
            "XML_HWP" => "XML_HWP",
            "HTML_UTF16" => "HTML_UTF16",
            "MHTML" => "MHTML",
            "PDF" => "PDF",
            "RTF" => "RTF",
            "GRAPHICS" => "GRAPHICS",
            "GIF" => "GIF",
            "PNG" => "PNG",
            "JPEG" => "JPEG",
            "TIFF" => "TIFF",
            "RIFF" => "RIFF",
            "MAIL" => "MAIL",
            "7Z" or "7ZSFX" => "7Z",
            "ZIP" or "ZIPSFX" => "ZIP",
            "RAR" or "RARSFX" => "RAR",
            "ARJ" or "ARJSFX" => "ARJ",
            "CABSFX" => "CAB",
            "EGG" or "EGGSFX" => "EGG",
            "NULSFT" => "NULSFT",
            "AUTOIT" => "AUTOIT",
            "ISHIELD_MSI" => "ISHIELD_MSI",
            "SIS" => "SIS",
            "XAR" => "XAR",
            "UDF" => "UDF",
            "ONENOTE" => "ONENOTE",
            "AI_MODEL" => "AI_MODEL",
            "PYTHON_COMPILED" => "PYTHON_COMPILED",
            "LHA_LZH" => "LHA",
            "SCRENC" => "SCRENC",
            "SWF" => "FLASH",
            "XZ" => "XZ",
            "GZ" => "GZ",
            "BZ" => "BZ",
            "DMG" => "DMG",
            "HWP3" => "HWP3",
            "HWPOLE2" => "HWPOLE2",
            "XDP" => "XDP",
            "CRYPTFF" => "CRYPTFF",
            "INTERNAL" => "INTERNAL",
            "SFX" => "SFX",
            "SCRIPT" => "SCRIPT",
            "LNK" => "LNK",
            "PS" => "PS",
            _ => value
        };
    }

    private static bool FileTypeEquals(string? expected, string actual)
    {
        if (expected is null || expected.Equals("ANY", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals(actual, StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSEXE", StringComparison.OrdinalIgnoreCase) && actual.Equals("PE", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("ZIP", StringComparison.OrdinalIgnoreCase) && actual.StartsWith("OOXML_", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("OLE2", StringComparison.OrdinalIgnoreCase) && actual.StartsWith("HWP", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MACHO_UNIBIN", StringComparison.OrdinalIgnoreCase) && actual.Equals("MACH-O", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSSZDD", StringComparison.OrdinalIgnoreCase) && actual.Equals("SZDD", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSCAB", StringComparison.OrdinalIgnoreCase) && actual.Equals("CAB", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSCHM", StringComparison.OrdinalIgnoreCase) && actual.Equals("CHM", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
