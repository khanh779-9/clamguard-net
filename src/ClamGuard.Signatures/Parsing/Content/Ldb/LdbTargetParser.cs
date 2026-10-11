using ClamGuard.Core;

namespace ClamGuard.Signatures.Parsing;

internal static class LdbTargetParser
{
    internal static LdbTargetDescription? ParseLdbTarget(string text)
    {
        var targetValue = 0;
        var targetSpecified = false;
        var minEngine = 0;
        var maxEngine = int.MaxValue;
        long? minFileSize = null, maxFileSize = null, minEp = null, maxEp = null;
        int? minSections = null, maxSections = null;
        string? container = null, handlerType = null, iconGroup1 = null, iconGroup2 = null;
        IReadOnlyList<string>? intermediates = null;
        var hasNewExtension = false;
        var engineSpecified = false;

        var attrs = text.Split(',', StringSplitOptions.RemoveEmptyEntries);
        if (attrs.Length == 0)
            throw new FormatException("Empty LDB target description.");

        for (var i = 0; i < attrs.Length; i++)
        {
            var token = attrs[i];
            var colon = token.IndexOf(':');
            if (colon <= 0)
                throw new FormatException($"Invalid LDB target attribute: {token}");

            var key = token[..colon];
            var value = token[(colon + 1)..];

            // ClamAV 1.5.4 requires Engine to be the first attribute for backward compatibility.
            if (key.Equals("Engine", StringComparison.Ordinal))
            {
                if (i != 0)
                    throw new FormatException("LDB Engine attribute must be first.");
                (minEngine, maxEngine) = ParseIntRange(value, int.MaxValue, allowWildcard: false, requireRange: true);
                engineSpecified = true;
                continue;
            }

            if (key.Equals("Target", StringComparison.Ordinal))
            {
                if (!int.TryParse(value, out targetValue) || targetValue is < 0 or > 14)
                    throw new FormatException($"Invalid LDB target: {value}");
                targetSpecified = true;
                continue;
            }

            hasNewExtension = true;
            switch (key)
            {
                case "FileSize":
                    (minFileSize, maxFileSize) = ParseLongRange(value, requireRange: true);
                    break;
                case "EntryPoint":
                    (minEp, maxEp) = ParseLongRange(value, requireRange: true);
                    break;
                case "NumberOfSections":
                    (minSections, maxSections) = ParseIntRange(value, int.MaxValue, allowWildcard: false, requireRange: true);
                    break;
                case "IconGroup1":
                    if (value.Length == 0) throw new FormatException("IconGroup1 cannot be empty.");
                    iconGroup1 = value;
                    break;
                case "IconGroup2":
                    if (value.Length == 0) throw new FormatException("IconGroup2 cannot be empty.");
                    iconGroup2 = value;
                    break;
                case "Container":
                    container = NormalizeFileType(value);
                    break;
                case "HandlerType":
                    handlerType = NormalizeFileType(value);
                    break;
                case "Intermediates":
                    var layers = value.Split('>', StringSplitOptions.RemoveEmptyEntries);
                    if (layers.Length == 0 || layers.Length > 16)
                        throw new FormatException("LDB Intermediates supports 1..16 layers.");
                    intermediates = layers.Select(NormalizeFileType).ToArray();
                    break;
                default:
                    // ClamAV treats an unknown TDB attribute as an unsupported signature
                    // and skips that signature instead of failing the whole database file.
                    return null;
            }
        }

        if (!targetSpecified)
            throw new FormatException("LDB target description requires Target.");

        if (hasNewExtension && (!engineSpecified || minEngine < 51))
            throw new FormatException("LDB attributes other than Target require Engine min level >= 51.");

        if (iconGroup1 is not null || iconGroup2 is not null)
        {
            if (targetValue != 1)
                throw new FormatException("IconGroup is only supported with Target:1 (PE).");
        }

        if ((minEp is not null || maxEp is not null || minSections is not null || maxSections is not null) &&
            targetValue is not (1 or 6 or 9))
        {
            throw new FormatException("EntryPoint/NumberOfSections are only supported with PE/ELF/Mach-O targets.");
        }

        return new LdbTargetDescription(
            (SignatureTargetType)targetValue, minFileSize, maxFileSize, minEp, maxEp, minSections, maxSections,
            container, intermediates, handlerType, iconGroup1, iconGroup2, minEngine, maxEngine, targetSpecified);
    }

    private static (int Min, int Max) ParseIntRange(string value, int defaultMax, bool allowWildcard, bool requireRange)
    {
        if (allowWildcard && value == "*") return (0, defaultMax);
        var parts = value.Split('-', 2);
        if (requireRange && parts.Length != 2)
            throw new FormatException($"Invalid numeric range: {value}");
        if (!int.TryParse(parts[0], out var min) || min < 0)
            throw new FormatException($"Invalid numeric range: {value}");
        var max = parts.Length == 1 ? min :
            int.TryParse(parts[1], out var parsedMax) ? parsedMax : throw new FormatException($"Invalid numeric range: {value}");
        if (max < min) throw new FormatException($"Invalid numeric range: {value}");
        return (min, max);
    }

    private static (long Min, long Max) ParseLongRange(string value, bool requireRange)
    {
        var parts = value.Split('-', 2);
        if (requireRange && parts.Length != 2)
            throw new FormatException($"Invalid numeric range: {value}");
        if (!long.TryParse(parts[0], out var min) || min < 0)
            throw new FormatException($"Invalid numeric range: {value}");
        var max = parts.Length == 1 ? min :
            long.TryParse(parts[1], out var parsedMax) ? parsedMax : throw new FormatException($"Invalid numeric range: {value}");
        if (max < min) throw new FormatException($"Invalid numeric range: {value}");
        return (min, max);
    }

    private static string NormalizeFileType(string value)
    {
        if (value == "*") return "ANY";
        var key = value.Trim().ToUpperInvariant();
        return key switch
        {
            "CL_TYPE_ANY" => "ANY",
            "CL_TYPE_MSEXE" or "CL_TYPE_PE" or "PE" => "PE",
            "CL_TYPE_MSOLE2" or "CL_TYPE_OLE2" or "OLE2" => "OLE2",
            "CL_TYPE_HTML" or "HTML" => "HTML",
            "CL_TYPE_MAIL" or "MAIL" => "MAIL",
            "CL_TYPE_GRAPHICS" or "GRAPHICS" => "GRAPHICS",
            "CL_TYPE_ELF" or "ELF" => "ELF",
            "CL_TYPE_TEXT_ASCII" or "CL_TYPE_ASCII" or "ASCII" or "TEXT_ASCII" => "ASCII",
            "CL_TYPE_MACHO" or "CL_TYPE_MACH_O" or "CL_TYPE_MACHO_UNIBIN" or "MACH-O" or "MACHO" => "MACH-O",
            "CL_TYPE_PDF" or "PDF" => "PDF",
            "CL_TYPE_FLASH" or "CL_TYPE_SWF" or "FLASH" or "SWF" => "FLASH",
            "CL_TYPE_JAVA" or "JAVA" => "JAVA",
            "CL_TYPE_INTERNAL" or "INTERNAL" => "INTERNAL",
            "CL_TYPE_OTHER" or "OTHER" => "OTHER",
            "CL_TYPE_7Z" or "7Z" => "7Z",
            "CL_TYPE_ZIP" or "ZIP" => "ZIP",
            "CL_TYPE_RAR" or "RAR" => "RAR",
            "CL_TYPE_TAR" or "TAR" => "TAR",
            "CL_TYPE_POSIX_TAR" or "POSIX_TAR" => "POSIX_TAR",
            "CL_TYPE_OLD_TAR" or "OLD_TAR" => "OLD_TAR",
            "CL_TYPE_GZ" or "GZIP" or "GZ" => "GZ",
            "CL_TYPE_BZ" or "BZIP2" or "BZ" => "BZ",
            "CL_TYPE_XZ" or "XZ" => "XZ",
            "CL_TYPE_CPIO_CRC" or "CPIO_CRC" => "CPIO_CRC",
            "CL_TYPE_CPIO_NEWC" or "CPIO_NEWC" => "CPIO_NEWC",
            "CL_TYPE_CPIO_ODC" or "CPIO_ODC" => "CPIO_ODC",
            "CL_TYPE_CPIO_OLD" or "CPIO_OLD" => "CPIO_OLD",
            "CL_TYPE_OOXML_WORD" or "OOXML_WORD" => "OOXML_WORD",
            "CL_TYPE_OOXML_XL" or "OOXML_XL" => "OOXML_XL",
            "CL_TYPE_OOXML_PPT" or "OOXML_PPT" => "OOXML_PPT",
            "CL_TYPE_CAB" or "CAB" => "CAB",
            "CL_TYPE_RIFF" or "RIFF" => "RIFF",
            _ => key.StartsWith("CL_TYPE_", StringComparison.Ordinal) ? key[8..] : key
        };
    }
}
