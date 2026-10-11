using ClamGuard.Core;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

/// <summary>
/// Scan-order and materialization policy derived from ClamAV 1.5.4's file-type
/// dispatch. Keeping these decisions centralized prevents expensive parsers from
/// running on unrelated layers and, importantly, avoids materializing large PE
/// files merely because the file is executable.
/// </summary>
internal static class ScanTypePolicy
{
    private static readonly HashSet<string> ArchiveTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Types expanded by ArchiveScanner. Parser choice remains independent
        // and is made by ShouldParseContainer below using native-style switches.
        "ZIP", "ZIPSFX", "GZ", "BZ", "XZ", "RAR", "RARSFX", "7Z", "7ZSFX", "ARJ", "ARJSFX",
        "CAB", "CABSFX", "CHM", "ISO", "UDF", "XAR", "DMG", "LHA", "LHA_LZH", "EGG", "EGGSFX",
        "ALZ", "SIS", "NULSFT", "AUTOIT", "ISHIELD_MSI", "SZDD", "MSSZDD", "MSCAB", "MSCHM",
        "POSIX_TAR", "OLD_TAR", "CPIO_NEWC", "CPIO_CRC", "CPIO_ODC", "CPIO_OLD",
        "OLE2", "MSOLE2", "OOXML_WORD", "OOXML_PPT", "OOXML_XL", "OOXML_HWP",
        "RTF", "BINHEX", "UUENCODED", "TNEF", "MAIL", "MHTML", "PDF", "FLASH", "SWF"
    };

    public static bool IsArchiveContainer(string fileType) => ArchiveTypes.Contains(fileType);

    /// <summary>
    /// Whether a file-type parser should run. Disabling a parser never disables the
    /// raw signature pass; it only skips that type's additional decoding/inspection.
    /// </summary>
    public static bool ShouldParseContainer(string fileType, ScanOptions options)
    {
        var type = fileType.ToUpperInvariant();
        // Keep these mappings aligned with CL_SCAN_PARSE_* in ClamAV 1.5.4.
        // Native ClamAV treats OOXML as two independent operations: XMLDOCS
        // optionally processes OOXML metadata, while extraction/scanning of its
        // ZIP members is controlled by ARCHIVE. XML_WORD/XML_XL/XML_HWP use the
        // document parser switch directly.
        if (type is "PDF" or "XDP") return options.ScanPDF;
        if (type is "HTML" or "HTML_UTF16") return options.ScanHTML;
        if (type is "MAIL" or "MHTML" or "TNEF") return options.ScanMail;
        // Native CL_TYPE_UUENCODED dispatch is controlled by DCONF_OTHER / UUENC,
        // not CL_SCAN_PARSE_MAIL. Its capability check remains in ArchiveScanner.
        if (type is "UUENCODED") return true;
        if (type is "FLASH" or "SWF") return options.ScanSWF;
        if (type is "HWP3") return options.ScanHWP3;
        if (type is "ONENOTE") return options.ScanOneNote;
        if (type is "XML_WORD" or "XML_XL" or "XML_HWP") return options.ScanXMLDocs;
        if (type is "OOXML_WORD" or "OOXML_PPT" or "OOXML_XL" or "OOXML_HWP") return options.ScanArchive;
        if (type is "OLE2" or "MSOLE2" or "HWPOLE2") return options.ScanOLE2;
        // Native ClamAV dispatches RTF and BinHex through CL_SCAN_PARSE_ARCHIVE,
        // not CL_SCAN_PARSE_OLE2 / CL_SCAN_PARSE_MAIL.
        if (type is "RTF" or "BINHEX") return options.ScanArchive;
        if (IsPe(type)) return options.ScanPE;
        if (IsElf(type)) return options.ScanELF;
        return options.ScanArchive;
    }

    public static bool ShouldRunSpecializedPreRaw(string fileType, ScanOptions options)
        => RequiresSpecializedPreRaw(fileType) && ShouldParseContainer(fileType, options);

    public static bool IsHeuristic(Detection detection)
        => detection.Name.StartsWith("Heuristics.", StringComparison.OrdinalIgnoreCase);

    public static bool IsPe(string fileType)
        => fileType.Equals("PE", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("MSEXE", StringComparison.OrdinalIgnoreCase);

    public static bool IsElf(string fileType) => fileType.Equals("ELF", StringComparison.OrdinalIgnoreCase);

    public static bool IsMachO(string fileType)
        => fileType.Equals("MACH-O", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("MACHO", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("MACHO_UNIBIN", StringComparison.OrdinalIgnoreCase);

    public static bool IsHwp3(string fileType) => fileType.Equals("HWP3", StringComparison.OrdinalIgnoreCase);

    public static bool IsHwpoLe2(string fileType) => fileType.Equals("HWPOLE2", StringComparison.OrdinalIgnoreCase);

    public static bool RequiresSpecializedPreRaw(string fileType)
        => IsHwp3(fileType) || IsHwpoLe2(fileType) ||
           fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("ONENOTE", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("XDP", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("XML_WORD", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("XML_XL", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("XML_HWP", StringComparison.OrdinalIgnoreCase);

    public static bool RequiresSpecializedPostRaw(string fileType)
        => fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase) ||
           fileType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase);

    public static bool IsText(string fileType)
        => fileType is "ASCII" or "HTML" or "HTML_UTF16" or "TEXT_UTF16LE" or "TEXT_UTF16BE" or "JAVA" or "SCRIPT" or "PS";

    public static bool IsNormalizedTarget(SignatureTargetType target)
        => target is SignatureTargetType.Html or SignatureTargetType.Ascii;

    public static bool IsNormalizedTarget(int target)
        => target is 3 or 7;

    /// <summary>
    /// NDB signatures that can be evaluated against the raw byte stream without
    /// parsing or normalization stay on the streaming path. ClamAV uses its AC
    /// matcher for both fixed and content-style bodies; only rules requiring a
    /// transformed target, macro reconstruction, or unsupported offset semantics
    /// need a later materialized pass.
    /// </summary>
    public static bool CanStreamRawNdb(NdbSignature signature, string fileType)
    {
        if (signature.MacroGroup is not null)
            return false;
        if (IsNormalizedTarget(signature.Target))
            return false;
        if (!LdbRuntime.TargetMatchesFileType(signature.Target, fileType))
            return false;
        return IsRawOffsetStreamSafe(signature.OffsetExpression);
    }

    public static bool IsRawOffsetStreamSafe(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression.Trim() == "*")
            return true;

        var value = expression.Trim();
        if (value.Equals("EOF", StringComparison.OrdinalIgnoreCase))
            return true;
        if (value.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value[4..], out var eofShift))
            return eofShift >= 0;
        if (int.TryParse(value, out var absolute))
            return absolute >= 0;

        var comma = value.IndexOf(',');
        return comma > 0 && comma < value.Length - 1 &&
               int.TryParse(value.AsSpan(0, comma).Trim(), out var min) &&
               int.TryParse(value.AsSpan(comma + 1).Trim(), out var max) &&
               min >= 0 && max >= min;
    }

    public static bool LooksLikeMachOFat(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8) return false;
        var magic = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(data[..4]);
        return magic is 0xCAFEBABEu or 0xBEBAFECAu or 0xCAFEBABFu or 0xBFBAFECAu;
    }
}
