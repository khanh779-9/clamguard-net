namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Mirror of ClamAV 1.5.4 libclamav/matcher.h cli_mtargets[]: signatures are
/// partitioned into per-target matcher roots so a scan only evaluates the
/// automata for the detected file type plus the GENERIC root, with the
/// target-specific root matched before the generic one (cli_scan_buff order).
/// </summary>
public static class SignatureTargetGroups
{
    public const int Generic = 0;
    public const int Pe = 1;
    public const int Ole2 = 2;
    public const int Html = 3;
    public const int Mail = 4;
    public const int Graphics = 5;
    public const int Elf = 6;
    public const int Ascii = 7;
    public const int NotUsed = 8;
    public const int MachO = 9;
    public const int Pdf = 10;
    public const int Flash = 11;
    public const int Java = 12;
    public const int Internal = 13;
    public const int Other = 14;
    public const int Count = 15;

    /// <summary>NDB/LDB Target field value to matcher root index (identity in ClamAV).</summary>
    public static int FromSignatureTarget(int target)
        => target is >= 0 and < Count ? target : Generic;

    /// <summary>
    /// Detected ClamGuard file type to matcher root index. Types that are not
    /// members of any cli_mtargets entry fall back to the GENERIC root, exactly
    /// like cli_scan_buff when no target-specific root exists for the type.
    /// </summary>
    public static int FromFileType(string fileType)
    {
        if (string.IsNullOrEmpty(fileType))
            return Generic;

        return fileType.ToUpperInvariant() switch
        {
            "PE" or "MSEXE" => Pe,
            "OLE2" or "MSOLE2" => Ole2,
            "HTML" => Html,
            "MAIL" => Mail,
            "GRAPHICS" or "GIF" or "PNG" or "JPEG" or "TIFF" => Graphics,
            "ELF" => Elf,
            "ASCII" => Ascii,
            "MACH-O" or "MACHO" or "MACHO_UNIBIN" => MachO,
            "PDF" => Pdf,
            "FLASH" or "SWF" => Flash,
            "JAVA" => Java,
            "INTERNAL" => Internal,
            "OTHER" => Other,
            _ => Generic
        };
    }
}
