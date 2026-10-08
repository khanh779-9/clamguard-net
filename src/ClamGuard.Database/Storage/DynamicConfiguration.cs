namespace ClamGuard.Database.Storage;

/// <summary>
/// Bit flags của các module/submodule dconf — giá trị chuẩn ClamAV (libclamav/dconf.h).
/// </summary>
public static class DynamicConfigFlags
{
    // PE flags
    public const uint PeParite = 0x1;
    public const uint PeKriz = 0x2;
    public const uint PeMagistr = 0x4;
    public const uint PePolipos = 0x8;
    public const uint PeMd5Sect = 0x10;
    public const uint PeUpx = 0x20;
    public const uint PeFsg = 0x40;
    public const uint PeSwizzor = 0x80;
    public const uint PePetite = 0x100;
    public const uint PePeSpin = 0x200;
    public const uint PeYc = 0x400;
    public const uint PeWwPack = 0x800;
    public const uint PeNsPack = 0x1000;
    public const uint PeMew = 0x2000;
    public const uint PeUpack = 0x4000;
    public const uint PeAsPack = 0x8000;
    public const uint PeCatalog = 0x10000;
    public const uint PeCerts = 0x20000;
    public const uint PeMatchIcon = 0x40000;
    public const uint PeImpTbl = 0x80000;

    // Archive flags
    public const uint ArchiveRar = 0x1;
    public const uint ArchiveZip = 0x2;
    public const uint ArchiveGz = 0x4;
    public const uint ArchiveBz = 0x8;
    public const uint ArchiveSzdd = 0x10;
    public const uint ArchiveCab = 0x20;
    public const uint ArchiveChm = 0x40;
    public const uint ArchiveOle2 = 0x80;
    public const uint ArchiveTar = 0x100;
    public const uint ArchiveBinHex = 0x200;
    public const uint ArchiveSis = 0x400;
    public const uint ArchiveNsis = 0x800;
    public const uint ArchiveArj = 0x1000;
    public const uint ArchiveAutoIt = 0x2000;
    public const uint ArchiveCpio = 0x4000;
    public const uint ArchiveIshield = 0x8000;
    public const uint ArchiveSevenZip = 0x10000;
    public const uint ArchiveIso9660 = 0x20000;
    public const uint ArchiveDmg = 0x40000;
    public const uint ArchiveXar = 0x80000;
    public const uint ArchiveHfsPlus = 0x100000;
    public const uint ArchiveXz = 0x200000;
    public const uint ArchivePasswd = 0x400000;
    public const uint ArchiveMbr = 0x800000;
    public const uint ArchiveGpt = 0x1000000;
    public const uint ArchiveApm = 0x2000000;
    public const uint ArchiveEgg = 0x4000000;
    public const uint ArchiveUdf = 0x8000000;
    public const uint ArchiveLhaLzh = 0x10000000;
    public const uint ArchiveAlz = 0x20000000;
    public const uint ArchiveZstd = 0x40000000;

    // Document flags
    public const uint DocumentHtml = 0x1;
    public const uint DocumentRtf = 0x2;
    public const uint DocumentPdf = 0x4;
    public const uint DocumentScript = 0x8;
    public const uint DocumentHtmlSkipRaw = 0x10;
    public const uint DocumentJsNorm = 0x20;
    public const uint DocumentSwf = 0x40;
    public const uint DocumentMsXml = 0x80;
    public const uint DocumentOoXml = 0x100;
    public const uint DocumentHwp = 0x200;
    public const uint DocumentOneNote = 0x400;

    // Mail flags
    public const uint MailMbox = 0x1;
    public const uint MailTnef = 0x2;

    // Other flags
    public const uint OtherUuEnc = 0x1;
    public const uint OtherScrenc = 0x2;
    public const uint OtherRiff = 0x4;
    public const uint OtherJpeg = 0x8;
    public const uint OtherCryptff = 0x10;
    public const uint OtherDlp = 0x20;
    public const uint OtherPrefiltering = 0x80;
    public const uint OtherPdfNameObj = 0x100;
    public const uint OtherPrtnIntxn = 0x200;
    public const uint OtherLzw = 0x400;
    public const uint OtherPng = 0x800;
    public const uint OtherGif = 0x1000;
    public const uint OtherTiff = 0x2000;
    public const uint OtherImageFuzzyHash = 0x4000;

    // PCRE flags
    public const uint PcreSupport = 0x1;
    public const uint PcreOptions = 0x2;
    public const uint PcreGlobal = 0x4;

    // Bytecode flags
    public const uint BytecodeInterpreter = 0x1;
    public const uint BytecodeJitX86 = 0x2;
    public const uint BytecodeJitPpc = 0x4;
    public const uint BytecodeJitArm = 0x8;
}

/// <summary>
/// Ngữ cảnh dconf của engine — tương đương `struct cli_dconf` của ClamAV.
/// Defaults khớp `cli_dconf_init()` (bảng `modules[]` trong libclamav/dconf.c):
/// PE bật tất cả trừ SWIZZOR; BYTECODE bật tất cả trừ JIT_ARM; các module còn lại bật tất cả.
/// </summary>
public sealed class DynamicConfiguration
{
    public uint Pe { get; internal set; } =
        DynamicConfigFlags.PeParite | DynamicConfigFlags.PeKriz | DynamicConfigFlags.PeMagistr |
        DynamicConfigFlags.PePolipos | DynamicConfigFlags.PeMd5Sect | DynamicConfigFlags.PeUpx |
        DynamicConfigFlags.PeFsg | DynamicConfigFlags.PePetite | DynamicConfigFlags.PePeSpin |
        DynamicConfigFlags.PeYc | DynamicConfigFlags.PeWwPack | DynamicConfigFlags.PeNsPack |
        DynamicConfigFlags.PeMew | DynamicConfigFlags.PeUpack | DynamicConfigFlags.PeAsPack |
        DynamicConfigFlags.PeCatalog | DynamicConfigFlags.PeCerts | DynamicConfigFlags.PeMatchIcon |
        DynamicConfigFlags.PeImpTbl;

    public uint Elf { get; internal set; } = 0x1;
    public uint Macho { get; internal set; } = 0x1;

    public uint Archive { get; internal set; } =
        DynamicConfigFlags.ArchiveRar | DynamicConfigFlags.ArchiveZip | DynamicConfigFlags.ArchiveGz |
        DynamicConfigFlags.ArchiveBz | DynamicConfigFlags.ArchiveArj | DynamicConfigFlags.ArchiveSzdd |
        DynamicConfigFlags.ArchiveCab | DynamicConfigFlags.ArchiveChm | DynamicConfigFlags.ArchiveOle2 |
        DynamicConfigFlags.ArchiveTar | DynamicConfigFlags.ArchiveCpio | DynamicConfigFlags.ArchiveBinHex |
        DynamicConfigFlags.ArchiveSis | DynamicConfigFlags.ArchiveNsis | DynamicConfigFlags.ArchiveAutoIt |
        DynamicConfigFlags.ArchiveIshield | DynamicConfigFlags.ArchiveSevenZip | DynamicConfigFlags.ArchiveIso9660 |
        DynamicConfigFlags.ArchiveDmg | DynamicConfigFlags.ArchiveXar | DynamicConfigFlags.ArchiveHfsPlus |
        DynamicConfigFlags.ArchiveXz | DynamicConfigFlags.ArchivePasswd | DynamicConfigFlags.ArchiveMbr |
        DynamicConfigFlags.ArchiveGpt | DynamicConfigFlags.ArchiveApm | DynamicConfigFlags.ArchiveEgg |
        DynamicConfigFlags.ArchiveUdf | DynamicConfigFlags.ArchiveLhaLzh | DynamicConfigFlags.ArchiveAlz |
        DynamicConfigFlags.ArchiveZstd;

    public uint Doc { get; internal set; } =
        DynamicConfigFlags.DocumentHtml | DynamicConfigFlags.DocumentRtf | DynamicConfigFlags.DocumentPdf |
        DynamicConfigFlags.DocumentScript | DynamicConfigFlags.DocumentHtmlSkipRaw | DynamicConfigFlags.DocumentJsNorm |
        DynamicConfigFlags.DocumentSwf | DynamicConfigFlags.DocumentOoXml | DynamicConfigFlags.DocumentMsXml |
        DynamicConfigFlags.DocumentHwp | DynamicConfigFlags.DocumentOneNote;

    public uint Mail { get; internal set; } = DynamicConfigFlags.MailMbox | DynamicConfigFlags.MailTnef;

    public uint Other { get; internal set; } =
        DynamicConfigFlags.OtherUuEnc | DynamicConfigFlags.OtherScrenc | DynamicConfigFlags.OtherRiff |
        DynamicConfigFlags.OtherJpeg | DynamicConfigFlags.OtherCryptff | DynamicConfigFlags.OtherDlp |
        DynamicConfigFlags.OtherPrefiltering | DynamicConfigFlags.OtherPdfNameObj | DynamicConfigFlags.OtherPrtnIntxn |
        DynamicConfigFlags.OtherLzw | DynamicConfigFlags.OtherGif | DynamicConfigFlags.OtherPng |
        DynamicConfigFlags.OtherTiff | DynamicConfigFlags.OtherImageFuzzyHash;

    public uint Phishing { get; internal set; } =
        0x1 | 0x2;

    public uint Bytecode { get; internal set; } =
        DynamicConfigFlags.BytecodeInterpreter | DynamicConfigFlags.BytecodeJitX86 | DynamicConfigFlags.BytecodeJitPpc;

    public uint Pcre { get; internal set; } =
        DynamicConfigFlags.PcreSupport | DynamicConfigFlags.PcreOptions | DynamicConfigFlags.PcreGlobal;

    /// <summary>
    /// Giải quyết masks cho từng module theo semantics `cli_dconf_load()` + `chkflevel()`:
    /// các dòng được xử lý theo thứ tự trong database; dòng CUỐI CÙNG có khoảng
    /// [min,max] flevel bao phủ engine flevel sẽ thắng; dòng không có flevel
    /// (null) áp dụng vô điều kiện; nếu không có dòng nào khớp, module giữ defaults.
    /// </summary>
    public static DynamicConfiguration Resolve(IReadOnlyList<DynamicConfigEntry> entries, int flevel)
    {
        var config = new DynamicConfiguration();
        foreach (var entry in entries)
        {
            if (entry.MinimumFunctionalityLevel is not null && entry.MinimumFunctionalityLevel.Value > flevel)
                continue;
            if (entry.MaximumFunctionalityLevel is not null && entry.MaximumFunctionalityLevel.Value < flevel)
                continue;

            switch (entry.Module)
            {
                case "PE": config.Pe = entry.Value; break;
                case "ELF": config.Elf = entry.Value; break;
                case "MACHO": config.Macho = entry.Value; break;
                case "ARCHIVE": config.Archive = entry.Value; break;
                case "DOCUMENT": config.Doc = entry.Value; break;
                case "MAIL": config.Mail = entry.Value; break;
                case "OTHER": config.Other = entry.Value; break;
                case "PHISHING": config.Phishing = entry.Value; break;
                case "BYTECODE": config.Bytecode = entry.Value; break;
                case "PCRE": config.Pcre = entry.Value; break;
            }
        }
        return config;
    }
}
