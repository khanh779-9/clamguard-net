using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal sealed record LdbSection(long RawOffset, long RawSize, long VirtualAddress, long VirtualSize);
internal sealed class LdbExecutableInfo
{
    public long EntryPoint { get; init; }
    public int NumberOfSections { get; init; }
    public IReadOnlyList<LdbSection> Sections { get; init; } = [];
    public IReadOnlyList<(int Start, int End)> VersionInfoRegions { get; init; } = [];
    public IReadOnlyList<LdbIconGroup> IconGroups { get; init; } = [];
}

internal sealed record LdbIconGroup(string GroupId, IReadOnlyList<byte[]> Icons);

internal sealed record LdbScanContext(
    string FileType,
    long FileSize,
    LdbExecutableInfo? Executable,
    IReadOnlyList<string> ParentTypes,
    bool Retyped = false);

internal readonly record struct LdbOffsetRange(int Start, int EndInclusive, int MaxBound = int.MaxValue)
{
    public bool IsValid => Start >= 0 && EndInclusive >= Start;
}

internal static class LdbRuntime
{
    public static LdbScanContext CreateContext(ReadOnlySpan<byte> data, string fileType, IReadOnlyList<string>? parentTypes = null, bool retyped = false)
        => new(fileType, data.Length, ExecutableInspector.TryInspect(data, fileType), parentTypes ?? [], retyped);

    public static bool MatchesTarget(LdbTargetDescription? target, LdbScanContext ctx)
    {
        if (target is null)
            return true;
        if (target.Target != 0 && !TargetMatchesFileType(target.Target, ctx.FileType))
            return false;
        if (target.MinFileSize is not null && ctx.FileSize < target.MinFileSize.Value)
            return false;
        if (target.MaxFileSize is not null && ctx.FileSize > target.MaxFileSize.Value)
            return false;

        if ((target.MinEntryPoint is not null || target.MaxEntryPoint is not null ||
             target.MinSections is not null || target.MaxSections is not null) && ctx.Executable is null)
            return false;

        if (target.MinEntryPoint is not null && ctx.Executable!.EntryPoint < target.MinEntryPoint.Value)
            return false;
        if (target.MaxEntryPoint is not null && ctx.Executable!.EntryPoint > target.MaxEntryPoint.Value)
            return false;
        if (target.MinSections is not null && ctx.Executable!.NumberOfSections < target.MinSections.Value)
            return false;
        if (target.MaxSections is not null && ctx.Executable!.NumberOfSections > target.MaxSections.Value)
            return false;

        if (target.Container is not null)
        {
            // CL_TYPE_ANY is a root-only constraint. A concrete container type
            // must be the immediate parent of the scanned object.
            if (target.Container.Equals("ANY", StringComparison.OrdinalIgnoreCase))
            {
                if (ctx.ParentTypes.Count != 0)
                    return false;
            }
            else if (ctx.ParentTypes.Count == 0 || !FileTypeMatches(target.Container, ctx.ParentTypes[^1]))
            {
                return false;
            }
        }

        if (target.Intermediates is not null)
        {
            if (target.Intermediates.Count > 16 || ctx.ParentTypes.Count < target.Intermediates.Count)
                return false;

            // The database stores intermediates top-down; the last entry is the
            // immediate container. Match the requested suffix of the actual
            // parent chain so additional outer containers are permitted.
            var actualStart = ctx.ParentTypes.Count - target.Intermediates.Count;
            for (var i = 0; i < target.Intermediates.Count; i++)
            {
                var expected = target.Intermediates[i];
                if (!FileTypeMatches(expected, ctx.ParentTypes[actualStart + i]))
                    return false;
            }
        }

        if ((target.IconGroup1 is not null || target.IconGroup2 is not null) && ctx.Executable is null)
            return false;

        return true;
    }

    public static bool TargetMatchesFileType(int target, LdbScanContext ctx) => TargetMatchesFileType(target, ctx.FileType);
    public static bool TargetMatchesFileType(int target, string fileType) => target switch
    {
        0 => true,
        1 => fileType.Equals("PE", StringComparison.OrdinalIgnoreCase),
        2 => fileType.Equals("OLE2", StringComparison.OrdinalIgnoreCase),
        3 => fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase),
        4 => fileType.Equals("MAIL", StringComparison.OrdinalIgnoreCase),
        5 => fileType is "GRAPHICS" or "GIF" or "PNG" or "JPEG" or "TIFF",
        6 => fileType.Equals("ELF", StringComparison.OrdinalIgnoreCase),
        7 => fileType.Equals("ASCII", StringComparison.OrdinalIgnoreCase),
        8 => false,
        9 => fileType is "MACH-O" or "MACHO" or "MACHO_UNIBIN",
        10 => fileType.Equals("PDF", StringComparison.OrdinalIgnoreCase),
        11 => fileType.Equals("FLASH", StringComparison.OrdinalIgnoreCase),
        12 => fileType.Equals("JAVA", StringComparison.OrdinalIgnoreCase),
        13 => fileType.Equals("INTERNAL", StringComparison.OrdinalIgnoreCase),
        14 => fileType.Equals("OTHER", StringComparison.OrdinalIgnoreCase),
        _ => false
    };

    private static bool FileTypeMatches(string expected, string actual)
    {
        if (expected.Equals("ANY", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals(actual, StringComparison.OrdinalIgnoreCase)) return true;

        // ClamAV may assign a specialized type to a ZIP-backed document while
        // container signatures still refer to the underlying ZIP/OLE container.
        if (expected.Equals("ZIP", StringComparison.OrdinalIgnoreCase) &&
            actual.StartsWith("OOXML_", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("OLE2", StringComparison.OrdinalIgnoreCase) &&
            actual.StartsWith("HWP", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("TAR", StringComparison.OrdinalIgnoreCase) &&
            actual is "POSIX_TAR" or "OLD_TAR") return true;
        if (expected.Equals("MSSZDD", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("SZDD", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSCAB", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("CAB", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSCHM", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("CHM", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSOLE2", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("OLE2", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("ISO9660", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("ISO", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MSEXE", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("PE", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MACHO_UNIBIN", StringComparison.OrdinalIgnoreCase) &&
            actual.Equals("MACH-O", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("ZIPSFX", StringComparison.OrdinalIgnoreCase) && actual.Equals("ZIP", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("RARSFX", StringComparison.OrdinalIgnoreCase) && actual.Equals("RAR", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("ARJSFX", StringComparison.OrdinalIgnoreCase) && actual.Equals("ARJ", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("CABSFX", StringComparison.OrdinalIgnoreCase) && actual.Equals("CAB", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("7ZSFX", StringComparison.OrdinalIgnoreCase) && actual.Equals("7Z", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("EGGSFX", StringComparison.OrdinalIgnoreCase) && actual.Equals("EGG", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("SWF", StringComparison.OrdinalIgnoreCase) && actual.Equals("FLASH", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("MHTML", StringComparison.OrdinalIgnoreCase) && actual.Equals("MHTML", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public static List<LdbOffsetRange> ResolveOffset(string expression, LdbScanContext ctx, int macroIndex = -1, IReadOnlyDictionary<int, List<int>>? macroPositions = null)
    {
        expression = string.IsNullOrWhiteSpace(expression) ? "*" : expression.Trim();

        // NDB/LDB floating offsets use `base,maxshift`. Parse the shift first so
        // absolute offsets such as `123,8` work as intended instead of falling
        // through to the executable-only relative-offset branch.
        var maxShift = 0;
        var comma = expression.IndexOf(',');
        if (comma >= 0)
        {
            if (expression.IndexOf(',', comma + 1) >= 0 ||
                !int.TryParse(expression[(comma + 1)..].Trim(), out maxShift) || maxShift < 0)
                return [];
            expression = expression[..comma].Trim();
        }

        if (expression == "*")
            return [new(0, checked((int)Math.Min(int.MaxValue, Math.Max(0, ctx.FileSize - 1))))];

        if (expression.Equals("VI", StringComparison.OrdinalIgnoreCase))
            return ctx.Executable?.VersionInfoRegions.Select(x => new LdbOffsetRange(x.Start, x.End)).ToList() ?? [];

        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
        {
            var p = ctx.FileSize;
            return p >= 0 && p <= int.MaxValue ? [new((int)p, (int)p)] : [];
        }

        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[4..], out var eofShift))
        {
            if (eofShift < 0) return [];
            var p = ctx.FileSize - eofShift;
            return p >= 0 && p <= int.MaxValue ? [new((int)p, (int)Math.Min(int.MaxValue, p + (long)maxShift))] : [];
        }

        if (expression.StartsWith("$", StringComparison.Ordinal) && expression.EndsWith("$") && int.TryParse(expression[1..^1], out var group) && group is >= 0 and < 32)
        {
            var last = macroPositions is not null && macroPositions.TryGetValue(group, out var positions) && positions.Count != 0
                ? positions.Max()
                : -1;
            return last >= 0 ? [new(last, (int)Math.Min(int.MaxValue, (long)last + maxShift))] : [];
        }

        if (int.TryParse(expression, out var absolute))
            return absolute >= 0 ? [new(absolute, (int)Math.Min(int.MaxValue, (long)absolute + maxShift))] : [];

        if (ctx.Executable is null)
            return [];

        if (expression.StartsWith("EP+", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var epPlus))
            return ExactWithShift(ctx.Executable.EntryPoint, epPlus, maxShift);
        if (expression.StartsWith("EP-", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var epMinus))
            return ExactWithShift(ctx.Executable.EntryPoint, -epMinus, maxShift);
        if (expression.StartsWith("SL+", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var slPlus))
        {
            var last = ctx.Executable.Sections.LastOrDefault();
            return last is null ? [] : ExactWithShift(last.RawOffset, slPlus, maxShift);
        }
        if (expression.StartsWith("SE", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[2..], out var seIndex))
        {
            if ((uint)seIndex >= (uint)ctx.Executable.Sections.Count) return [];
            var section = ctx.Executable.Sections[seIndex];
            if (section.RawSize <= 0) return [];
            var start = section.RawOffset;
            var end = section.RawOffset + section.RawSize - 1L + maxShift;
            var maxBound = section.RawOffset + section.RawSize;
            if (start < 0 || start > int.MaxValue || end < start) return [];
            return [new((int)start, (int)Math.Min(int.MaxValue, end), (int)Math.Min(int.MaxValue, maxBound))];
        }
        if (expression.StartsWith("S", StringComparison.OrdinalIgnoreCase))
        {
            var plus = expression.IndexOf('+');
            if (plus > 1 && int.TryParse(expression[1..plus], out var sIndex) && int.TryParse(expression[(plus + 1)..], out var sShift))
            {
                if ((uint)sIndex >= (uint)ctx.Executable.Sections.Count) return [];
                return ExactWithShift(ctx.Executable.Sections[sIndex].RawOffset, sShift, maxShift);
            }
        }
        return [];
    }

    private static List<LdbOffsetRange> ExactWithShift(long baseOffset, int relative, int maxShift)
    {
        var start = baseOffset + relative;
        if (start < 0 || start > int.MaxValue) return [];
        var endLong = start + (long)Math.Max(0, maxShift);
        if (endLong < start) return [];
        return [new((int)start, (int)Math.Min(int.MaxValue, endLong))];
    }

    public static bool HasIconGroup(ReadOnlySpan<byte> data, LdbScanContext ctx, string? group1, string? group2, IconDatabase? database)
    {
        if (database is null || ctx.Executable is null || ctx.FileType != "PE") return false;
        var groups = ctx.Executable.IconGroups;
        if (groups.Count == 0) return false;

        var wanted1 = string.IsNullOrEmpty(group1) ? "*" : group1;
        var wanted2 = string.IsNullOrEmpty(group2) ? "*" : group2;
        foreach (var iconGroup in groups)
        {
            foreach (var icon in iconGroup.Icons)
            {
                if (!IconDecoder.TryDecode(icon, out var image)) continue;
                var prepared = IconMetrics.PrepareForClam(image);
                var side = prepared.Width;
                foreach (var dbEntry in database.Entries.Where(e => GroupMatches(wanted1, e.Group1) && GroupMatches(wanted2, e.Group2) && e.Metric.Side == side))
                    if (IconMetrics.Matches(prepared, dbEntry.Metric, alreadyPrepared: true)) return true;
            }
        }
        return false;
    }

    private static bool GroupMatches(string wanted, string actual)
        => wanted == "*" || wanted.Equals(actual, StringComparison.Ordinal);


    public static bool FuzzyImageMatches(ReadOnlySpan<byte> data, byte[] expectedHash)
    {
        if (expectedHash.Length != 8) return false;
        if (!ImageDecoder.TryDecode(data, out var image)) return false;
        var hash = ImageFuzzyHasher.Compute(image);
        return hash.AsSpan().SequenceEqual(expectedHash);
    }

    internal static IReadOnlyList<(int Offset, int Length)> GetMachOFatSlices(ReadOnlySpan<byte> data)
        => ExecutableInspector.GetMachOFatSlices(data);
}

internal sealed record RgbImage(int Width, int Height, byte[] Pixels)
{
    public int Index(int x, int y) => (y * Width + x) * 3;
}

internal static class ExecutableInspector
{
    public static LdbExecutableInfo? TryInspect(ReadOnlySpan<byte> data, string fileType)
        => fileType.ToUpperInvariant() switch
        {
            "PE" => TryPe(data),
            "ELF" => TryElf(data),
            "MACH-O" => TryMachO(data),
            _ => null
        };

    private static LdbExecutableInfo? TryPe(ReadOnlySpan<byte> data)
    {
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return null;
        var pe = ReadI32(data, 0x3c);
        if (pe < 0 || (long)pe + 24 > data.Length || ReadU32(data, pe) != 0x00004550) return null;
        var sections = ReadU16(data, pe + 6);
        var optSize = ReadU16(data, pe + 20);
        var opt = pe + 24;
        if (opt < 0 || (long)opt + optSize > data.Length || optSize < 32) return null;
        var magic = ReadU16(data, opt);
        var dataDirBase = magic == 0x20b ? opt + 112 : magic == 0x10b ? opt + 96 : -1;
        if ((long)opt + 64 > data.Length) return null;
        var entryRva = ReadU32(data, opt + 16);
        var sectionTable = opt + optSize;
        var headerSize = magic == 0x20b || magic == 0x10b ? (long)ReadU32(data, opt + 60) : sectionTable - pe;
        if (headerSize < 0) return null;
        var list = new List<LdbSection>();
        var tableEnd = (long)sectionTable + (long)sections * 40;
        if (sectionTable < 0 || tableEnd > data.Length) return null;
        for (var i = 0; i < sections; i++)
        {
            var o = sectionTable + i * 40;
            list.Add(new LdbSection(ReadU32(data, o + 20), ReadU32(data, o + 16), ReadU32(data, o + 12), ReadU32(data, o + 8)));
        }
        var ep = RvaToRaw(entryRva, list, data.Length, checked((int)Math.Min(int.MaxValue, headerSize)));
        var regions = new List<(int Start, int End)>();
        var icons = new List<LdbIconGroup>();
        if (dataDirBase >= 0 && dataDirBase + 24 <= data.Length)
        {
            var resRva = ReadU32(data, dataDirBase + 8 * 2);
            var resSize = ReadU32(data, dataDirBase + 8 * 2 + 4);
            if (resRva != 0 && resSize != 0)
            {
                var resRaw = RvaToRaw(resRva, list, data.Length, checked((int)Math.Min(int.MaxValue, headerSize)));
                if (resRaw >= 0) ResourceParser.Parse(data, resRaw, resSize, list, regions, icons);
            }
        }
        return new LdbExecutableInfo { EntryPoint = ep, NumberOfSections = list.Count, Sections = list, VersionInfoRegions = regions, IconGroups = icons };
    }

    private static LdbExecutableInfo? TryElf(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16 || data[0] != 0x7f || data[1] != (byte)'E' || data[2] != (byte)'L' || data[3] != (byte)'F') return null;
        var cls = data[4];
        if (cls is not (1 or 2) || data[5] is not (1 or 2)) return null;
        var requiredHeader = cls == 2 ? 64 : 52;
        if (data.Length < requiredHeader) return null;
        var le = data[5] == 1;
        var entry = U64(data, 24, le, cls == 2);
        var phoff = U64(data, cls == 2 ? 32 : 28, le, cls == 2);
        var phentsize = ReadU16Endian(data, cls == 2 ? 54 : 42, le);
        var phnum = ReadU16Endian(data, cls == 2 ? 56 : 44, le);
        var shoff = U64(data, cls == 2 ? 40 : 32, le, cls == 2);
        var shentsize = ReadU16Endian(data, cls == 2 ? 58 : 46, le);
        var shnum = ReadU16Endian(data, cls == 2 ? 60 : 48, le);
        var minPhEnt = cls == 2 ? 56 : 32;
        var minShEnt = cls == 2 ? 64 : 40;

        // Match ClamAV's executable sanity limits: reject pathological program
        // and section tables before allocating/iterating them.
        if (phnum > 128 || shnum > 256) return null;
        if (phnum != 0 && (phentsize != minPhEnt || !FitsTable(phoff, phentsize, phnum, data.Length))) return null;
        if (shnum != 0 && (shentsize != minShEnt || !FitsTable(shoff, shentsize, shnum, data.Length))) return null;

        var sections = new List<LdbSection>(shnum);
        for (var i = 0; i < shnum; i++)
        {
            var o = checked((long)shoff + (long)i * shentsize);
            var addrOffset = cls == 2 ? 16 : 12;
            var rawOffset = cls == 2 ? 24 : 16;
            var sizeOffset = cls == 2 ? 32 : 20;
            var address = U64(data, checked((int)(o + addrOffset)), le, cls == 2);
            var raw = U64(data, checked((int)(o + rawOffset)), le, cls == 2);
            var size = U64(data, checked((int)(o + sizeOffset)), le, cls == 2);
            if (raw > (ulong)data.Length)
                continue;
            // Preserve the declared section start, but clamp file-backed bytes
            // to the actual mapping so later scanners can never read past EOF.
            var rawSize = Math.Min(size, (ulong)data.Length - raw);
            sections.Add(new LdbSection((long)raw, (long)rawSize, (long)address, (long)size));
        }

        long rawEp = -1;
        for (var i = 0; i < phnum; i++)
        {
            var o = checked((long)phoff + (long)i * phentsize);
            var type = ReadU32Endian(data, checked((int)o), le);
            if (type != 1) continue;
            var po = cls == 2 ? 8 : 4;
            var pv = cls == 2 ? 16 : 8;
            var filesz = cls == 2 ? 32 : 16;
            var pOffset = U64(data, checked((int)o + po), le, cls == 2);
            var pVaddr = U64(data, checked((int)o + pv), le, cls == 2);
            var pFilesz = U64(data, checked((int)o + filesz), le, cls == 2);
            if (pOffset > (ulong)data.Length || pFilesz > (ulong)data.Length - pOffset) continue;
            if (entry >= pVaddr && entry - pVaddr < pFilesz)
            {
                var raw = pOffset + (entry - pVaddr);
                if (raw <= int.MaxValue) rawEp = (long)raw;
                break;
            }
        }
        return new LdbExecutableInfo { EntryPoint = Math.Max(0, rawEp), NumberOfSections = sections.Count, Sections = sections };
    }

    private static bool FitsTable(ulong offset, ushort entrySize, ushort count, int length)
    {
        if (offset > (ulong)length) return false;
        return (ulong)entrySize * count <= (ulong)length - offset;
    }

    private static bool TryGetMachORawSize(ulong virtualSize, uint alignExponent, uint sectionFlags, out long rawSize)
    {
        rawSize = 0;
        if (alignExponent > 31 || virtualSize > uint.MaxValue)
            return false;

        // Mach-O section type is stored in the low byte of flags.
        var sectionType = sectionFlags & 0xFFu;
        if (sectionType is 0x1u or 0x12u or 0x13u) // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
            return true;

        var alignment = 1UL << (int)alignExponent;
        var remainder = virtualSize % alignment;
        var rounded = virtualSize + ((alignment - remainder) % alignment);
        if (rounded > uint.MaxValue)
            return false;

        rawSize = (long)rounded;
        return true;
    }

    private static LdbExecutableInfo? TryMachO(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        var magic = ReadU32(data, 0);
        if (magic is 0xbebafeca or 0xcafebabe or 0xbfbafeca or 0xcafebabf)
        {
            var bigEndian = magic is 0xbebafeca or 0xbfbafeca;
            var fatIs64 = magic is 0xcafebabf or 0xbfbafeca;
            return TryMachOFat(data, bigEndian, fatIs64);
        }
        if (data.Length < 32) return null;
        var little64 = magic == 0xfeedfacf; var little32 = magic == 0xfeedface;
        var big64 = magic == 0xcffaedfe; var big32 = magic == 0xcefaedfe;
        if (!(little64 || little32 || big64 || big32)) return null;
        var is64 = little64 || big64; var le = little64 || little32;
        var ncmds = ReadU32Endian(data, 16, le);
        if (ncmds == 0 || ncmds > 1024) return null;
        var cmdOff = 32;
        long entryRaw = -1;
        ulong entryVirtual = 0;
        var entryIsVirtual = false;
        var sections = new List<LdbSection>();
        for (var i = 0; i < ncmds; i++)
        {
            if (cmdOff < 0 || cmdOff > data.Length - 8) return null;
            var cmd = ReadU32Endian(data, cmdOff, le);
            var sz = ReadU32Endian(data, cmdOff + 4, le);
            if (sz < 8 || sz > int.MaxValue || cmdOff > data.Length - (int)sz) return null;

            // LC_MAIN stores a file offset directly.
            if (cmd == 0x80000028u && sz >= 24 && cmdOff + 16 <= data.Length)
            {
                var candidate = ReadU64Endian(data, cmdOff + 8, le);
                if (candidate <= (ulong)data.Length)
                    entryRaw = (long)candidate;
                entryIsVirtual = false;
            }

            // Older 32-bit Mach-O images can expose the initial PC through
            // LC_UNIXTHREAD rather than LC_MAIN. The PC is a VM address, so it
            // is converted to a raw file offset after section parsing.
            if (cmd == 0x5u && sz >= 16)
            {
                var flavor = ReadU32Endian(data, cmdOff + 8, le);
                if (is64 && flavor == 4u && sz >= 144 + 8)
                {
                    entryVirtual = ReadU64Endian(data, cmdOff + 16 + 16 * 8, le);
                    entryIsVirtual = true;
                }
                else if (!is64 && flavor == 1u && sz >= 56 + 4)
                {
                    entryVirtual = ReadU32Endian(data, cmdOff + 16 + 10 * 4, le);
                    entryIsVirtual = true;
                }
                else if (is64 && flavor == 6u && sz >= 272 + 8)
                {
                    // ARM64 thread state: pc follows x[29], fp, lr and sp.
                    entryVirtual = ReadU64Endian(data, cmdOff + 16 + 32 * 8, le);
                    entryIsVirtual = true;
                }
            }

            if (cmd == (is64 ? 0x19u : 0x1u))
            {
                var minLoad = is64 ? 72 : 56;
                if (sz < (uint)minLoad) return null;
                var nsects = ReadU32Endian(data, cmdOff + (is64 ? 64 : 48), le);
                if (nsects > 255) return null;
                var so = cmdOff + (is64 ? 72 : 56);
                var sectSize = is64 ? 80 : 68;
                var sectionBytes = checked((long)nsects * sectSize);
                if (so < 0 || sectionBytes > data.Length - so) return null;

                for (var si = 0; si < nsects; si++, so += sectSize)
                {
                    long va;
                    long raw;
                    long rawSize;
                    uint alignExponent;
                    uint sectionFlags;
                    ulong virtualSizeU;
                    if (is64)
                    {
                        var sectionVa = ReadU64Endian(data, so + 32, le);
                        virtualSizeU = ReadU64Endian(data, so + 40, le);
                        var sectionRaw = ReadU32Endian(data, so + 48, le);
                        alignExponent = ReadU32Endian(data, so + 64, le);
                        sectionFlags = ReadU32Endian(data, so + 68, le);
                        if (sectionVa > long.MaxValue || virtualSizeU > long.MaxValue) return null;
                        va = (long)sectionVa;
                        raw = sectionRaw;
                    }
                    else
                    {
                        va = ReadU32Endian(data, so + 24, le);
                        virtualSizeU = ReadU32Endian(data, so + 36, le);
                        raw = ReadU32Endian(data, so + 40, le);
                        alignExponent = ReadU32Endian(data, so + 48, le);
                        sectionFlags = ReadU32Endian(data, so + 56, le);
                    }

                    if (!TryGetMachORawSize(virtualSizeU, alignExponent, sectionFlags, out rawSize))
                        return null;
                    if (raw > data.Length)
                        continue;
                    rawSize = Math.Min(rawSize, data.Length - raw);
                    sections.Add(new LdbSection(raw, rawSize, va, (long)Math.Min(virtualSizeU, long.MaxValue)));
                }
            }

            cmdOff += checked((int)sz);
        }

        if (entryIsVirtual && entryVirtual <= long.MaxValue)
        {
            var mapped = MapMachOVirtualToRaw(entryVirtual, sections);
            if (mapped >= 0) entryRaw = mapped;
        }

        return new LdbExecutableInfo { EntryPoint = Math.Max(0, entryRaw), NumberOfSections = sections.Count, Sections = sections };
    }

    private static LdbExecutableInfo? TryMachOFat(ReadOnlySpan<byte> data, bool bigEndianHeader, bool is64)
    {
        if (data.Length < 8) return null;
        var count = bigEndianHeader
            ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(4, 4))
            : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        if (count == 0 || count > 64) return null;
        var archSize = is64 ? 32 : 20;
        var tableEnd = checked(8L + (long)count * archSize);
        if (tableEnd > data.Length) return null;

        for (var i = 0; i < count; i++)
        {
            var o = 8 + i * archSize;
            ulong sliceOffset = is64
                ? (bigEndianHeader ? BinaryPrimitives.ReadUInt64BigEndian(data.Slice(o + 8, 8)) : BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(o + 8, 8)))
                : (bigEndianHeader ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(o + 8, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o + 8, 4)));
            ulong sliceSize = is64
                ? (bigEndianHeader ? BinaryPrimitives.ReadUInt64BigEndian(data.Slice(o + 16, 8)) : BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(o + 16, 8)))
                : (bigEndianHeader ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(o + 12, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o + 12, 4)));
            if (sliceSize == 0 || sliceOffset > (ulong)data.Length || sliceSize > (ulong)data.Length - sliceOffset || sliceOffset > int.MaxValue || sliceSize > int.MaxValue) continue;
            var slice = data.Slice((int)sliceOffset, (int)sliceSize);
            var info = TryMachO(slice);
            if (info is not null)
            {
                var baseOffset = checked((long)sliceOffset);
                return new LdbExecutableInfo
                {
                    EntryPoint = checked(info.EntryPoint + baseOffset),
                    NumberOfSections = info.NumberOfSections,
                    Sections = info.Sections
                        .Select(s => new LdbSection(checked(s.RawOffset + baseOffset), s.RawSize, s.VirtualAddress, s.VirtualSize))
                        .ToArray(),
                    VersionInfoRegions = info.VersionInfoRegions
                        .Select(r => (checked(r.Start + (int)baseOffset), checked(r.End + (int)baseOffset)))
                        .ToArray(),
                    IconGroups = info.IconGroups
                };
            }
        }
        return null;
    }

    internal static IReadOnlyList<(int Offset, int Length)> GetMachOFatSlices(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8) return [];

        var magic = ReadU32(data, 0);
        var bigEndianHeader = magic is 0xbebafeca or 0xbfbafeca;
        var is64 = magic is 0xbfbafeca or 0xcafebabf;
        if (magic is not (0xbebafeca or 0xcafebabe or 0xbfbafeca or 0xcafebabf))
            return [];

        var count = bigEndianHeader
            ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(4, 4))
            : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        if (count == 0 || count > 64) return [];

        var archSize = is64 ? 32 : 20;
        var tableEnd = 8L + (long)count * archSize;
        if (tableEnd > data.Length) return [];

        var slices = new List<(int Offset, int Length)>();
        for (var i = 0; i < count; i++)
        {
            var o = 8 + i * archSize;
            ulong offset = is64
                ? (bigEndianHeader ? BinaryPrimitives.ReadUInt64BigEndian(data.Slice(o + 8, 8)) : BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(o + 8, 8)))
                : (bigEndianHeader ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(o + 8, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o + 8, 4)));
            ulong length = is64
                ? (bigEndianHeader ? BinaryPrimitives.ReadUInt64BigEndian(data.Slice(o + 16, 8)) : BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(o + 16, 8)))
                : (bigEndianHeader ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(o + 12, 4)) : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o + 12, 4)));

            if (offset > int.MaxValue || length > int.MaxValue || length == 0 ||
                offset > (ulong)data.Length || length > (ulong)data.Length - offset)
                continue;

            var slice = data.Slice((int)offset, (int)length);
            if (TryMachO(slice) is not null)
                slices.Add(((int)offset, (int)length));
        }
        return slices;
    }

    internal static long RvaToRaw(uint rva, IReadOnlyList<LdbSection> sections, int fileLength, int headerSize)
    {
        if (rva < (uint)Math.Max(0, headerSize) && rva < (uint)Math.Max(0, fileLength)) return rva;
        foreach (var s in sections)
        {
            var sectionStart = Math.Max(0L, s.VirtualAddress);
            var rawSize = Math.Max(0L, s.RawSize);
            if (rva < (ulong)sectionStart || (ulong)rva - (ulong)sectionStart >= (ulong)rawSize)
                continue;
            var delta = (long)rva - sectionStart;
            var raw = s.RawOffset + delta;
            return raw >= 0 && raw < fileLength ? raw : -1;
        }
        return -1;
    }

    private static long MapMachOVirtualToRaw(ulong address, IReadOnlyList<LdbSection> sections)
    {
        foreach (var section in sections)
        {
            if (section.VirtualAddress < 0 || section.VirtualSize < 0 || section.RawOffset < 0 || section.RawSize < 0)
                continue;
            var start = (ulong)section.VirtualAddress;
            var size = (ulong)section.VirtualSize;
            if (address < start || address - start >= size) continue;
            var delta = address - start;
            if (delta >= (ulong)section.RawSize) continue;
            var raw = (ulong)section.RawOffset + delta;
            return raw <= int.MaxValue ? (long)raw : -1;
        }
        return -1;
    }

    private static int ReadI32(ReadOnlySpan<byte> d, int o) => BinaryPrimitives.ReadInt32LittleEndian(d.Slice(o, 4));
    private static uint ReadU32(ReadOnlySpan<byte> d, int o) => BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(o, 4));
    private static ushort ReadU16(ReadOnlySpan<byte> d, int o) => BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(o, 2));
    private static ulong U64(ReadOnlySpan<byte> d, int o, bool le, bool is64) => is64 ? ReadU64Endian(d, o, le) : ReadU32Endian(d, o, le);
    private static ushort ReadU16Endian(ReadOnlySpan<byte> d, int o, bool le) => le ? BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(o, 2)) : BinaryPrimitives.ReadUInt16BigEndian(d.Slice(o, 2));
    private static uint ReadU32Endian(ReadOnlySpan<byte> d, int o, bool le) => le ? BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(o, 4)) : BinaryPrimitives.ReadUInt32BigEndian(d.Slice(o, 4));
    private static ulong ReadU64Endian(ReadOnlySpan<byte> d, int o, bool le) => le ? BinaryPrimitives.ReadUInt64LittleEndian(d.Slice(o, 8)) : BinaryPrimitives.ReadUInt64BigEndian(d.Slice(o, 8));
}

internal static class ResourceParser
{
    public static void Parse(ReadOnlySpan<byte> data, long baseOffset, uint resourceSize, IReadOnlyList<LdbSection> sections, List<(int Start, int End)> versionRegions, List<LdbIconGroup> groups)
    {
        if (baseOffset < 0 || baseOffset >= data.Length || resourceSize == 0)
            return;

        var resourceEnd = Math.Min((long)data.Length, baseOffset + (long)resourceSize);
        if (resourceEnd <= baseOffset || resourceEnd > int.MaxValue)
            return;

        var map = new Dictionary<uint, byte[]>(); var groupIds = new List<(string, byte[])>();
        WalkType(data, baseOffset, baseOffset, (int)resourceEnd, 0, [], map, groupIds, versionRegions, sections);
        foreach (var (id, blob) in groupIds)
        {
            if (blob.Length < 6 || BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(2, 2)) != 1) continue;
            var count = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(4, 2)); var icons = new List<byte[]>();
            for (var i = 0; i < count && 6 + i * 14 + 14 <= blob.Length; i++)
            {
                var iconId = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(6 + i * 14 + 12, 2));
                if (map.TryGetValue(iconId, out var icon)) icons.Add(icon);
            }
            groups.Add(new LdbIconGroup(id, icons));
        }
    }

    private static void WalkType(ReadOnlySpan<byte> data, long resBase, long dirOff, int fileLen, int depth, List<uint> path, Dictionary<uint, byte[]> iconMap, List<(string, byte[])> groupIds, List<(int, int)> versionRegions, IReadOnlyList<LdbSection> sections)
    {
        if (depth > 3 || dirOff < 0 || dirOff + 16 > fileLen) return;
        var named = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice((int)dirOff + 12, 2));
        var ids = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice((int)dirOff + 14, 2));
        var entries = named + ids;
        var off = dirOff + 16;
        for (var i = 0; i < entries && off + 8 <= fileLen; i++, off += 8)
        {
            var nameOrId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)off, 4));
            var dataOrDir = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)off + 4, 4));
            var isNamed = (nameOrId & 0x80000000u) != 0;
            var id = nameOrId & 0x7fffffffu;
            if ((dataOrDir & 0x80000000u) != 0)
            {
                WalkType(data, resBase, resBase + (dataOrDir & 0x7fffffffu), fileLen, depth + 1, path.Append(id).ToList(), iconMap, groupIds, versionRegions, sections);
            }
            else
            {
                var e = resBase + dataOrDir; if (e + 16 > fileLen) continue;
                var rva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)e, 4)); var size = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)e + 4, 4));
                var raw = ExecutableInspector.RvaToRaw(rva, sections, fileLen, 0); if (raw < 0 || raw + size > fileLen) continue;
                var bytes = data.Slice((int)raw, checked((int)size)).ToArray();
                if (path.Count >= 2 && path[0] == 3) iconMap[path[1]] = bytes;
                if (path.Count >= 2 && path[0] == 14) groupIds.Add((path[1].ToString(), bytes));
                if (path.Count >= 1 && path[0] == 16 && path.Count >= 3)
                    VersionInfoParser.FindRegions(bytes, (int)raw, versionRegions);
            }
        }
    }
}

internal static class VersionInfoParser
{
    // ClamAV's VI offset set contains the start of each StringFileInfo string
    // block's UTF-16 key (the block header is six bytes). It does not make the
    // whole version-info resource a searchable range.
    public static void FindRegions(ReadOnlySpan<byte> data, int fileBase, List<(int Start, int End)> regions)
    {
        if (data.Length < 6) return;
        var rootLength = ReadU16(data, 0);
        var rootValueLength = ReadU16(data, 2);
        var rootType = ReadU16(data, 4);
        if (rootLength < 6 || rootLength > data.Length || rootType != 0)
            return;

        var keyEnd = ReadUtf16KeyEnd(data, 6, rootLength);
        if (keyEnd < 0 || !ReadUtf16KeyEquals(data, 6, keyEnd, "VS_VERSION_INFO"))
            return;

        var fixedStart = Align4(keyEnd + 2);
        // VS_FIXEDFILEINFO is 52 bytes and carries the fixed signature FE EF 04 BD.
        if (rootValueLength != 0x34 || fixedStart + 0x34 > rootLength)
            return;
        if (ReadU32(data, fixedStart) != 0xFEEF04BD)
            return;

        var child = Align4(fixedStart + 0x34);
        var rootEnd = rootLength;
        while (child + 6 <= rootEnd)
        {
            var length = ReadU16(data, child);
            if (length < 6 || child + length > rootEnd)
                break;
            var childKeyEnd = ReadUtf16KeyEnd(data, child + 6, child + length);
            if (childKeyEnd >= 0 && ReadUtf16KeyEquals(data, child + 6, childKeyEnd, "StringFileInfo"))
            {
                ParseStringFileInfo(data, child, child + length, childKeyEnd, fileBase, regions);
                break;
            }
            child += Align4(length);
        }
    }

    private static void ParseStringFileInfo(ReadOnlySpan<byte> data, int start, int end, int keyEnd, int fileBase, List<(int Start, int End)> regions)
    {
        var child = Align4(keyEnd + 2);
        while (child + 6 <= end)
        {
            var length = ReadU16(data, child);
            if (length <= 24 || child + length > end)
                break;
            var tableKeyEnd = ReadUtf16KeyEnd(data, child + 6, child + length);
            if (tableKeyEnd < 0)
                break;
            ParseStringTable(data, child, child + length, tableKeyEnd, fileBase, regions);
            child += Align4(length);
        }
    }

    private static void ParseStringTable(ReadOnlySpan<byte> data, int start, int end, int keyEnd, int fileBase, List<(int Start, int End)> regions)
    {
        // StringTable header = 6 bytes + 16-byte UTF-16 key + 2-byte padding = 24.
        var child = Align4(keyEnd + 2);
        if (child < start + 24) child = start + 24;
        while (child + 6 <= end)
        {
            var length = ReadU16(data, child);
            if (length <= 6 || child + length > end)
                break;

            var valueLength = ReadU16(data, child + 2);
            var type = ReadU16(data, child + 4);
            var stringKeyEnd = ReadUtf16KeyEnd(data, child + 6, child + length);
            if (stringKeyEnd >= 0)
            {
                // Match exactly what pe.c places into peinfo->vinfo: vptr + 6.
                var valueBytes = type == 1 ? checked(valueLength * 2) : valueLength;
                var valueStart = Align4(stringKeyEnd + 2);
                if (type == 1 && valueBytes > 2 && valueStart + Math.Min(valueBytes, child + length - valueStart) <= child + length)
                    regions.Add((fileBase + child + 6, fileBase + child + 6));
            }
            child += Align4(length);
        }
    }

    private static int ReadUtf16KeyEnd(ReadOnlySpan<byte> data, int start, int limit)
    {
        var p = start;
        while (p + 1 < limit)
        {
            if (data[p] == 0 && data[p + 1] == 0)
                return p;
            p += 2;
        }
        return -1;
    }

    private static bool ReadUtf16KeyEquals(ReadOnlySpan<byte> data, int start, int endExclusive, string expected)
    {
        var chars = (endExclusive - start) / 2;
        if (chars != expected.Length) return false;
        for (var i = 0; i < chars; i++)
            if (data[start + i * 2] != expected[i] || data[start + i * 2 + 1] != 0)
                return false;
        return true;
    }

    private static int Align4(int value) => (value + 3) & ~3;
    private static ushort ReadU16(ReadOnlySpan<byte> d, int o) => BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(o, 2));
    private static uint ReadU32(ReadOnlySpan<byte> d, int o) => BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(o, 4));
}

internal static class IconDecoder
{
    public static bool TryDecode(byte[] bytes, out RgbImage image)
    {
        image = null!;
        if (bytes.Length < 40) return false;

        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
        if (headerSize < 40 || headerSize > bytes.Length) return false;

        var width = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4, 4));
        var encodedHeight = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8, 4));
        var height = encodedHeight / 2;
        var planes = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(12, 2));
        var bpp = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(14, 2));
        var clrUsed = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(32, 4));
        if (width < 16 || height < 16 || width > 256 || height > 256 ||
            planes is not (0 or 1) || bpp is not (1 or 4 or 8 or 16 or 24 or 32))
            return false;

        var paletteCount = bpp <= 8 ? (clrUsed != 0 ? (int)Math.Min(clrUsed, 1u << bpp) : 1 << bpp) : 0;
        var dataOffset = checked((int)headerSize + paletteCount * 4);
        if (dataOffset > bytes.Length) return false;

        var colorStride = checked(((width * bpp + 31) / 32) * 4);
        var colorBytes = checked(colorStride * height);
        if (dataOffset + colorBytes > bytes.Length) return false;

        var andStride = checked(((width + 31) / 32) * 4);
        var maskOffset = dataOffset + colorBytes;
        var hasMask = maskOffset >= 0 && maskOffset + (long)andStride * height <= bytes.Length;
        var pixels = new uint[checked(width * height)];
        var anyExplicitAlpha = false;

        for (var y = 0; y < height; y++)
        {
            var srcRow = y * colorStride;
            var dstY = height - 1 - y;
            for (var x = 0; x < width; x++)
            {
                byte r, g, b, a = 255;
                if (bpp == 24)
                {
                    var p = dataOffset + srcRow + x * 3;
                    b = bytes[p]; g = bytes[p + 1]; r = bytes[p + 2];
                }
                else if (bpp == 32)
                {
                    var p = dataOffset + srcRow + x * 4;
                    b = bytes[p]; g = bytes[p + 1]; r = bytes[p + 2]; a = bytes[p + 3];
                    anyExplicitAlpha |= a != 0;
                }
                else if (bpp == 16)
                {
                    var p = dataOffset + srcRow + x * 2;
                    var v = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(p, 2));
                    // ClamAV treats icon 16-bpp pixels as 5-5-5-style RGB values.
                    b = Expand5((byte)(v & 0x1f));
                    g = Expand5((byte)((v >> 5) & 0x1f));
                    r = Expand5((byte)((v >> 10) & 0x1f));
                }
                else
                {
                    var bitPos = x * bpp;
                    var p = dataOffset + srcRow + bitPos / 8;
                    var shift = 8 - bpp - bitPos % 8;
                    var paletteIndex = (bytes[p] >> shift) & ((1 << bpp) - 1);
                    var palOffset = checked((int)headerSize + paletteIndex * 4);
                    if (palOffset + 4 > bytes.Length) return false;
                    var pal = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(palOffset, 4));
                    b = (byte)pal; g = (byte)(pal >> 8); r = (byte)(pal >> 16);
                }

                pixels[dstY * width + x] = ((uint)a << 24) | ((uint)r << 16) | ((uint)g << 8) | b;
            }
        }

        // 32-bit icons with real alpha use that alpha channel. Otherwise ClamAV
        // uses the XOR/AND icon mask to determine transparency.
        if (bpp != 32 || !anyExplicitAlpha)
        {
            if (!hasMask)
            {
                // Broken 32-bit icons are treated as fully opaque.
                if (bpp != 32) return false;
                for (var i = 0; i < pixels.Length; i++) pixels[i] |= 0xff000000u;
            }
            else
            {
                for (var y = 0; y < height; y++)
                {
                    var srcRow = maskOffset + y * andStride;
                    var dstY = height - 1 - y;
                    for (var x = 0; x < width; x++)
                    {
                        var maskByte = bytes[srcRow + (x >> 3)];
                        var transparent = ((maskByte >> (7 - (x & 7))) & 1) != 0;
                        var index = dstY * width + x;
                        pixels[index] = (pixels[index] & 0x00ffffffu) | (transparent ? 0u : 0xff000000u);
                    }
                }
            }
        }

        var rgb = new byte[checked(width * height * 3)];
        for (var i = 0; i < pixels.Length; i++)
        {
            var c = pixels[i];
            var a = (c >> 24) & 0xffu;
            var r = 0xffu - a + a * ((c >> 16) & 0xffu) / 0xffu;
            var g = 0xffu - a + a * ((c >> 8) & 0xffu) / 0xffu;
            var b = 0xffu - a + a * (c & 0xffu) / 0xffu;
            var q = i * 3;
            rgb[q] = (byte)r; rgb[q + 1] = (byte)g; rgb[q + 2] = (byte)b;
        }

        image = new RgbImage(width, height, rgb);
        return true;
    }

    private static byte Expand5(byte v) => (byte)((v << 3) | (v >> 2));
}

internal static class IconMetrics
{
    private sealed record Metric(
        uint[] ColorAvg, byte[] ColorX, byte[] ColorY,
        uint[] GrayAvg, byte[] GrayX, byte[] GrayY,
        byte[] BrightAvg, byte[] BrightX, byte[] BrightY,
        byte[] DarkAvg, byte[] DarkX, byte[] DarkY,
        byte[] EdgeAvg, byte[] EdgeX, byte[] EdgeY,
        byte[] NoEdgeAvg, byte[] NoEdgeX, byte[] NoEdgeY,
        byte RSum, byte GSum, byte BSum, byte CCount);

    public static bool Matches(RgbImage source, IconMetric reference, bool alreadyPrepared = false)
    {
        var image = alreadyPrepared ? source : PrepareForClam(source);
        if (image.Width != reference.Side || image.Height != reference.Side) return false;
        var m = Compute(image, reference.Side);
        var enginesize = (reference.Side >> 3) - 2;
        if (enginesize < 0 || enginesize > 2) return false;
        var bw = m.CCount == 0 && reference.CCount == 0;
        int edge, noedge, bright, dark, confidence;
        if (bw)
        {
            edge = MatchBw(Concat(m.EdgeAvg, m.ColorAvg), Concat(m.EdgeX, m.ColorX), Concat(m.EdgeY, m.ColorY),
                           Concat(reference.EdgeAvg, reference.ColorAvg), Concat(reference.EdgeX, reference.ColorX), Concat(reference.EdgeY, reference.ColorY), reference.Side);
            noedge = MatchBw(Concat(m.NoEdgeAvg, m.GrayAvg), Concat(m.NoEdgeX, m.GrayX), Concat(m.NoEdgeY, m.GrayY),
                             Concat(reference.NoEdgeAvg, reference.GrayAvg), Concat(reference.NoEdgeX, reference.GrayX), Concat(reference.NoEdgeY, reference.GrayY), reference.Side);
            bright = Match3(m.BrightAvg, m.BrightX, m.BrightY, reference.BrightAvg, reference.BrightX, reference.BrightY, 255, reference.Side);
            dark = Match3(m.DarkAvg, m.DarkX, m.DarkY, reference.DarkAvg, reference.DarkX, reference.DarkY, 255, reference.Side);
            confidence = (bright + dark + edge * 2 + noedge) / 6;
            return confidence >= 70;
        }
        edge = Match3(m.EdgeAvg, m.EdgeX, m.EdgeY, reference.EdgeAvg, reference.EdgeX, reference.EdgeY, 255, reference.Side);
        noedge = Match3(m.NoEdgeAvg, m.NoEdgeX, m.NoEdgeY, reference.NoEdgeAvg, reference.NoEdgeX, reference.NoEdgeY, 255, reference.Side);
        bright = Match3(m.BrightAvg, m.BrightX, m.BrightY, reference.BrightAvg, reference.BrightX, reference.BrightY, 255, reference.Side);
        dark = Match3(m.DarkAvg, m.DarkX, m.DarkY, reference.DarkAvg, reference.DarkX, reference.DarkY, 255, reference.Side);
        var color = m.CCount != 0 && reference.CCount != 0 ? Match3(m.ColorAvg, m.ColorX, m.ColorY, reference.ColorAvg, reference.ColorX, reference.ColorY, 4072, reference.Side) : 0;
        var gray = m.CCount != 0 && reference.CCount != 0 ? Match3(m.GrayAvg, m.GrayX, m.GrayY, reference.GrayAvg, reference.GrayX, reference.GrayY, 4072, reference.Side) : 0;
        var colors = (Spread(m.RSum, reference.RSum) + Spread(m.GSum, reference.GSum) + Spread(m.BSum, reference.BSum) + Spread(m.CCount, reference.CCount)) / 4;
        confidence = (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6;
        return confidence >= 64 + 4 * (2 - enginesize);
    }

    private static Metric Compute(RgbImage image, int side)
    {
        var ks = side / 4;
        var colorAvg = new uint[3]; var colorX = new byte[3]; var colorY = new byte[3];
        var grayAvg = Enumerable.Repeat(uint.MaxValue, 3).ToArray(); var grayX = new byte[3]; var grayY = new byte[3];
        var brightAvg = new uint[3]; var brightX = new byte[3]; var brightY = new byte[3];
        var darkAvg = Enumerable.Repeat(uint.MaxValue, 3).ToArray(); var darkX = new byte[3]; var darkY = new byte[3];
        var col = new uint[side, side]; var light = new uint[side, side];
        var ss = new byte[side * side]; var vv = new byte[side * side];
        uint ccount = 0, rsum = 0, gsum = 0, bsum = 0;
        for (var y = 0; y < side; y++) for (var x = 0; x < side; x++)
        {
            var q = image.Index(x, y); var r = image.Pixels[q]; var g = image.Pixels[q + 1]; var b = image.Pixels[q + 2];
            var max = Math.Max(r, Math.Max(g, b)); var min = Math.Min(r, Math.Min(g, b)); var delta = max - min; var sat = delta == 0 ? 0 : 255 * delta / max;
            ss[y * side + x] = (byte)sat; vv[y * side + x] = max;
        }
        for (var y = 0; y <= side - ks; y++) for (var x = 0; x <= side - ks; x++)
        {
            uint csum = 0, lsum = 0;
            for (var yy = 0; yy < ks; yy++) for (var xx = 0; xx < ks; xx++) { var s = ss[(y + yy) * side + x + xx]; var v = vv[(y + yy) * side + x + xx]; csum += (uint)Math.Sqrt(s * s * v); lsum += v; }
            col[y, x] = csum; light[y, x] = lsum;
        }
        for (var y = 0; y < side; y++) for (var x = 0; x < side; x++)
            if (ss[y * side + x] > 85 && vv[y * side + x] > 85)
            {
                ccount++; var q = image.Index(x, y); var r = image.Pixels[q]; var g = image.Pixels[q + 1]; var b = image.Pixels[q + 2]; var delta = Math.Max(r, Math.Max(g, b)) - Math.Min(r, Math.Min(g, b)); if (delta > 0) { rsum += (uint)(100 - 100 * Math.Abs(g - b) / delta); gsum += (uint)(100 - 100 * Math.Abs(r - b) / delta); bsum += (uint)(100 - 100 * Math.Abs(r - g) / delta); }
            }
        Select(col, side, ks, true, colorAvg, colorX, colorY); Select(col, side, ks, false, grayAvg, grayX, grayY); Select(light, side, ks, true, brightAvg, brightX, brightY); Select(light, side, ks, false, darkAvg, darkX, darkY);
        for (var i = 0; i < 3; i++) { colorAvg[i] /= (uint)(ks * ks); grayAvg[i] = grayAvg[i] == uint.MaxValue ? 0 : grayAvg[i] / (uint)(ks * ks); brightAvg[i] /= (uint)(ks * ks); darkAvg[i] = darkAvg[i] == uint.MaxValue ? 0 : darkAvg[i] / (uint)(ks * ks); }
        var cpercent = (int)(ccount * 100 / (uint)(side * side)); byte rs, gs, bs, cp; if (cpercent <= 5) rs=gs=bs=cp=0; else { rs=(byte)Math.Min(255,rsum/(int)ccount); gs=(byte)Math.Min(255,gsum/(int)ccount); bs=(byte)Math.Min(255,bsum/(int)ccount); cp=(byte)Math.Min(100,cpercent); }
        var lab = new double[side, side]; for (var y=0;y<side;y++)for(var x=0;x<side;x++){var q=image.Index(x,y);lab[y,x]=LabDiff(image.Pixels[q],image.Pixels[q+1],image.Pixels[q+2]);}
        var sobel=new double[side,side]; double peak=0; for(var y=1;y<side-1;y++)for(var x=1;x<side-1;x++){var gx=lab[y-1,x-1]+2*lab[y,x-1]+lab[y+1,x-1]-lab[y-1,x+1]-2*lab[y,x+1]-lab[y+1,x+1];var gy=lab[y-1,x-1]+2*lab[y-1,x]+lab[y-1,x+1]-lab[y+1,x-1]-2*lab[y+1,x]-lab[y+1,x+1];sobel[y,x]=Math.Sqrt(gx*gx+gy*gy);peak=Math.Max(peak,sobel[y,x]);}
        if(peak>0)for(var y=1;y<side-1;y++)for(var x=1;x<side-1;x++)sobel[y,x]=sobel[y,x]*255/peak;
        for(var x=0;x<side;x++)sobel[0,x]=sobel[side-1,x]=0; for(var y=0;y<side;y++)sobel[y,0]=sobel[y,side-1]=0;
        var tmp=new double[side,side]; for(var y=1;y<side-1;y++)for(var x=1;x<side-1;x++){var sum=0d;var tot=0;for(var dx=-1;dx<=1;dx++){var c=sobel[y,x+dx];var w=dx==0?2:1;sum+=c*w;tot+=w;}tmp[y,x]=sum/tot;} for(var y=1;y<side-1;y++)for(var x=1;x<side-1;x++){var sum=0d;var tot=0;for(var dy=-1;dy<=1;dy++){var w=dy==0?2:1;sum+=tmp[y+dy,x]*w;tot+=w;}sobel[y,x]=sum/tot;}
        var edgeRaw=new uint[side,side]; for(var y=0;y<=side-ks;y++)for(var x=0;x<=side-ks;x++){uint sum=0;for(var yy=0;yy<ks;yy++)for(var xx=0;xx<ks;xx++)sum+=(uint)Math.Clamp((int)Math.Round(sobel[y+yy,x+xx]),0,255);edgeRaw[y,x]=sum;}
        var bwOnly=cp==0; var edgeA=new byte[6];var edgeX=new byte[6];var edgeY=new byte[6];var noA=new byte[6];var noX=new byte[6];var noY=new byte[6]; SelectEdge(edgeRaw,side,ks,true,edgeA,edgeX,edgeY); SelectEdge(edgeRaw,side,ks,false,noA,noX,noY);
        var eAvg=edgeA[..3];var eX=edgeX[..3];var eY=edgeY[..3];var nAvg=noA[..3];var nX=noX[..3];var nY=noY[..3]; if(bwOnly){var e2=edgeA[3..];var x2=edgeX[3..];var y2=edgeY[3..];var n2=noA[3..];colorAvg=e2.Select(v=>(uint)v*1u).ToArray();colorX=x2;colorY=y2;grayAvg=n2.Select(v=>(uint)v*1u).ToArray();grayX=noX[3..];grayY=noY[3..];}
        return new Metric(colorAvg.Select(v=>Math.Min(v,4072)).ToArray(),colorX,colorY,grayAvg.Select(v=>Math.Min(v,4072)).ToArray(),grayX,grayY,brightAvg.Select(v=>(byte)Math.Min(v,255)).ToArray(),brightX,brightY,darkAvg.Select(v=>(byte)Math.Min(v,255)).ToArray(),darkX,darkY,eAvg,eX,eY,nAvg,nX,nY,rs,gs,bs,cp);
    }

    private static void Select(uint[,] map,int side,int ks,bool high,uint[] avg,byte[] xs,byte[] ys){for(var i=0;i<3;i++){var found=false;uint best=high?0:uint.MaxValue;int bx=0,by=0;for(var y=0;y<side-ks;y++)for(var x=0;x<side-1-ks;x++){var z=map[y,x];if(high?z<=best:z>=best)continue;var overlap=false;for(var j=0;j<i;j++)if(x+ks>xs[j]&&x<xs[j]+ks&&y+ks>ys[j]&&y<ys[j]+ks){overlap=true;break;}if(!overlap){best=z;bx=x;by=y;found=true;}}if(!found)break;avg[i]=best;xs[i]=(byte)bx;ys[i]=(byte)by;}}
    private static void SelectEdge(uint[,] map,int side,int ks,bool high,byte[] avg,byte[] xs,byte[] ys){for(var i=0;i<6;i++){var found=false;uint best=high?0:uint.MaxValue;int bx=0,by=0;for(var y=0;y<side-ks;y++)for(var x=0;x<side-1-ks;x++){var z=map[y,x];if(high?z<=best:z>=best)continue;var overlap=false;for(var j=0;j<i;j++)if(x+ks>xs[j]&&x<xs[j]+ks&&y+ks>ys[j]&&y<ys[j]+ks){overlap=true;break;}if(!overlap){best=z;bx=x;by=y;found=true;}}if(!found)break;avg[i]=(byte)Math.Min(255,best/(uint)(ks*ks));xs[i]=(byte)bx;ys[i]=(byte)by;}}
    private static int Match3(byte[] a1,byte[] x1,byte[] y1,byte[] a2,byte[] x2,byte[] y2,int max,int side)=>Match3u(a1.Select(v=>(uint)v).ToArray(),x1,y1,a2.Select(v=>(uint)v).ToArray(),x2,y2,max,side);
    private static int Match3(uint[] a1,byte[] x1,byte[] y1,uint[] a2,byte[] x2,byte[] y2,int max,int side)=>Match3u(a1,x1,y1,a2,x2,y2,max,side);
    private static int Match3u(uint[] a1,byte[] x1,byte[] y1,uint[] a2,byte[] x2,byte[] y2,int max,int side){var ks=side/4;var total=0;for(var i=0;i<3;i++){var best=0;for(var j=0;j<3;j++){var dx=x1[i]-x2[j];var dy=y1[i]-y2[j];var d=Math.Sqrt(dx*dx+dy*dy);if(d<=ks*.75&&Math.Abs((long)a1[i]-a2[j])<=max/5)best=Math.Max(best,100-(int)(d*60/(ks*.75)));}total+=best;}return total/3;}
    private static int MatchBw(uint[] a1, byte[] x1, byte[] y1, uint[] a2, byte[] x2, byte[] y2, int side)
    {
        var ks = side / 4;
        var total = 0;
        for (var i = 0; i < 6; i++)
        {
            var best = 0;
            for (var j = 0; j < 6; j++)
            {
                var dx = x1[i] - x2[j];
                var dy = y1[i] - y2[j];
                var d = Math.Sqrt(dx * dx + dy * dy);
                if (d <= ks * .75 && Math.Abs((long)a1[i] - a2[j]) <= 51)
                    best = Math.Max(best, 100 - (int)(d * 60 / (ks * .75)));
            }
            total += best;
        }
        return total / 6;
    }

    private static uint[] Concat(uint[] a, uint[] b) => a.Concat(b).ToArray();
    private static uint[] Concat(byte[] a, uint[] b) => a.Select(static v => (uint)v).Concat(b).ToArray();
    private static byte[] Concat(byte[] a, byte[] b) => a.Concat(b).ToArray();
    private static int Spread(byte a,byte b){var d=Math.Abs(a-b)*10;return d<100?100-d:0;}

    // Port of pe_icons.c scaling logic. The default path is scalemode=2:
    // pick the nearest of 32/24/16 using Manhattan distance, then sample using
    // floor(y*scaley) and floor(x*scalex + 0.5). Exact 16/24/32 images are kept.
    // Multiples of 24/32 use ClamAV's fast 50% linear-gamma reducer.
    public static RgbImage PrepareForClam(RgbImage source)
    {
        var width = source.Width;
        var height = source.Height;
        if (width < 16 || height < 16 || width > 256 || height > 256) return source;
        if (width < height * 3 / 4 || height < width * 3 / 4) return source;

        var scalemode = 2;
        if (width == height)
        {
            if (width is 16 or 24 or 32) scalemode = 0;
            else if (width % 32 == 0 || width % 24 == 0) scalemode = 1;
        }
        if (scalemode == 0) return source;

        var image = source;
        if (scalemode == 1)
        {
            var w = image.Width;
            var h = image.Height;
            while (w > 32)
            {
                if (w < 2 || h < 2) break;
                var nw = w / 2;
                var nh = h / 2;
                var pixels = new byte[nw * nh * 3];
                for (var y = 0; y < nh; y++)
                for (var x = 0; x < nw; x++)
                {
                    var p00 = image.Index(x * 2, y * 2);
                    var p01 = image.Index(x * 2 + 1, y * 2);
                    var p10 = image.Index(x * 2, y * 2 + 1);
                    var p11 = image.Index(x * 2 + 1, y * 2 + 1);
                    var q = (y * nw + x) * 3;
                    pixels[q]     = Average4(image.Pixels[p00], image.Pixels[p01], image.Pixels[p10], image.Pixels[p11]);
                    pixels[q + 1] = Average4(image.Pixels[p00 + 1], image.Pixels[p01 + 1], image.Pixels[p10 + 1], image.Pixels[p11 + 1]);
                    pixels[q + 2] = Average4(image.Pixels[p00 + 2], image.Pixels[p01 + 2], image.Pixels[p10 + 2], image.Pixels[p11 + 2]);
                }
                image = new RgbImage(nw, nh, pixels);
                w = nw;
                h = nh;
            }
            return image;
        }

        var d32 = Math.Abs(width - 32) + Math.Abs(height - 32);
        var d24 = Math.Abs(width - 24) + Math.Abs(height - 24);
        var newSize = d32 < d24 ? 32 : d24 < (Math.Abs(width - 16) + Math.Abs(height - 16)) ? 24 : 16;
        var scalex = (double)width / newSize;
        var scaley = (double)height / newSize;
        var output = new byte[newSize * newSize * 3];
        for (var y = 0; y < newSize; y++)
        {
            var oldy = (int)(y * scaley);
            for (var x = 0; x < newSize; x++)
            {
                var oldx = Math.Min(width - 1, (int)(x * scalex + 0.5f));
                var src = image.Index(oldx, Math.Min(height - 1, oldy));
                var dst = (y * newSize + x) * 3;
                output[dst] = image.Pixels[src];
                output[dst + 1] = image.Pixels[src + 1];
                output[dst + 2] = image.Pixels[src + 2];
            }
        }
        return new RgbImage(newSize, newSize, output);
    }

    private static byte Average4(byte a, byte b, byte c, byte d)
    {
        var ab = ((a & b) + (((a ^ b) & 0xfe) >> 1));
        var cd = ((c & d) + (((c ^ d) & 0xfe) >> 1));
        return (byte)((ab & cd) + (((ab ^ cd) & 0xfe) >> 1));
    }
    private static double LabDiff(byte r0,byte g0,byte b0){double r=r0/255.0,g=g0/255.0,b=b0/255.0;r=r>.04045?Math.Pow((r+.055)/1.055,2.4):r/12.92;g=g>.04045?Math.Pow((g+.055)/1.055,2.4):g/12.92;b=b>.04045?Math.Pow((b+.055)/1.055,2.4):b/12.92;var x=(.4124*r+.3576*g+.1805*b)*100/95.047;var y=.2126*r+.7152*g+.0722*b;var z=(.0193*r+.1192*g+.9505*b)*100/108.883;x=x>.008856?Math.Pow(x,1/3.0):7.787*x+16/116;y=y>.008856?Math.Pow(y,1/3.0):7.787*y+16/116;z=z>.008856?Math.Pow(z,1/3.0):7.787*z+16/116;var l=116*y-16;var a=500*(x-y);var bb=200*(y-z);var dl=l-53.192777691077211;var da=a-.0031420942181448197;var db=bb+.0062075877844014471;return Math.Sqrt(dl*dl+da*da+db*db);}
}

internal static class ImageDecoder
{
    public static bool TryDecode(ReadOnlySpan<byte> data, out RgbImage image)
    {
        image = null!;
        if (TryDecodeWpf(data, out image)) return true;
        return PngFallback.TryDecode(data, out image) ||
               GifFallback.TryDecode(data, out image) ||
               BmpFallback.TryDecode(data, out image);
    }

    private static bool TryDecodeWpf(ReadOnlySpan<byte> data, out RgbImage image)
    {
        image = null!;
        try
        {
            var bitmapImageType = Type.GetType("System.Windows.Media.Imaging.BitmapImage, PresentationCore", false);
            var formatType = Type.GetType("System.Windows.Media.Imaging.FormatConvertedBitmap, PresentationCore", false);
            var pixelFormatsType = Type.GetType("System.Windows.Media.PixelFormats, PresentationCore", false);
            var rectType = Type.GetType("System.Windows.Int32Rect, WindowsBase", false);
            if (bitmapImageType is null || formatType is null || pixelFormatsType is null || rectType is null) return false;

            using var ms = new MemoryStream(data.ToArray(), writable: false);
            var bitmap = Activator.CreateInstance(bitmapImageType)!;
            bitmapImageType.GetMethod("BeginInit")!.Invoke(bitmap, null);
            bitmapImageType.GetProperty("StreamSource")!.SetValue(bitmap, ms);
            var cacheType = Type.GetType("System.Windows.Media.Imaging.BitmapCacheOption, PresentationCore", false)!;
            bitmapImageType.GetProperty("CacheOption")!.SetValue(bitmap, Enum.Parse(cacheType, "OnLoad"));
            bitmapImageType.GetMethod("EndInit")!.Invoke(bitmap, null);

            var converted = Activator.CreateInstance(formatType)!;
            formatType.GetMethod("BeginInit")!.Invoke(converted, null);
            formatType.GetProperty("Source")!.SetValue(converted, bitmap);
            var bgra = pixelFormatsType.GetProperty("Bgra32", BindingFlags.Public | BindingFlags.Static)!.GetValue(null);
            formatType.GetProperty("DestinationFormat")!.SetValue(converted, bgra);
            formatType.GetMethod("EndInit")!.Invoke(converted, null);

            var sourceType = Type.GetType("System.Windows.Media.Imaging.BitmapSource, PresentationCore", false)!;
            var w = (int)sourceType.GetProperty("PixelWidth")!.GetValue(converted)!;
            var h = (int)sourceType.GetProperty("PixelHeight")!.GetValue(converted)!;
            var raw = new byte[w * h * 4];
            var copy = sourceType.GetMethod("CopyPixels", new[] { rectType, typeof(Array), typeof(int), typeof(int) });
            if (copy is null) return false;
            var rect = Activator.CreateInstance(rectType, new object?[] { 0, 0, w, h });
            copy.Invoke(converted, new object?[] { rect, raw, w * 4, 0 });
            var rgb = new byte[w * h * 3];
            for (var i = 0; i < w * h; i++) { rgb[i*3] = raw[i*4+2]; rgb[i*3+1] = raw[i*4+1]; rgb[i*3+2] = raw[i*4]; }
            image = new RgbImage(w, h, rgb);
            return true;
        }
        catch { return false; }
    }

}

internal static class PngFallback
{
    public static bool TryDecode(ReadOnlySpan<byte> d, out RgbImage image)
    {
        image = null!; if (d.Length < 33 || !d[..8].SequenceEqual(new byte[]{137,80,78,71,13,10,26,10})) return false;
        var chunks = new List<byte[]>(); var palette = Array.Empty<byte>(); var trns = Array.Empty<byte>(); var pos=8; int w=0,h=0,bit=0,ct=0;
        using var all = new MemoryStream();
        while (pos+12<=d.Length) { var len=(int)BinaryPrimitives.ReadUInt32BigEndian(d.Slice(pos,4)); var type=Encoding.ASCII.GetString(d.Slice(pos+4,4)); if (pos+12+len>d.Length) return false; var body=d.Slice(pos+8,len); if(type=="IHDR"){w=(int)BinaryPrimitives.ReadUInt32BigEndian(body[..4]);h=(int)BinaryPrimitives.ReadUInt32BigEndian(body.Slice(4,4));bit=body[8];ct=body[9];if(bit!=8||body[12]!=0)return false;} else if(type=="IDAT") all.Write(body); else if(type=="PLTE") palette=body.ToArray(); else if(type=="tRNS") trns=body.ToArray(); else if(type=="IEND") break; pos+=12+len; }
        if(w<1||h<1||all.Length==0)return false; using var z=new MemoryStream(all.ToArray()); using var def=new ZLibStream(z,CompressionMode.Decompress); using var rawMs=new MemoryStream(); def.CopyTo(rawMs); var raw=rawMs.ToArray(); var bpp=ct switch{0=>1,2=>3,3=>1,4=>2,6=>4,_=>0}; if(bpp==0||raw.Length<(w*bpp+1)*h)return false; var scan=w*bpp; var prev=new byte[scan]; var cur=new byte[scan]; var rgb=new byte[w*h*3]; var rp=0; for(var y=0;y<h;y++){var f=raw[rp++];Array.Copy(raw,rp,cur,0,scan);rp+=scan;for(var x=0;x<scan;x++){byte a=x>=bpp?cur[x-bpp]:(byte)0;var b=prev[x];byte c=x>=bpp?prev[x-bpp]:(byte)0;cur[x]=f switch{0=>cur[x],1=>(byte)(cur[x]+a),2=>(byte)(cur[x]+b),3=>(byte)(cur[x]+((a+b)/2)),4=>(byte)(cur[x]+Paeth(a,b,c)),_=>cur[x]};} for(var x=0;x<w;x++){var q=(y*w+x)*3;if(ct==2){rgb[q]=cur[x*3];rgb[q+1]=cur[x*3+1];rgb[q+2]=cur[x*3+2];}else if(ct==6){rgb[q]=cur[x*4];rgb[q+1]=cur[x*4+1];rgb[q+2]=cur[x*4+2];}else if(ct==3){var idx=cur[x];var p=idx*3;if(p+2>=palette.Length)return false;rgb[q]=palette[p];rgb[q+1]=palette[p+1];rgb[q+2]=palette[p+2];}else return false;}Array.Copy(cur,prev,scan);} image=new RgbImage(w,h,rgb);return true;
    }
    private static byte Paeth(byte a,byte b,byte c){var p=a+b-c;var pa=Math.Abs(p-a);var pb=Math.Abs(p-b);var pc=Math.Abs(p-c);return pa<=pb&&pa<=pc?a:pb<=pc?b:c;}
}

internal static class BmpFallback
{
    public static bool TryDecode(ReadOnlySpan<byte> d,out RgbImage image){image=null!;if(d.Length<54||d[0]!='B'||d[1]!='M')return false;var off=BinaryPrimitives.ReadInt32LittleEndian(d.Slice(10,4));var w=BinaryPrimitives.ReadInt32LittleEndian(d.Slice(18,4));var h0=BinaryPrimitives.ReadInt32LittleEndian(d.Slice(22,4));var bpp=BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(28,2));var h=Math.Abs(h0);if(w<1||h<1||bpp!=24)return false;var stride=((w*3+3)/4)*4;if(off<0||off+stride*h>d.Length)return false;var rgb=new byte[w*h*3];for(var y=0;y<h;y++){var sy=h0>0?h-1-y:y;for(var x=0;x<w;x++){var p=off+sy*stride+x*3;var q=(y*w+x)*3;rgb[q]=d[p+2];rgb[q+1]=d[p+1];rgb[q+2]=d[p];}}image=new RgbImage(w,h,rgb);return true;}
}

internal static class GifFallback
{
    public static bool TryDecode(ReadOnlySpan<byte> data, out RgbImage image)
    {
        image = null!;
        if (data.Length < 13 ||
            !(data[..6].SequenceEqual("GIF87a"u8) || data[..6].SequenceEqual("GIF89a"u8)))
            return false;

        var width = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(6, 2));
        var height = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2));
        var packed = data[10];
        if (width == 0 || height == 0) return false;

        var pos = 13;
        byte[]? globalPalette = null;
        if ((packed & 0x80) != 0)
        {
            var count = 2 << (packed & 7);
            var bytes = checked(count * 3);
            if (pos + bytes > data.Length) return false;
            globalPalette = data.Slice(pos, bytes).ToArray();
            pos += bytes;
        }

        while (pos < data.Length)
        {
            var marker = data[pos++];
            if (marker == 0x3b) break; // trailer
            if (marker == 0x21)
            {
                if (pos >= data.Length) return false;
                pos++; // extension label
                if (!SkipSubBlocks(data, ref pos)) return false;
                continue;
            }
            if (marker != 0x2c) return false;
            if (pos + 9 > data.Length) return false;

            var left = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos, 2));
            var top = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos + 2, 2));
            var frameWidth = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos + 4, 2));
            var frameHeight = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos + 6, 2));
            var imagePacked = data[pos + 8];
            pos += 9;
            if (frameWidth == 0 || frameHeight == 0 ||
                (long)left + frameWidth > width || (long)top + frameHeight > height)
                return false;

            byte[]? localPalette = null;
            if ((imagePacked & 0x80) != 0)
            {
                var count = 2 << (imagePacked & 7);
                var bytes = checked(count * 3);
                if (pos + bytes > data.Length) return false;
                localPalette = data.Slice(pos, bytes).ToArray();
                pos += bytes;
            }

            if (pos >= data.Length) return false;
            var minCodeSize = data[pos++];
            if (minCodeSize < 2 || minCodeSize > 8) return false;
            if (!ReadSubBlocks(data, ref pos, out var compressed)) return false;
            if (!DecodeLzw(compressed, minCodeSize, checked(frameWidth * frameHeight), out var indices)) return false;

            var palette = localPalette ?? globalPalette;
            if (palette is null) return false;
            var rgb = new byte[checked(width * height * 3)];
            var interlaced = (imagePacked & 0x40) != 0;
            var srcIndex = 0;
            if (interlaced)
            {
                foreach (var (start, step) in new[] { (0, 8), (4, 8), (2, 4), (1, 2) })
                    for (var y = start; y < frameHeight && srcIndex < indices.Length; y += step)
                        for (var x = 0; x < frameWidth && srcIndex < indices.Length; x++)
                            if (!PutPixel(rgb, width, left + x, top + y, indices[srcIndex++], palette)) return false;
            }
            else
            {
                for (var y = 0; y < frameHeight; y++)
                    for (var x = 0; x < frameWidth; x++)
                        if (!PutPixel(rgb, width, left + x, top + y, indices[srcIndex++], palette)) return false;
            }

            image = new RgbImage(width, height, rgb);
            return true; // ClamAV's image path hashes the first decoded frame.
        }
        return false;
    }

    private static bool PutPixel(byte[] rgb, int canvasWidth, int x, int y, byte paletteIndex, byte[] palette)
    {
        var p = paletteIndex * 3;
        if (p + 2 >= palette.Length) return false;
        var q = (y * canvasWidth + x) * 3;
        rgb[q] = palette[p]; rgb[q + 1] = palette[p + 1]; rgb[q + 2] = palette[p + 2];
        return true;
    }

    private static bool ReadSubBlocks(ReadOnlySpan<byte> data, ref int pos, out byte[] content)
    {
        using var ms = new MemoryStream();
        while (true)
        {
            if (pos >= data.Length) { content = []; return false; }
            var size = data[pos++];
            if (size == 0) break;
            if (pos + size > data.Length) { content = []; return false; }
            ms.Write(data.Slice(pos, size));
            pos += size;
        }
        content = ms.ToArray();
        return true;
    }

    private static bool SkipSubBlocks(ReadOnlySpan<byte> data, ref int pos)
    {
        while (true)
        {
            if (pos >= data.Length) return false;
            var size = data[pos++];
            if (size == 0) return true;
            if (pos + size > data.Length) return false;
            pos += size;
        }
    }

    private static bool DecodeLzw(ReadOnlySpan<byte> compressed, int minCodeSize, int expectedLength, out byte[] output)
    {
        output = new byte[expectedLength];
        var clear = 1 << minCodeSize;
        var end = clear + 1;
        var nextCode = clear + 2;
        var codeSize = minCodeSize + 1;
        var prefix = new short[4096];
        var suffix = new byte[4096];
        var stack = new byte[4096];
        for (var i = 0; i < clear; i++) suffix[i] = (byte)i;

        var bitPos = 0;
        var outPos = 0;
        var previous = -1;
        var previousFirst = (byte)0;
        while (outPos < expectedLength)
        {
            if (!ReadCode(compressed, ref bitPos, codeSize, out var code)) return false;
            if (code == clear)
            {
                codeSize = minCodeSize + 1;
                nextCode = clear + 2;
                previous = -1;
                continue;
            }
            if (code == end) break;
            if (code >= 4096) return false;

            var current = code;
            var stackPos = 0;
            if (current == nextCode && previous >= 0)
            {
                stack[stackPos++] = previousFirst;
                current = previous;
            }
            while (current >= clear + 2)
            {
                if (current >= nextCode || stackPos >= stack.Length) return false;
                stack[stackPos++] = suffix[current];
                current = prefix[current];
            }
            if (current < 0 || current >= clear) return false;
            var first = suffix[current];
            if (stackPos >= stack.Length) return false;
            stack[stackPos++] = first;
            if (outPos + stackPos > expectedLength) return false;
            for (var i = stackPos - 1; i >= 0; i--) output[outPos++] = stack[i];

            if (previous >= 0 && nextCode < 4096)
            {
                prefix[nextCode] = (short)previous;
                suffix[nextCode] = first;
                nextCode++;
                if (nextCode == (1 << codeSize) && codeSize < 12)
                    codeSize++;
            }
            previous = code;
            previousFirst = first;
        }
        return outPos == expectedLength;
    }

    private static bool ReadCode(ReadOnlySpan<byte> data, ref int bitPos, int codeSize, out int code)
    {
        if (bitPos + codeSize > data.Length * 8) { code = 0; return false; }
        var value = 0;
        for (var i = 0; i < codeSize; i++)
            value |= ((data[(bitPos + i) >> 3] >> ((bitPos + i) & 7)) & 1) << i;
        bitPos += codeSize;
        code = value;
        return true;
    }
}

internal static class ImageFuzzyHasher
{
    public static byte[] Compute(RgbImage source)
    {
        const int size = 32;
        var gray = new double[size, size];
        var resized = ResizeLanczos3(source, size, size);
        for (var y = 0; y < size; y++)
            for (var x = 0; x < size; x++)
            {
                var q = resized.Index(x, y);
                gray[y, x] = Math.Round(
                    0.299 * resized.Pixels[q] +
                    0.587 * resized.Pixels[q + 1] +
                    0.114 * resized.Pixels[q + 2],
                    MidpointRounding.AwayFromZero);
            }

        var coeff = new double[8, 8];
        for (var v = 0; v < 8; v++)
            for (var u = 0; u < 8; u++)
            {
                double sum = 0;
                for (var y = 0; y < size; y++)
                    for (var x = 0; x < size; x++)
                        sum += gray[y, x] *
                               Math.Cos(Math.PI / size * (x + 0.5) * u) *
                               Math.Cos(Math.PI / size * (y + 0.5) * v);
                coeff[v, u] = sum * 4.0;
            }

        var values = new double[64];
        var k = 0;
        for (var y = 0; y < 8; y++)
            for (var x = 0; x < 8; x++)
                values[k++] = coeff[y, x];
        Array.Sort(values);
        var median = (values[31] + values[32]) / 2.0;

        var hash = new byte[8];
        k = 0;
        for (var i = 0; i < 8; i++)
        {
            byte value = 0;
            for (var bit = 7; bit >= 0; bit--, k++)
                if (coeff[k / 8, k % 8] > median)
                    value |= (byte)(1 << bit);
            hash[i] = value;
        }
        return hash;
    }

    private static RgbImage ResizeLanczos3(RgbImage source, int width, int height)
    {
        if (source.Width == width && source.Height == height)
            return source;

        var horizontal = new byte[checked(width * source.Height * 3)];
        var xWeights = BuildWeights(source.Width, width, 3.0);
        for (var y = 0; y < source.Height; y++)
            for (var x = 0; x < width; x++)
            {
                var weights = xWeights[x];
                for (var c = 0; c < 3; c++)
                {
                    double sum = 0;
                    foreach (var (index, weight) in weights)
                        sum += source.Pixels[source.Index(index, y) + c] * weight;
                    horizontal[(y * width + x) * 3 + c] = ClampByte(sum);
                }
            }

        var vertical = new byte[checked(width * height * 3)];
        var yWeights = BuildWeights(source.Height, height, 3.0);
        for (var y = 0; y < height; y++)
            for (var x = 0; x < width; x++)
            {
                var weights = yWeights[y];
                for (var c = 0; c < 3; c++)
                {
                    double sum = 0;
                    foreach (var (index, weight) in weights)
                        sum += horizontal[(index * width + x) * 3 + c] * weight;
                    vertical[(y * width + x) * 3 + c] = ClampByte(sum);
                }
            }
        return new RgbImage(width, height, vertical);
    }

    private static (int Index, double Weight)[][] BuildWeights(int sourceLength, int destinationLength, double radius)
    {
        var scale = (double)destinationLength / sourceLength;
        var kernelScale = Math.Min(1.0, scale);
        var support = radius / kernelScale;
        var all = new (int, double)[destinationLength][];
        for (var dst = 0; dst < destinationLength; dst++)
        {
            var center = (dst + 0.5) / scale - 0.5;
            var first = Math.Max(0, (int)Math.Ceiling(center - support));
            var last = Math.Min(sourceLength - 1, (int)Math.Floor(center + support));
            var list = new List<(int, double)>();
            var sum = 0.0;
            for (var src = first; src <= last; src++)
            {
                var distance = Math.Abs((src - center) * kernelScale);
                var weight = Lanczos(distance, radius);
                if (weight == 0) continue;
                list.Add((src, weight));
                sum += weight;
            }
            if (sum == 0)
                list.Add((Math.Clamp((int)Math.Round(center), 0, sourceLength - 1), 1.0));
            else
                for (var i = 0; i < list.Count; i++) list[i] = (list[i].Item1, list[i].Item2 / sum);
            all[dst] = list.ToArray();
        }
        return all;
    }

    private static double Lanczos(double x, double radius)
    {
        if (x >= radius) return 0;
        if (x < 1e-12) return 1;
        var pix = Math.PI * x;
        return (Math.Sin(pix) / pix) * (Math.Sin(pix / radius) / (pix / radius));
    }

    private static byte ClampByte(double value)
        => (byte)Math.Clamp((int)Math.Round(value, MidpointRounding.AwayFromZero), 0, 255);
}

