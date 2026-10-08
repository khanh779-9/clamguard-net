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

