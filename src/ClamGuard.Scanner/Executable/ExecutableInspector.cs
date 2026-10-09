using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

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
