using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal static partial class PeSpecializedMatcher
{
    private static bool TryParseHeaders(ReadOnlySpan<byte> data, long fileLength, out PeImageView pe)
    {
        pe = null!;
        if (fileLength <= 0 || data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c, 4));
        if (peOffset < 0 || (long)peOffset + 24 > data.Length) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(peOffset, 4)) != 0x00004550) return false;

        var coff = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 2, 2));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 16, 2));
        var optional = coff + 20;
        if (optionalSize < 96 || optional > data.Length - optionalSize) return false;

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optional, 2));
        var is64 = magic == 0x20b;
        if (!is64 && magic != 0x10b) return false;

        var dataDirectoryOffset = optional + (is64 ? 112 : 96);
        if (dataDirectoryOffset > optional + optionalSize ||
            dataDirectoryOffset + 8 * (int)(ImportDirectoryIndex + 1) > optional + optionalSize)
            return false;

        var importOffset = dataDirectoryOffset + 8 * (int)ImportDirectoryIndex;
        var importRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset, 4));
        var importSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset + 4, 4));

        var table = optional + optionalSize;
        var tableBytes = checked((long)sections * 40L);
        if (table < 0 || tableBytes < 0 || table + tableBytes > data.Length) return false;

        var parsedSections = new List<PeSectionView>(sections);
        for (var i = 0; i < sections; i++)
        {
            var o = table + i * 40;
            var nameBytes = data.Slice((int)o, 8);
            var zero = nameBytes.IndexOf((byte)0);
            if (zero < 0) zero = 8;
            var name = Encoding.ASCII.GetString(nameBytes[..zero]);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 8, 4));
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 12, 4));
            var declaredRawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 16, 4));
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 20, 4));
            var rawSize = rawOffset >= fileLength
                ? 0u
                : Math.Min(declaredRawSize, (uint)Math.Min((long)uint.MaxValue, fileLength - rawOffset));
            parsedSections.Add(new PeSectionView(name, rawOffset, rawSize, virtualAddress, virtualSize));
        }

        var overlayStart = Math.Clamp(table + tableBytes, 0, fileLength);
        foreach (var section in parsedSections)
        {
            var end = section.RawOffset + section.RawSize;
            if (section.RawSize > 0 && end > overlayStart && end <= fileLength)
                overlayStart = end;
        }

        pe = new PeImageView
        {
            IsPe32Plus = is64,
            NumberOfSections = sections,
            OptionalHeaderOffset = optional,
            OptionalHeaderSize = optionalSize,
            DataDirectoryOffset = dataDirectoryOffset,
            Sections = parsedSections,
            ImportRva = importRva,
            ImportSize = importSize,
            OverlayOffset = overlayStart,
            OverlaySize = fileLength - overlayStart
        };
        return true;
    }

    private static bool TryParse(ReadOnlySpan<byte> data, out PeImageView pe)
    {
        pe = null!;
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c, 4));
        if (peOffset < 0 || peOffset > data.Length - 24) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(peOffset, 4)) != 0x00004550) return false;

        var coff = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 2, 2));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 16, 2));
        var optional = coff + 20;
        if (optionalSize < 96 || optional > data.Length - optionalSize) return false;

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optional, 2));
        var is64 = magic == 0x20b;
        if (!is64 && magic != 0x10b) return false;

        var dataDirectoryOffset = optional + (is64 ? 112 : 96);
        if (dataDirectoryOffset > optional + optionalSize || dataDirectoryOffset + 8 * (int)(ImportDirectoryIndex + 1) > optional + optionalSize)
            return false;

        var importOffset = dataDirectoryOffset + 8 * (int)ImportDirectoryIndex;
        var importRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset, 4));
        var importSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset + 4, 4));

        var table = optional + optionalSize;
        var tableBytes = checked((long)sections * 40L);
        if (table < 0 || tableBytes < 0 || table + tableBytes > data.Length) return false;

        var parsedSections = new List<PeSectionView>(sections);
        for (var i = 0; i < sections; i++)
        {
            var o = table + i * 40;
            var nameBytes = data.Slice((int)o, 8);
            var zero = nameBytes.IndexOf((byte)0);
            if (zero < 0) zero = 8;
            var name = Encoding.ASCII.GetString(nameBytes[..zero]);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 8, 4));
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 12, 4));
            var declaredRawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 16, 4));
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 20, 4));

            // ClamAV's PE parser treats bytes beyond EOF as unavailable section
            // content. Keep only the file-backed portion for hash/RVA operations.
            var rawSize = rawOffset >= data.Length
                ? 0u
                : Math.Min(declaredRawSize, (uint)(data.Length - rawOffset));

            parsedSections.Add(new PeSectionView(name, rawOffset, rawSize, virtualAddress, virtualSize));
        }

        long overlayStart = Math.Clamp(table + tableBytes, 0, data.Length);
        foreach (var section in parsedSections)
        {
            var end = section.RawOffset + section.RawSize;
            if (section.RawSize > 0 && end > overlayStart && end <= data.Length)
                overlayStart = end;
        }

        pe = new PeImageView
        {
            IsPe32Plus = is64,
            NumberOfSections = sections,
            OptionalHeaderOffset = optional,
            OptionalHeaderSize = optionalSize,
            DataDirectoryOffset = dataDirectoryOffset,
            Sections = parsedSections,
            ImportRva = importRva,
            ImportSize = importSize,
            OverlayOffset = overlayStart,
            OverlaySize = data.Length - overlayStart
        };
        return true;
    }

    public static bool TryGetOverlayRange(ReadOnlySpan<byte> headerData, long fileLength, out long offset, out long length)
    {
        offset = 0;
        length = 0;
        if (fileLength <= 0 || headerData.Length < 0x40 || headerData[0] != 'M' || headerData[1] != 'Z')
            return false;

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(headerData.Slice(0x3c, 4));
        if (peOffset < 0 || (long)peOffset + 24 > headerData.Length || BinaryPrimitives.ReadUInt32LittleEndian(headerData.Slice(peOffset, 4)) != 0x00004550)
            return false;

        var coff = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(headerData.Slice(coff + 2, 2));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(headerData.Slice(coff + 16, 2));
        var table = coff + 20 + optionalSize;
        if (sections == 0 || table < 0)
            return false;

        var tableBytes = checked((long)sections * 40L);
        if (tableBytes > int.MaxValue || table + tableBytes > headerData.Length)
            return false; // Caller deliberately bounds the prefix to 4 MiB.

        var overlayStart = Math.Clamp(table + tableBytes, 0, fileLength);
        for (var i = 0; i < sections; i++)
        {
            var section = checked(table + i * 40);
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(headerData.Slice(section + 16, 4));
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(headerData.Slice(section + 20, 4));
            if (rawSize == 0 || rawOffset >= fileLength)
                continue;
            var end = Math.Min(fileLength, (long)rawOffset + rawSize);
            if (end > overlayStart)
                overlayStart = end;
        }

        if (overlayStart >= fileLength)
            return false;

        offset = overlayStart;
        length = fileLength - overlayStart;
        return true;
    }

    public static bool TryGetOverlay(ReadOnlySpan<byte> data, out ReadOnlySpan<byte> overlay, out long offset)
    {
        overlay = default;
        offset = 0;
        if (!TryParse(data, out var pe) || pe.OverlaySize <= 0 || pe.OverlayOffset > int.MaxValue)
            return false;
        var start = (int)pe.OverlayOffset;
        var length = (int)pe.OverlaySize;
        if (start < 0 || length <= 0 || start > data.Length - length)
            return false;
        overlay = data.Slice(start, length);
        offset = start;
        return true;
    }

    private static bool TryReadImports(ReadOnlySpan<byte> data, PeImageView pe, out List<PeImport> imports, out int hashedLength)
    {
        imports = [];
        hashedLength = 0;
        if (!RvaToRaw(pe.ImportRva, pe.Sections, data.Length, out var importRaw)) return false;
        var descriptorLimit = Math.Min((long)pe.ImportSize, data.Length - importRaw);
        if (descriptorLimit < 20) return false;

        var descriptorCount = 0;
        while (descriptorCount++ < MaxImports)
        {
            var d = importRaw + descriptorCount * 20L - 20;
            if (d < importRaw || d + 20 > importRaw + descriptorLimit || d + 20 > data.Length) return false;
            var originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)d, 4));
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)d + 12, 4));
            var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)d + 16, 4));
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                return imports.Count != 0;
            if (nameRva == 0) return false;
            if (!RvaToRaw(nameRva, pe.Sections, data.Length, out var nameRaw)) return false;
            if (!TryReadAsciiZ(data, nameRaw, MaxImportNameLength, out var dllName)) return false;
            var normalizedDll = NormalizeLibraryName(dllName);

            var thunkRva = originalFirstThunk;
            if (thunkRva == 0 || !RvaToRaw(thunkRva, pe.Sections, data.Length, out var thunkRaw) || thunkRaw == 0)
            {
                thunkRva = firstThunk;
                if (thunkRva == 0 || !RvaToRaw(thunkRva, pe.Sections, data.Length, out thunkRaw) || thunkRaw == 0)
                    return false;
            }
            var thunkSize = pe.IsPe32Plus ? 8 : 4;
            var ordinalMask = pe.IsPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
            var functionCount = 0;
            while (functionCount++ < MaxImports)
            {
                var to = thunkRaw + (long)(functionCount - 1) * thunkSize;
                if (to < 0 || to > data.Length - thunkSize) return false;
                var thunkValue = pe.IsPe32Plus
                    ? BinaryPrimitives.ReadUInt64LittleEndian(data.Slice((int)to, 8))
                    : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)to, 4));
                if (thunkValue == 0) break;

                string function;
                if ((thunkValue & ordinalMask) != 0)
                {
                    var ordinal = (ushort)(thunkValue & 0xffff);
                    function = ResolveKnownOrdinal(normalizedDll, ordinal) ?? $"ord{ordinal}";
                }
                else
                {
                    var hintNameRva = checked((uint)thunkValue);
                    if (!RvaToRaw(hintNameRva, pe.Sections, data.Length, out var hintNameRaw) || hintNameRaw > data.Length - 2)
                        return false;
                    if (!TryReadAsciiZ(data, hintNameRaw + 2, MaxImportNameLength, out function)) return false;
                }

                if (!IsValidImportName(function)) return false;
                var normalizedFunction = function.ToLowerInvariant();
                imports.Add(new PeImport(normalizedDll, normalizedFunction));
                hashedLength += normalizedDll.Length + 1 + normalizedFunction.Length + (imports.Count > 1 ? 1 : 0);
                if (imports.Count >= MaxImports) return false;
            }
        }

        return false;
    }

    private static string NormalizeLibraryName(string library)
    {
        var value = library.Trim();
        // ClamAV looks at the FIRST dot and strips only when that suffix is
        // exactly .dll/.sys/.ocx. Do not turn foo.bar.dll into foo.bar.
        var dot = value.IndexOf('.');
        if (dot > 0)
        {
            var ext = value[dot..];
            if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase))
                value = value[..dot];
        }
        return value.ToLowerInvariant();
    }

    private static bool IsValidImportName(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxImportNameLength) return false;
        foreach (var c in value)
        {
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                c == '_' || c == '.')
                continue;
            return false;
        }
        return true;
    }

    private static string? ResolveKnownOrdinal(string library, ushort ordinal)
    {
        // ClamAV has special ordinal-name maps for WS2_32/wsock32. Keeping the
        // common Winsock exports here removes a frequent source of imphash drift;
        // unknown ordinals remain deterministic as ordNNN.
        if (library is "ws2_32" or "wsock32")
        {
            return ordinal switch
            {
                1 => "accept", 2 => "bind", 3 => "closesocket", 4 => "connect", 5 => "getpeername",
                6 => "getsockname", 7 => "getsockopt", 8 => "htonl", 9 => "htons", 10 => "ioctlsocket",
                11 => "inet_addr", 12 => "inet_ntoa", 13 => "listen", 14 => "ntohl", 15 => "ntohs",
                16 => "recv", 17 => "recvfrom", 18 => "select", 19 => "send", 20 => "sendto",
                21 => "setsockopt", 22 => "shutdown", 23 => "socket", 24 => "gethostbyaddr", 25 => "gethostbyname",
                _ => null
            };
        }
        return null;
    }

    private static bool TryReadAsciiZ(ReadOnlySpan<byte> data, long offset, int maxLength, out string value)
    {
        value = string.Empty;
        if (offset < 0 || offset >= data.Length) return false;
        var end = Math.Min(data.Length, checked((int)Math.Min(int.MaxValue, offset + maxLength)));
        var start = (int)offset;
        var slice = data[start..end];
        var zero = slice.IndexOf((byte)0);
        if (zero < 0) return false;
        value = Encoding.ASCII.GetString(slice[..zero]);
        return value.Length != 0;
    }

    private static bool RvaToRaw(uint rva, IReadOnlyList<PeSectionView> sections, int fileLength, out int raw)
    {
        raw = -1;
        foreach (var section in sections)
        {
            var start = (ulong)section.VirtualAddress;
            var rawSpan = (ulong)section.RawSize;
            if ((ulong)rva < start || (ulong)rva - start >= rawSpan) continue;
            var candidate = (long)section.RawOffset + ((long)rva - (long)start);
            if (candidate < 0 || candidate >= fileLength) return false;
            raw = (int)candidate;
            return true;
        }

        return rva < fileLength && rva <= int.MaxValue
            ? (raw = (int)rva) >= 0
            : false;
    }
}
