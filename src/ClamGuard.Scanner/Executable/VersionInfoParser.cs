using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

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
