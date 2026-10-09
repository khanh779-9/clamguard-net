using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

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
