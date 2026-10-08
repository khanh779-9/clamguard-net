using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;

namespace ClamGuard.Scanner;

/// <summary>
/// Trích xuất riêng OLE2, RTF, Microsoft Office / HWP5 (Hàn Quốc).
/// </summary>
internal static class OfficeOleExtractor
{
    internal static List<Detection> ScanOle2(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (!Ole2Reader.TryOpen(data, out var reader)) return results;

        // ClamAV's OLE2 handler identifies HWP5 by the root FileHeader stream and,
        // when its header advertises compression, raw-DEFLATE-decompresses a small
        // set of content streams before scanning them. Other streams still follow
        // the normal OLE2 child scan path.
        Hwp5OleContext? hwp5 = null;
        var fileHeader = reader.Streams.FirstOrDefault(x => x.Name.Equals("fileheader", StringComparison.OrdinalIgnoreCase));
        if (fileHeader is not null && fileHeader.Size <= 4096 &&
            reader.TryReadStream(fileHeader, out var hwpHeader) &&
            hwpHeader.Length >= 40 && hwpHeader.AsSpan(0, Math.Min(17, hwpHeader.Length)).SequenceEqual("HWP Document File"u8))
        {
            var version = BinaryPrimitives.ReadUInt32LittleEndian(hwpHeader.AsSpan(32, 4));
            var flags = BinaryPrimitives.ReadUInt32LittleEndian(hwpHeader.AsSpan(36, 4));
            hwp5 = new Hwp5OleContext(version, flags);
        }

        foreach (var stream in reader.Streams)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;
            if (stream.Size == 0 || stream.Size > (ulong)options.Limits.MaxFileSize) continue;
            if (!reader.TryReadStream(stream, out var child)) continue;

            var specialHwpStream = hwp5 is not null && IsHwp5ContentStream(stream.Name);
            if (specialHwpStream && (hwp5!.Flags & 0x2) == 0 && (hwp5.Flags & 0x1) != 0)
            {
                if (TryInflateRawBounded(child, options.Limits.MaxEmbeddedStreamSize, out var inflated))
                    child = inflated;
                else
                    continue;
            }

            if (!ArchiveScanner.ConsumeBudget(budget, options.Limits, child.Length)) break;
            results.AddRange(ArchiveScanner.ScanChild(child, stream.Name, "OLE2", state, options, parents, depth, budget, cancellationToken));
            if (!options.CollectAllMatches && results.Count != 0) return results;
        }
        return results;
    }

    private sealed record Hwp5OleContext(uint Version, uint Flags);

    private static bool IsHwp5ContentStream(string name)
        => name.StartsWith("bin", StringComparison.OrdinalIgnoreCase) ||
           name.StartsWith("jscriptversion", StringComparison.OrdinalIgnoreCase) ||
           name.StartsWith("defaultjscript", StringComparison.OrdinalIgnoreCase) ||
           name.StartsWith("section", StringComparison.OrdinalIgnoreCase) ||
           name.StartsWith("viewtext", StringComparison.OrdinalIgnoreCase) ||
           name.StartsWith("docinfo", StringComparison.OrdinalIgnoreCase);

    private static bool TryInflateRawBounded(ReadOnlySpan<byte> compressed, long maxOutput, out byte[] output)
    {
        output = [];
        if (compressed.IsEmpty || maxOutput <= 0 || maxOutput > int.MaxValue) return false;
        try
        {
            using var input = new MemoryStream(compressed.ToArray(), writable: false);
            using var inflater = new DeflateStream(input, CompressionMode.Decompress);
            using var result = new MemoryStream();
            var buffer = new byte[64 * 1024];
            while (true)
            {
                var read = inflater.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                if (result.Length + read > maxOutput) return false;
                result.Write(buffer, 0, read);
            }
            output = result.ToArray();
            return output.Length != 0;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    internal static List<Detection> ScanRtfEmbeddedObjects(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        var marker = "{\\*\\objdata"u8;
        var search = 0;

        while (search + marker.Length < data.Length &&
               budget.Entries < options.Limits.MaxArchiveEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rel = data[search..].IndexOf(marker);
            if (rel < 0) break;
            var start = search + rel + marker.Length;

            // objdata is normally a hexadecimal payload inside a brace group.
            // Track nested braces so another RTF group cannot terminate the
            // extraction prematurely.
            var depthCount = 1;
            var nibble = -1;
            using var decoded = new MemoryStream();
            var cursor = start;

            while (cursor < data.Length && depthCount > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var b = data[cursor++];

                if (b == (byte)'{')
                {
                    depthCount++;
                    continue;
                }
                if (b == (byte)'}')
                {
                    depthCount--;
                    continue;
                }

                var hex = ArchiveScanner.HexNibble(b);
                if (hex >= 0)
                {
                    if (nibble < 0) nibble = hex;
                    else
                    {
                        if (decoded.Length >= options.Limits.MaxEmbeddedStreamSize ||
                            decoded.Length >= options.Limits.MaxFileSize - 1)
                            break;

                        decoded.WriteByte((byte)((nibble << 4) | hex));
                        nibble = -1;
                    }
                }
            }

            if (decoded.Length > 0)
            {
                if (!ArchiveScanner.ConsumeBudget(budget, options.Limits, decoded.Length))
                    break;

                var child = decoded.ToArray();
                results.AddRange(ArchiveScanner.ScanChild(
                    child,
                    "embedded-rtf-object",
                    "RTF",
                    state,
                    options,
                    parents,
                    depth,
                    budget,
                    cancellationToken));
            }

            budget.Entries++;
            search = Math.Max(cursor, start + 1);
        }

        return results;
    }
}

internal sealed record OleStreamInfo(string Name, ulong StartSector, ulong Size, bool MiniStream);

internal sealed class Ole2Reader
{
    private const uint FreeSect = 0xFFFFFFFF;
    private const uint NoStream = 0xFFFFFFFF;
    private const uint EndOfChain = 0xFFFFFFFE;
    private const uint FatSect = 0xFFFFFFFD;
    private const uint DifSect = 0xFFFFFFFC;
    private readonly ReadOnlyMemory<byte> _data;
    private readonly int _sectorSize;
    private readonly int _miniSectorSize;
    private readonly uint[] _fat;
    private readonly uint[] _miniFat;
    private readonly byte[] _miniStream;

    public IReadOnlyList<OleStreamInfo> Streams { get; }

    private Ole2Reader(ReadOnlyMemory<byte> data, int sectorSize, int miniSectorSize, uint[] fat, uint[] miniFat, byte[] miniStream, IReadOnlyList<OleStreamInfo> streams)
    {
        _data = data;
        _sectorSize = sectorSize;
        _miniSectorSize = miniSectorSize;
        _fat = fat;
        _miniFat = miniFat;
        _miniStream = miniStream;
        Streams = streams;
    }

    public static bool TryOpen(ReadOnlySpan<byte> data, out Ole2Reader reader)
    {
        reader = null!;
        if (data.Length < 512 || !data[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return false;
        if (BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(28, 2)) != 0xFFFE) return false;
        var sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(30, 2));
        var miniShift = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(32, 2));
        if (sectorShift is not (9 or 12) || miniShift is not (6 or 9)) return false;
        var sectorSize = 1 << sectorShift;
        var miniSectorSize = 1 << miniShift;
        var numFatSectors = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(44, 4));
        var firstDirSector = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(48, 4));
        var miniCutoff = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(56, 4));
        var firstMiniFat = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(60, 4));
        var numMiniFat = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(64, 4));
        var firstDifat = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(68, 4));
        var numDifat = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(72, 4));
        if (numFatSectors > 4096 || numMiniFat > 4096 || numDifat > 4096) return false;

        var difat = new List<uint>(checked((int)Math.Min(109u, numFatSectors)));
        for (var i = 0; i < 109 && difat.Count < numFatSectors; i++)
        {
            var sid = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(76 + i * 4, 4));
            if (sid != FreeSect) difat.Add(sid);
        }
        var nextDif = firstDifat;
        for (var d = 0; d < numDifat && difat.Count < numFatSectors && nextDif != EndOfChain; d++)
        {
            if (!TrySector(data, sectorSize, nextDif, out var sec)) return false;
            var entries = sectorSize / 4 - 1;
            for (var i = 0; i < entries && difat.Count < numFatSectors; i++)
            {
                var sid = BinaryPrimitives.ReadUInt32LittleEndian(sec.Span.Slice(i * 4, 4));
                if (sid != FreeSect) difat.Add(sid);
            }
            nextDif = BinaryPrimitives.ReadUInt32LittleEndian(sec.Span.Slice((sectorSize / 4 - 1) * 4, 4));
        }
        if (difat.Count != numFatSectors) return false;

        var fat = ReadFat(data, sectorSize, difat);
        if (fat.Length == 0) return false;
        var dirBytes = ReadSectorChain(data, sectorSize, fat, firstDirSector, 128L * 1024 * 1024);
        if (dirBytes.Length < 128) return false;

        uint rootMiniStart = EndOfChain;
        ulong rootMiniSize = 0;
        var streams = new List<OleStreamInfo>();
        for (var off = 0; off + 128 <= dirBytes.Length; off += 128)
        {
            var objType = dirBytes[off + 66];
            if (objType == 0) continue;
            var nameChars = Math.Max(0, BinaryPrimitives.ReadUInt16LittleEndian(dirBytes.AsSpan(off + 64, 2)) / 2 - 1);
            var name = nameChars > 0 ? Encoding.Unicode.GetString(dirBytes, off, nameChars * 2) : string.Empty;
            var left = BinaryPrimitives.ReadUInt32LittleEndian(dirBytes.AsSpan(off + 68, 4));
            var right = BinaryPrimitives.ReadUInt32LittleEndian(dirBytes.AsSpan(off + 72, 4));
            _ = left; _ = right;
            var start = BinaryPrimitives.ReadUInt32LittleEndian(dirBytes.AsSpan(off + 116, 4));
            var size = BinaryPrimitives.ReadUInt64LittleEndian(dirBytes.AsSpan(off + 120, 8));
            if (objType == 5)
            {
                rootMiniStart = start;
                rootMiniSize = size;
            }
            else if (objType == 2 && size > 0 && name.Length != 0)
            {
                streams.Add(new OleStreamInfo(name, start, size, size < miniCutoff));
            }
        }

        var miniFatBytes = numMiniFat == 0 || firstMiniFat == EndOfChain ? [] : ReadSectorChain(data, sectorSize, fat, firstMiniFat, 16L * 1024 * 1024);
        var miniFat = new uint[miniFatBytes.Length / 4];
        for (var i = 0; i < miniFat.Length; i++) miniFat[i] = BinaryPrimitives.ReadUInt32LittleEndian(miniFatBytes.AsSpan(i * 4, 4));
        var miniStream = rootMiniStart == EndOfChain || rootMiniSize == 0
            ? []
            : ReadSectorChain(data, sectorSize, fat, rootMiniStart, Math.Min(rootMiniSize, 256UL * 1024 * 1024));

        reader = new Ole2Reader(data.ToArray(), sectorSize, miniSectorSize, fat, miniFat, miniStream, streams);
        return true;
    }

    public bool TryReadStream(OleStreamInfo stream, out byte[] bytes)
    {
        bytes = [];
        if (stream.Size > int.MaxValue) return false;
        if (stream.MiniStream)
        {
            if (_miniFat.Length == 0 || _miniStream.Length == 0) return false;
            using var output = new MemoryStream((int)stream.Size);
            var current = (uint)stream.StartSector;
            var remaining = stream.Size;
            var guard = 0;
            while (remaining > 0 && current != EndOfChain && current != FreeSect && guard++ < _miniFat.Length)
            {
                var offset = checked((ulong)current * (ulong)_miniSectorSize);
                if (offset >= (ulong)_miniStream.Length) return false;
                var take = (int)Math.Min((ulong)_miniSectorSize, remaining);
                if (offset + (ulong)take > (ulong)_miniStream.Length) return false;
                output.Write(_miniStream, (int)offset, take);
                remaining -= (ulong)take;
                current = current < _miniFat.Length ? _miniFat[current] : EndOfChain;
            }
            if (remaining != 0) return false;
            bytes = output.ToArray();
            return true;
        }

        var sectorsNeeded = checked((long)((stream.Size + (ulong)_sectorSize - 1) / (ulong)_sectorSize));
        using var outStream = new MemoryStream((int)stream.Size);
        var sid = (uint)stream.StartSector;
        for (long i = 0; i < sectorsNeeded; i++)
        {
            if (sid >= _fat.Length || !TrySector(_data.Span, _sectorSize, sid, out var sec)) return false;
            var remaining = stream.Size - (ulong)outStream.Length;
            var take = (int)Math.Min((ulong)_sectorSize, remaining);
            outStream.Write(sec.Span[..take]);
            sid = _fat[sid];
        }
        bytes = outStream.ToArray();
        return true;
    }

    private static uint[] ReadFat(ReadOnlySpan<byte> data, int sectorSize, IReadOnlyList<uint> fatSectors)
    {
        var entries = checked(fatSectors.Count * (sectorSize / 4));
        var fat = new uint[entries];
        var p = 0;
        foreach (var sid in fatSectors)
        {
            if (!TrySector(data, sectorSize, sid, out var sec)) return [];
            for (var i = 0; i < sectorSize / 4; i++) fat[p++] = BinaryPrimitives.ReadUInt32LittleEndian(sec.Span.Slice(i * 4, 4));
        }
        return fat;
    }

    private static byte[] ReadSectorChain(ReadOnlySpan<byte> data, int sectorSize, IReadOnlyList<uint> fat, uint first, ulong maxBytes)
    {
        if (first is EndOfChain or FreeSect || fat.Count == 0) return [];
        using var output = new MemoryStream();
        var sid = first;
        var guard = 0;
        while (sid < fat.Count && sid is not EndOfChain and not FreeSect && guard < fat.Count)
        {
            guard++;
            if (!TrySector(data, sectorSize, sid, out var sec)) break;
            if (output.Length + sec.Length > (long)maxBytes) break;
            output.Write(sec.Span);
            sid = fat[(int)sid];
        }
        return output.ToArray();
    }

    private static bool TrySector(ReadOnlySpan<byte> data, int sectorSize, uint sid, out ReadOnlyMemory<byte> sector)
    {
        sector = default;
        var offset = checked(((ulong)sid + 1UL) * (ulong)sectorSize);
        if (offset > (ulong)data.Length || offset + (ulong)sectorSize > (ulong)data.Length) return false;
        sector = data.Slice((int)offset, sectorSize).ToArray();
        return true;
    }
}
