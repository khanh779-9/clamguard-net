using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;
internal static partial class ArchiveScanner
{
    private static List<Detection> ScanZip(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        try
        {
            using var stream = new MemoryStream(data.ToArray(), writable: false);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
            var parentType = DetectZipContainerType(zip);
            var zipMetadata = ReadZipMetadata(data);
            var filePosition = 0u;
            foreach (var entry in zip.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                filePosition++;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; break; }
                if (string.IsNullOrEmpty(entry.Name)) continue;

                var metadata = filePosition <= zipMetadata.Count ? zipMetadata[(int)filePosition - 1] : null;
                var metadataCompressedSize = metadata?.CompressedSize ?? entry.CompressedLength;
                var metadataOriginalSize = metadata?.OriginalSize ?? entry.Length;
                var metadataEncrypted = metadata?.Encrypted;
                var metadataCrc = metadata?.Crc32;
                if (options.EnableHeuristics && options.HeuristicEncryptedArchive && metadataEncrypted == true &&
                    !results.Any(x => x.Name.Equals("Heuristics.Encrypted.Zip", StringComparison.OrdinalIgnoreCase)))
                {
                    results.Add(new Detection("Heuristics.Encrypted.Zip", SignatureType.Metadata, null, "heuristics", $"Encrypted ZIP member: {entry.FullName}"));
                }
                var metadataHits = MatchMetadataSignatures(
                    state.Database.Signatures.OfType<MetadataSignature>(),
                    "ZIP",
                    entry.FullName,
                    metadataCompressedSize,
                    metadataOriginalSize,
                    metadataEncrypted,
                    filePosition,
                    metadataCrc);
                metadataHits.AddRange(MatchCdbSignatures(
                    state.Database.Signatures.OfType<CdbSignature>(),
                    "ZIP",
                    data.Length,
                    entry.FullName,
                    metadataCompressedSize,
                    metadataOriginalSize,
                    metadataEncrypted,
                    filePosition,
                    cancellationToken));
                if (metadataHits.Count != 0)
                {
                    results.AddRange(metadataHits);
                    if (!options.CollectAllMatches && options.HasBlockingDetections(metadataHits)) return results;
                }

                if (entry.Length < 0) continue;
                if (entry.Length > options.Limits.MaxFileSize)
                {
                    budget.LimitExceeded = true;
                    continue;
                }
                if (entry.CompressedLength > 0 && entry.Length > (long)entry.CompressedLength * Math.Max(1, options.Limits.MaxArchiveCompressionRatio))
                {
                    budget.LimitExceeded = true;
                    continue;
                }
                byte[] child;
                try
                {
                    using var entryStream = entry.Open();
                    if (!TryReadEntry(entryStream, entry.Length, options.Limits, budget, cancellationToken, out child))
                        continue;
                }
                catch (InvalidDataException) { continue; }
                catch (IOException) { continue; }

                var childPath = entry.FullName;
                results.AddRange(ScanChild(child, childPath, parentType, state, options, parents, depth, budget, cancellationToken));
                if (budget.ExpandedBytes >= options.Limits.MaxArchiveExpandedBytes) break;
            }
        }
        catch (InvalidDataException) { }
        catch (NotSupportedException) { }
        catch (IOException) { }
        return results;
    }

    internal static bool IsSymbianSisHeader(ReadOnlySpan<byte> data)
    {
        // ClamAV validates the first 16 bytes as Symbian package UIDs.
        // Require one of the known format UIDs instead of treating arbitrary
        // 16-byte files as SIS containers.
        var uid0 = BinaryPrimitives.ReadUInt32LittleEndian(data[..4]);
        var uid2 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
        return uid2 == 0x10000419u || uid0 == 0x10201A7Au;
    }

    private static List<Detection> ScanSzdd(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (data.Length < 14) return results;

        var expectedSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(10, 4));
        var limit = Math.Min((long)expectedSize, options.Limits.MaxFileSize);
        if (limit <= 0 || limit > int.MaxValue) return results;

        // MSEXPAND is the same LZSS-style format used by ClamAV's
        // libclamav/msexpand.c. Decode into the bounded scan buffer.
        var output = new byte[checked((int)limit)];
        var window = new byte[4096];
        var windowPos = 0xFF0; // ClamAV msexpand.c: B_SIZE - 16
        var input = 14;
        var outPos = 0;

        while (input < data.Length && outPos < output.Length)
        {
            var flags = data[input++];
            for (var bit = 0; bit < 8 && outPos < output.Length; bit++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (input >= data.Length) break;

                if ((flags & (1 << bit)) != 0)
                {
                    var value = data[input++];
                    output[outPos++] = value;
                    window[windowPos] = value;
                    windowPos = (windowPos + 1) & 0xFFF;
                }
                else
                {
                    if (input + 1 >= data.Length) break;
                    var low = data[input++];
                    var high = data[input++];
                    var offset = low | ((high & 0xF0) << 4);
                    var count = (high & 0x0F) + 3;
                    for (var n = 0; n < count && outPos < output.Length; n++)
                    {
                        var value = window[(offset + n) & 0xFFF];
                        output[outPos++] = value;
                        window[windowPos] = value;
                        windowPos = (windowPos + 1) & 0xFFF;
                    }
                }
            }
        }

        if (outPos != output.Length)
            Array.Resize(ref output, outPos);

        if (!ConsumeBudget(budget, options.Limits, output.Length))
            return results;

        results.AddRange(ScanChild(output, "embedded.szdd", "SZDD", state, options, parents, depth, budget, cancellationToken));
        return results;
    }

    private static string DetectZipContainerType(ZipArchive zip)
    {
        var names = zip.Entries
            .Where(static e => !string.IsNullOrEmpty(e.Name))
            .Select(static e => e.FullName.Replace('\\', '/'))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (names.Contains("word/document.xml") || names.Any(static x => x.StartsWith("word/", StringComparison.OrdinalIgnoreCase)))
            return "OOXML_WORD";
        if (names.Contains("xl/workbook.xml") || names.Any(static x => x.StartsWith("xl/", StringComparison.OrdinalIgnoreCase)))
            return "OOXML_XL";
        if (names.Contains("ppt/presentation.xml") || names.Any(static x => x.StartsWith("ppt/", StringComparison.OrdinalIgnoreCase)))
            return "OOXML_PPT";
        return "ZIP";
    }

    private static List<Detection> ScanGzip(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        try
        {
            using var input = new MemoryStream(data.ToArray(), writable: false);
            using var gzip = new GZipStream(input, CompressionMode.Decompress, leaveOpen: false);
            if (!TryReadStream(gzip, options.Limits.MaxFileSize, options.Limits, budget, cancellationToken, out var child))
                return results;
            results.AddRange(ScanChild(child, childPath: "embedded", parentType: "GZ", state, options, parents, depth, budget, cancellationToken));
        }
        catch (InvalidDataException) { }
        catch (IOException) { }
        return results;
    }

    private static List<Detection> ScanSingleExternalCodec(
        ReadOnlySpan<byte> data,
        string format,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        try
        {
            if (!ArchiveExternalDecoder.TryDecodeSingle(data.ToArray(), format, options.Limits, cancellationToken, out var child))
                return results;
            if (!ConsumeBudget(budget, options.Limits, child.Length))
                return results;
            results.AddRange(ScanChild(child, format == "BZ" ? "embedded.bz2" : "embedded.xz", format, state, options, parents, depth, budget, cancellationToken));
        }
        catch (OperationCanceledException) { throw; }
        catch (IOException) { }
        return results;
    }

    private static List<Detection> ScanExternalArchive(
        ReadOnlySpan<byte> data,
        string format,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        try
        {
            var decoder = ArchiveManagedDecoder.Supports(format)
                ? ArchiveManagedDecoder.ExtractMembers(data.ToArray(), format, options.Limits, cancellationToken)
                : ArchiveExternalDecoder.ExtractMembers(data.ToArray(), format, options.Limits, cancellationToken);

            foreach (var item in decoder)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; break; }

                var metadataHits = MatchMetadataSignatures(
                    state.Database.Signatures.OfType<MetadataSignature>(),
                    format,
                    item.Name,
                    item.CompressedSize,
                    item.Size,
                    item.Encrypted,
                    item.FilePosition,
                    item.Crc32);
                if (SupportsClamAvCdbMetadata(format))
                {
                    metadataHits.AddRange(MatchCdbSignatures(
                        state.Database.Signatures.OfType<CdbSignature>(),
                        format,
                        data.Length,
                        item.Name,
                        item.CompressedSize ?? 0,
                        item.Size,
                        item.Encrypted,
                        item.FilePosition,
                        cancellationToken));
                }
                if (metadataHits.Count != 0)
                {
                    results.AddRange(metadataHits);
                    if (!options.CollectAllMatches && options.HasBlockingDetections(metadataHits)) return results;
                }

                if (options.EnableHeuristics && options.HeuristicEncryptedArchive && item.Encrypted == true)
                {
                    var encryptedName = format switch
                    {
                        "7Z" => "Heuristics.Encrypted.7Zip",
                        "RAR" => "Heuristics.Encrypted.RAR",
                        _ => "Heuristics.Encrypted." + format
                    };
                    if (!results.Any(x => x.Name.Equals(encryptedName, StringComparison.OrdinalIgnoreCase)))
                        results.Add(new Detection(encryptedName, SignatureType.Metadata, null, "heuristics", $"Encrypted {format} member: {item.Name}"));
                }
                if (!item.CanExtract || item.IsDirectory || item.Encrypted == true) continue;
                if (item.Size < 0) continue;
                if (item.Size > options.Limits.MaxFileSize) { budget.LimitExceeded = true; continue; }
                if (!ConsumeBudget(budget, options.Limits, item.Data.Length)) break;
                results.AddRange(ScanChild(item.Data, item.Name, format, state, options, parents, depth, budget, cancellationToken));
                if (budget.ExpandedBytes >= options.Limits.MaxArchiveExpandedBytes) break;
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (InvalidDataException) { }
        catch (NotSupportedException) { }
        catch (ArgumentException) { }
        catch (SharpCompress.Common.SharpCompressException) { }
        catch (IOException) { }
        return results;
    }

    private static List<Detection> ScanTar(
        ReadOnlySpan<byte> data,
        string format,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        long offset = 0;
        uint filePosition = 0;
        string? pendingLongName = null;
        string? pendingPaxPath = null;
        while (offset + 512 <= data.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var header = data.Slice((int)offset, 512);
            if (IsAllZero(header))
            {
                if (offset + 1024 <= data.Length && IsAllZero(data.Slice((int)offset + 512, 512))) break;
                break;
            }

            var size = ReadTarNumber(header.Slice(124, 12));
            if (size < 0) break;
            if (size > options.Limits.MaxFileSize) { budget.LimitExceeded = true; break; }
            var type = header[156];
            var name = pendingPaxPath ?? pendingLongName ?? ReadTarString(header.Slice(0, 100));
            pendingPaxPath = null;
            pendingLongName = null;
            var dataStart = offset + 512;
            var dataEnd = checked(dataStart + size);
            if (dataEnd > data.Length) break;

            if (type == (byte)'L')
            {
                pendingLongName = ReadTarString(data.Slice((int)dataStart, (int)Math.Min(size, 1024 * 1024)));
            }
            else if (type == (byte)'x')
            {
                pendingPaxPath = ParsePaxPath(data.Slice((int)dataStart, (int)size));
            }
            else if (IsTarRegularFile(type))
            {
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; break; }
                filePosition++;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    // ClamAV's untar.c calls cli_matchmeta() for every regular file,
                    // using the archive layer type/size plus the entry metadata.
                    var cdbHits = MatchCdbSignatures(
                        state.Database.Signatures.OfType<CdbSignature>(),
                        format,
                        data.Length,
                        name,
                        size,
                        size,
                        false,
                        filePosition,
                        cancellationToken);
                    if (cdbHits.Count != 0)
                    {
                        results.AddRange(cdbHits);
                        if (!options.CollectAllMatches && options.HasBlockingDetections(cdbHits))
                            return results;
                    }

                    var file = data.Slice((int)dataStart, (int)size).ToArray();
                    if (!ConsumeBudget(budget, options.Limits, file.Length)) break;
                    results.AddRange(ScanChild(file, name, format, state, options, parents, depth, budget, cancellationToken));
                }
            }

            var padded = checked((size + 511) / 512 * 512);
            offset = checked(dataStart + padded);
            if (offset > data.Length) break;
            if (budget.ExpandedBytes >= options.Limits.MaxArchiveExpandedBytes) break;
        }
        return results;
    }

    private static List<Detection> ScanCpio(
        ReadOnlySpan<byte> data,
        string format,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        uint filePosition = 0;
        if (format is "CPIO_NEWC" or "CPIO_CRC")
        {
            var offset = 0;
            while (offset + 110 <= data.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var header = data.Slice(offset, 110);
                var magic = Encoding.ASCII.GetString(header[..6]);
                if (magic is not ("070701" or "070702")) break;
                filePosition++;
                if (!TryReadHex(header.Slice(54, 8), out var fileSize) || !TryReadHex(header.Slice(94, 8), out var nameSize)) break;
                if (nameSize <= 0 || nameSize > 16 * 1024 * 1024) break;
                if (fileSize > (ulong)options.Limits.MaxFileSize) { budget.LimitExceeded = true; break; }
                var nameStart = offset + 110;
                var nameEnd = checked((long)nameStart + (long)nameSize);
                var dataStart = Align4(nameEnd);
                var dataEnd = checked(dataStart + (long)fileSize);
                if (nameEnd > data.Length || dataEnd > data.Length) break;
                var name = ReadCString(data.Slice(nameStart, (int)nameSize));
                offset = Align4((int)dataEnd);
                if (name == "TRAILER!!!") break;
                if (name.Length == 0) continue;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; break; }
                var cdbHits = MatchCdbSignatures(
                    state.Database.Signatures.OfType<CdbSignature>(),
                    format,
                    data.Length,
                    name,
                    (long)fileSize,
                    (long)fileSize,
                    false,
                    filePosition,
                    cancellationToken);
                if (cdbHits.Count != 0)
                {
                    results.AddRange(cdbHits);
                    if (!options.CollectAllMatches && options.HasBlockingDetections(cdbHits))
                        return results;
                }
                var child = data.Slice((int)dataStart, checked((int)fileSize)).ToArray();
                if (!ConsumeBudget(budget, options.Limits, child.Length)) break;
                results.AddRange(ScanChild(child, name, format, state, options, parents, depth, budget, cancellationToken));
            }
        }
        else if (format == "CPIO_ODC")
        {
            var offset = 0;
            while (offset + 76 <= data.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var header = data.Slice(offset, 76);
                if (Encoding.ASCII.GetString(header[..6]) != "070707") break;
                filePosition++;
                if (!TryReadOctalField(header.Slice(59, 6), out var nameSize) ||
                    !TryReadOctalField(header.Slice(65, 11), out var fileSize)) break;
                if (nameSize <= 0 || nameSize > 16 * 1024 * 1024 || fileSize < 0) break;
                if (fileSize > options.Limits.MaxFileSize) { budget.LimitExceeded = true; break; }
                var nameStart = checked(offset + 76);
                var nameEnd = checked((long)nameStart + nameSize);
                var dataStart = (nameEnd + 1) & ~1L;
                var dataEnd = checked(dataStart + fileSize);
                if (nameEnd > data.Length || dataEnd > data.Length) break;
                var name = ReadCString(data.Slice(nameStart, (int)nameSize));
                offset = checked((int)((dataEnd + 1) & ~1L));
                if (name == "TRAILER!!!") break;
                if (name.Length == 0) continue;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; break; }
                var cdbHits = MatchCdbSignatures(
                    state.Database.Signatures.OfType<CdbSignature>(),
                    format,
                    data.Length,
                    name,
                    (long)fileSize,
                    (long)fileSize,
                    false,
                    filePosition,
                    cancellationToken);
                if (cdbHits.Count != 0)
                {
                    results.AddRange(cdbHits);
                    if (!options.CollectAllMatches && options.HasBlockingDetections(cdbHits))
                        return results;
                }
                var child = data.Slice((int)dataStart, checked((int)fileSize)).ToArray();
                if (!ConsumeBudget(budget, options.Limits, child.Length)) break;
                results.AddRange(ScanChild(child, name, format, state, options, parents, depth, budget, cancellationToken));
            }
        }
        else if (format == "CPIO_OLD")
        {
            var offset = 0;
            var little = data.Length >= 2 && BinaryPrimitives.ReadUInt16LittleEndian(data[..2]) == 0x71C7;
            if (!little && !(data.Length >= 2 && BinaryPrimitives.ReadUInt16BigEndian(data[..2]) == 0x71C7))
                return results;

            while (offset + 26 <= data.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var header = data.Slice(offset, 26);
                var magic = little ? BinaryPrimitives.ReadUInt16LittleEndian(header[..2]) : BinaryPrimitives.ReadUInt16BigEndian(header[..2]);
                if (magic != 0x71C7) break;
                filePosition++;
                var nameSize = little ? BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(20, 2)) : BinaryPrimitives.ReadUInt16BigEndian(header.Slice(20, 2));
                var fileSize = little ? BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(22, 4)) : BinaryPrimitives.ReadUInt32BigEndian(header.Slice(22, 4));
                if (nameSize == 0) break;
                if (fileSize > (uint)options.Limits.MaxFileSize) { budget.LimitExceeded = true; break; }
                var nameStart = checked(offset + 26);
                var nameEnd = checked((long)nameStart + nameSize);
                var dataStart = (nameEnd + 1) & ~1L;
                var dataEnd = checked(dataStart + fileSize);
                if (nameEnd > data.Length || dataEnd > data.Length || dataEnd > int.MaxValue) break;
                var name = ReadCString(data.Slice(nameStart, nameSize));
                offset = checked((int)((dataEnd + 1) & ~1L));
                if (name == "TRAILER!!!") break;
                if (name.Length == 0) continue;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; break; }
                var cdbHits = MatchCdbSignatures(
                    state.Database.Signatures.OfType<CdbSignature>(),
                    format,
                    data.Length,
                    name,
                    (long)fileSize,
                    (long)fileSize,
                    false,
                    filePosition,
                    cancellationToken);
                if (cdbHits.Count != 0)
                {
                    results.AddRange(cdbHits);
                    if (!options.CollectAllMatches && options.HasBlockingDetections(cdbHits))
                        return results;
                }
                var child = data.Slice((int)dataStart, checked((int)fileSize)).ToArray();
                if (!ConsumeBudget(budget, options.Limits, child.Length)) break;
                results.AddRange(ScanChild(child, name, format, state, options, parents, depth, budget, cancellationToken));
            }
        }
        return results;
    }

}
