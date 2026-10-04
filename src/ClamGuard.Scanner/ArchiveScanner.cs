using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal sealed class ArchiveScanBudget
{
    public int Entries;
    public long ExpandedBytes;
}

internal static class ArchiveScanner
{
    public static IReadOnlyList<Detection> Scan(
        ReadOnlySpan<byte> data,
        string hintPath,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string>? parents,
        int depth,
        CancellationToken cancellationToken,
        string? forcedType = null)
    {
        var budget = new ArchiveScanBudget();
        try
        {
            var results = ScanInternal(data, hintPath, state, options, parents ?? [], depth, budget, cancellationToken, forcedType);
            return !options.CollectAllMatches && results.Count > 1 ? [results[0]] : results;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (InvalidDataException)
        {
            // CL_TYPE parsers may report a malformed/truncated layer without
            // preventing cli_magic_scan() from continuing to the raw scan.
            return [];
        }
        catch (NotSupportedException)
        {
            return [];
        }
        catch (SharpCompress.Common.SharpCompressException)
        {
            return [];
        }
    }

    private static string? NormalizeHandlerType(string? type)
        => type?.ToUpperInvariant() switch
        {
            "OOXML_WORD" or "OOXML_PPT" or "OOXML_XL" or "OOXML_HWP" => "ZIP",
            "XML_WORD" or "XML_XL" or "XML_HWP" => "ZIP",
            "MSOLE2" or "HWPOLE2" => "OLE2",
            "MSSZDD" => "SZDD",
            "MSCAB" or "CABSFX" => "CAB",
            "MSCHM" => "CHM",
            "LHA_LZH" => "LHA",
            "SWF" => "FLASH",
            _ => type
        };

    private static IReadOnlyList<Detection> ScanInternal(
        ReadOnlySpan<byte> data,
        string hintPath,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken,
        string? forcedType = null)
    {
        if (depth >= Math.Max(1, options.Limits.MaxArchiveDepth)) return [];

        // Once the scan layer has a ClamAV file type (including an FTM override),
        // that type is authoritative for selecting the parser. Re-detecting from
        // bytes here could discard a dynamic FTM re-type and skip its handler.
        var type = NormalizeHandlerType(forcedType ?? DetectContainerType(data, hintPath));
        return type switch
        {
            "ZIP" => ScanZip(data, state, options, parents, depth, budget, cancellationToken),
            "GZ" => ScanGzip(data, state, options, parents, depth, budget, cancellationToken),
            "BZ" => ScanSingleExternalCodec(data, "BZ", state, options, parents, depth, budget, cancellationToken),
            "XZ" => ScanSingleExternalCodec(data, "XZ", state, options, parents, depth, budget, cancellationToken),
            "RAR" => ScanExternalArchive(data, "RAR", state, options, parents, depth, budget, cancellationToken),
            "7Z" => ScanExternalArchive(data, "7Z", state, options, parents, depth, budget, cancellationToken),
            "ARJ" => ScanExternalArchive(data, "ARJ", state, options, parents, depth, budget, cancellationToken),
            "CAB" => ScanExternalArchive(data, "CAB", state, options, parents, depth, budget, cancellationToken),
            "CHM" => ScanExternalArchive(data, "CHM", state, options, parents, depth, budget, cancellationToken),
            "ISO" => ScanExternalArchive(data, "ISO", state, options, parents, depth, budget, cancellationToken),
            "XAR" => ScanExternalArchive(data, "XAR", state, options, parents, depth, budget, cancellationToken),
            "DMG" => ScanExternalArchive(data, "DMG", state, options, parents, depth, budget, cancellationToken),
            "LHA" => ScanExternalArchive(data, "LHA", state, options, parents, depth, budget, cancellationToken),
            "EGG" => ScanExternalArchive(data, "EGG", state, options, parents, depth, budget, cancellationToken),
            "ALZ" => ScanExternalArchive(data, "ALZ", state, options, parents, depth, budget, cancellationToken),
            "SIS" => ScanExternalArchive(data, "SIS", state, options, parents, depth, budget, cancellationToken),
            "NULSFT" => ScanExternalArchive(data, "NULSFT", state, options, parents, depth, budget, cancellationToken),
            "SZDD" => ScanSzdd(data, state, options, parents, depth, budget, cancellationToken),
            "POSIX_TAR" or "OLD_TAR" => ScanTar(data, type!, state, options, parents, depth, budget, cancellationToken),
            "CPIO_NEWC" or "CPIO_CRC" or "CPIO_ODC" or "CPIO_OLD" => ScanCpio(data, type, state, options, parents, depth, budget, cancellationToken),
            "OLE2" => ScanOle2(data, state, options, parents, depth, budget, cancellationToken),
            "RTF" => ScanRtfEmbeddedObjects(data, state, options, parents, depth, budget, cancellationToken),
            "BINHEX" => ScanBinHex(data, state, options, parents, depth, budget, cancellationToken),
            "UUENCODED" => ScanUuEncoded(data, state, options, parents, depth, budget, cancellationToken),
            "TNEF" => ScanTnef(data, state, options, parents, depth, budget, cancellationToken),
            "MAIL" or "MHTML" => ScanMimeMail(data, type, state, options, parents, depth, budget, cancellationToken),
            "FLASH" => ScanFlash(data, state, options, parents, depth, budget, cancellationToken),
            "UDF" or "AUTOIT" or "ISHIELD_MSI" => ScanExternalArchive(data, type, state, options, parents, depth, budget, cancellationToken),
            "PDF" => ScanPdfEmbeddedStreams(data, state, options, parents, depth, budget, cancellationToken),
            _ => []
        };
    }

    private sealed record ZipMemberMetadata(long OriginalSize, long CompressedSize, bool Encrypted, uint Crc32, uint CompressionMethod);

    private static List<ZipMemberMetadata> ReadZipMetadata(ReadOnlySpan<byte> data)
    {
        const uint Eocd = 0x06054b50u;
        const uint Central = 0x02014b50u;
        const int EocdLength = 22;
        const int CentralLength = 46;
        var result = new List<ZipMemberMetadata>();
        var searchStart = Math.Max(0, data.Length - (EocdLength + ushort.MaxValue));
        var eocdOffset = -1;
        for (var i = data.Length - EocdLength; i >= searchStart; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i, 4)) == Eocd)
            {
                eocdOffset = i;
                break;
            }
        }
        if (eocdOffset < 0) return result;

        var entryCount = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(eocdOffset + 10, 2));
        var centralSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(eocdOffset + 12, 4));
        var centralOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(eocdOffset + 16, 4));
        if (entryCount == ushort.MaxValue || centralSize == uint.MaxValue || centralOffset == uint.MaxValue)
            return result; // ZIP64 central metadata remains on the existing archive decoder path.
        if ((ulong)centralOffset + centralSize > (ulong)data.Length || (ulong)centralOffset > int.MaxValue)
            return result;

        var cursor = (int)centralOffset;
        for (var i = 0; i < entryCount; i++)
        {
            if (cursor < 0 || cursor > data.Length - CentralLength ||
                BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(cursor, 4)) != Central)
                return [];

            var flags = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor + 8, 2));
            var method = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor + 10, 2));
            var crc = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(cursor + 16, 4));
            var compressed = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(cursor + 20, 4));
            var original = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(cursor + 24, 4));
            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor + 28, 2));
            var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor + 30, 2));
            var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor + 32, 2));
            var recordLength = checked(CentralLength + nameLength + extraLength + commentLength);
            if (recordLength <= CentralLength || cursor > data.Length - recordLength)
                return [];

            result.Add(new ZipMemberMetadata(
                original,
                compressed,
                (flags & 0x0001) != 0,
                crc,
                method));
            cursor += recordLength;
        }
        return result;
    }

    private static bool MetadataRangeMatches(MetadataRange range, long value)
    {
        // cli_loadmd() stores exact values in both bounds. A wildcard is
        // represented by a null MetadataRange and is handled by the caller.
        return range.Min == value && range.Max == value;
    }

    private static List<Detection> MatchMetadataSignatures(
        IEnumerable<MetadataSignature> signatures,
        string containerType,
        string fileName,
        long? compressedSize,
        long? originalSize,
        bool? encrypted,
        uint filePosition,
        uint? crc32)
    {
        var results = new List<Detection>();
        foreach (var signature in signatures)
        {
            if (!signature.ContainerType.Equals(containerType, StringComparison.OrdinalIgnoreCase)) continue;
            if (signature.Encrypted is not null && signature.Encrypted.Value != 2)
            {
                if (encrypted is null || signature.Encrypted.Value != (encrypted.Value ? 1 : 0)) continue;
            }
            if (signature.OriginalSize is not null)
            {
                if (originalSize is null || !MetadataRangeMatches(signature.OriginalSize.Value, originalSize.Value)) continue;
            }
            if (signature.CompressedSize is not null)
            {
                if (compressedSize is null || !MetadataRangeMatches(signature.CompressedSize.Value, compressedSize.Value)) continue;
            }
            // ClamAV's cli_loadmd stores res1 and cli_matchmeta only compares it
            // when the parsed value is non-zero. Preserve that exact quirk.
            if (signature.Res1.GetValueOrDefault() != 0)
            {
                if (crc32 is null || (signature.Res1 is not null && (uint)signature.Res1.Value != crc32.Value)) continue;
            }
            if (signature.FilePosition is not null && !MetadataRangeMatches(signature.FilePosition.Value, filePosition)) continue;
            // ClamAV 1.5.4 parses metadata CompressionMethod but cli_matchmeta() does not use it.
            if (signature.FileNameRegex is not null && !signature.FileNameRegex.IsMatch(fileName)) continue;
            results.Add(new Detection(
                signature.Name,
                SignatureType.Metadata,
                null,
                signature.SourceFile,
                $"{containerType} member {filePosition}: {fileName}"));
        }
        return results;
    }

    private static List<Detection> MatchCdbSignatures(
        IEnumerable<CdbSignature> signatures,
        string containerType,
        long containerSize,
        string fileName,
        long fileSizeInContainer,
        long fileSizeReal,
        bool? encrypted,
        uint filePosition,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        var clamType = ToClamAvFileType(containerType);

        foreach (var signature in signatures)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (signature.ContainerType != "*" &&
                !string.Equals(signature.ContainerType, clamType, StringComparison.Ordinal))
                continue;

            if (signature.Encrypted != 2)
            {
                if (encrypted is null || signature.Encrypted != (encrypted.Value ? 1 : 0))
                    continue;
            }

            if (!CdbRangeMatches(signature.ContainerSize, containerSize) ||
                !CdbRangeMatches(signature.FileSizeInContainer, fileSizeInContainer) ||
                !CdbRangeMatches(signature.FileSizeReal, fileSizeReal) ||
                !CdbRangeMatches(signature.FilePosition, filePosition))
                continue;

            if (signature.FileNameRegex is not null &&
                !signature.FileNameRegex.IsMatch(fileName))
                continue;

            results.Add(new Detection(
                signature.Name,
                SignatureType.Metadata,
                null,
                signature.SourceFile,
                $"{containerType} member {filePosition}: {fileName}"));
        }

        return results;
    }

    private static bool SupportsClamAvCdbMetadata(string format)
        => format is "ZIP" or "RAR" or "ARJ" or "EGG" or "POSIX_TAR" or "OLD_TAR" or
            "CPIO_OLD" or "CPIO_ODC" or "CPIO_NEWC" or "CPIO_CRC";

    private static bool CdbRangeMatches(MetadataRange? range, long value)
    {
        if (range is null)
            return true;

        // cli_matchmeta() treats a zero endpoint of a non-exact range as
        // unbounded, while an exact 0 remains a literal value.
        var min = range.Value.Min;
        var max = range.Value.Max;
        if (min == max)
            return min == value;

        if (min != 0 && min > value)
            return false;
        if (max != 0 && max < value)
            return false;
        return true;
    }

    private static string ToClamAvFileType(string containerType)
        => containerType.ToUpperInvariant() switch
        {
            "ZIP" => "CL_TYPE_ZIP",
            "RAR" => "CL_TYPE_RAR",
            "7Z" => "CL_TYPE_7Z",
            "ARJ" => "CL_TYPE_ARJ",
            "CAB" => "CL_TYPE_MSCAB",
            "CHM" => "CL_TYPE_MSCHM",
            "OLE2" => "CL_TYPE_MSOLE2",
            "ISO" or "ISO9660" => "CL_TYPE_ISO9660",
            "UDF" => "CL_TYPE_UDF",
            "GZ" => "CL_TYPE_GZ",
            "BZ" => "CL_TYPE_BZ",
            "XZ" => "CL_TYPE_XZ",
            "SIS" => "CL_TYPE_SIS",
            "EGG" => "CL_TYPE_EGG",
            "ALZ" => "CL_TYPE_ALZ",
            "LHA" or "LHA_LZH" => "CL_TYPE_LHA_LZH",
            "DMG" => "CL_TYPE_DMG",
            "XAR" => "CL_TYPE_XAR",
            "RTF" => "CL_TYPE_RTF",
            "PDF" => "CL_TYPE_PDF",
            "FLASH" or "SWF" => "CL_TYPE_SWF",
            "BINHEX" => "CL_TYPE_BINHEX",
            "UUENCODED" => "CL_TYPE_UUENCODED",
            "TNEF" => "CL_TYPE_TNEF",
            "MAIL" => "CL_TYPE_MAIL",
            "MHTML" => "CL_TYPE_MHTML",
            "AUTOIT" => "CL_TYPE_AUTOIT",
            "ISHIELD_MSI" => "CL_TYPE_ISHIELD_MSI",
            "NULSFT" => "CL_TYPE_NULSFT",
            "SZDD" => "CL_TYPE_MSSZDD",
            "POSIX_TAR" => "CL_TYPE_POSIX_TAR",
            "OLD_TAR" => "CL_TYPE_OLD_TAR",
            "CPIO_OLD" => "CL_TYPE_CPIO_OLD",
            "CPIO_ODC" => "CL_TYPE_CPIO_ODC",
            "CPIO_NEWC" => "CL_TYPE_CPIO_NEWC",
            "CPIO_CRC" => "CL_TYPE_CPIO_CRC",
            _ => "CL_TYPE_" + containerType.ToUpperInvariant()
        };

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
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;
                if (string.IsNullOrEmpty(entry.Name)) continue;

                var metadata = filePosition <= zipMetadata.Count ? zipMetadata[(int)filePosition - 1] : null;
                var metadataCompressedSize = metadata?.CompressedSize ?? entry.CompressedLength;
                var metadataOriginalSize = metadata?.OriginalSize ?? entry.Length;
                var metadataEncrypted = metadata?.Encrypted;
                var metadataCrc = metadata?.Crc32;
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
                    if (!options.CollectAllMatches) return results;
                }

                if (entry.Length < 0 || entry.Length > options.Limits.MaxFileSize) continue;
                if (entry.CompressedLength > 0 && entry.Length > (long)entry.CompressedLength * Math.Max(1, options.Limits.MaxArchiveCompressionRatio))
                    continue;
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
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;

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
                    if (!options.CollectAllMatches) return results;
                }

                if (!item.CanExtract || item.IsDirectory || item.Encrypted == true) continue;
                if (item.Size < 0 || item.Size > options.Limits.MaxFileSize) continue;
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
            if (size < 0 || size > options.Limits.MaxFileSize) break;
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
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;
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
                        if (!options.CollectAllMatches)
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
                if (nameSize <= 0 || nameSize > 16 * 1024 * 1024 || fileSize > (ulong)options.Limits.MaxFileSize) break;
                var nameStart = offset + 110;
                var nameEnd = checked((long)nameStart + (long)nameSize);
                var dataStart = Align4(nameEnd);
                var dataEnd = checked(dataStart + (long)fileSize);
                if (nameEnd > data.Length || dataEnd > data.Length) break;
                var name = ReadCString(data.Slice(nameStart, (int)nameSize));
                offset = Align4((int)dataEnd);
                if (name == "TRAILER!!!") break;
                if (name.Length == 0) continue;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;
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
                    if (!options.CollectAllMatches)
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
                if (nameSize <= 0 || nameSize > 16 * 1024 * 1024 || fileSize < 0 || fileSize > options.Limits.MaxFileSize) break;
                var nameStart = checked(offset + 76);
                var nameEnd = checked((long)nameStart + nameSize);
                var dataStart = (nameEnd + 1) & ~1L;
                var dataEnd = checked(dataStart + fileSize);
                if (nameEnd > data.Length || dataEnd > data.Length) break;
                var name = ReadCString(data.Slice(nameStart, (int)nameSize));
                offset = checked((int)((dataEnd + 1) & ~1L));
                if (name == "TRAILER!!!") break;
                if (name.Length == 0) continue;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;
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
                    if (!options.CollectAllMatches)
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
                if (nameSize == 0 || fileSize > (uint)options.Limits.MaxFileSize) break;
                var nameStart = checked(offset + 26);
                var nameEnd = checked((long)nameStart + nameSize);
                var dataStart = (nameEnd + 1) & ~1L;
                var dataEnd = checked(dataStart + fileSize);
                if (nameEnd > data.Length || dataEnd > data.Length || dataEnd > int.MaxValue) break;
                var name = ReadCString(data.Slice(nameStart, nameSize));
                offset = checked((int)((dataEnd + 1) & ~1L));
                if (name == "TRAILER!!!") break;
                if (name.Length == 0) continue;
                if (budget.Entries++ >= options.Limits.MaxArchiveEntries) break;
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
                    if (!options.CollectAllMatches)
                        return results;
                }
                var child = data.Slice((int)dataStart, checked((int)fileSize)).ToArray();
                if (!ConsumeBudget(budget, options.Limits, child.Length)) break;
                results.AddRange(ScanChild(child, name, format, state, options, parents, depth, budget, cancellationToken));
            }
        }
        return results;
    }

    private static List<Detection> ScanOle2(
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

            if (!ConsumeBudget(budget, options.Limits, child.Length)) break;
            results.AddRange(ScanChild(child, stream.Name, "OLE2", state, options, parents, depth, budget, cancellationToken));
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

    private static List<Detection> ScanRtfEmbeddedObjects(
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

                var hex = HexNibble(b);
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
                if (!ConsumeBudget(budget, options.Limits, decoded.Length))
                    break;

                var child = decoded.ToArray();
                results.AddRange(ScanChild(
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

    private static List<Detection> ScanBinHex(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        var marker = "(This file must be converted with BinHex 4.0)"u8;
        var markerPos = data.IndexOf(marker);
        if (markerPos < 0) return results;
        var colonRel = data[(markerPos + marker.Length)..].IndexOf((byte)':');
        if (colonRel < 0) return results;
        var colon = markerPos + marker.Length + colonRel;
        const string alphabet = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        var reverse = new sbyte[128];
        Array.Fill(reverse, (sbyte)-1);
        for (var i = 0; i < alphabet.Length; i++) reverse[(byte)alphabet[i]] = (sbyte)i;
        using var decoded = new MemoryStream();
        uint acc = 0; var bits = 0; var rle = false; byte last = 0;
        for (var i = colon + 1; i < data.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ch = data[i];
            if (ch == (byte)':') break;
            if (ch is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') continue;
            if (ch >= 128 || reverse[ch] < 0) return results;
            acc = (acc << 6) | (uint)(byte)reverse[ch]; bits += 6;
            while (bits >= 8)
            {
                bits -= 8; var value = (byte)((acc >> bits) & 0xff);
                if (rle) {
                    rle = false;
                    if (value == 0) { decoded.WriteByte(0x90); last = 0x90; }
                    else { var repeat = value - 1; if (repeat > options.Limits.MaxEmbeddedStreamSize - decoded.Length) return results; for (var n = 0; n < repeat; n++) decoded.WriteByte(last); }
                }
                else if (value == 0x90) rle = true;
                else { decoded.WriteByte(value); last = value; }
                if (decoded.Length > options.Limits.MaxEmbeddedStreamSize || decoded.Length > options.Limits.MaxFileSize) return results;
            }
        }
        var raw = decoded.ToArray();
        if (raw.Length < 20) return results;
        var nameLen = raw[0];
        var headerLen = 1 + nameLen + 1 + 4 + 4 + 2 + 4 + 4 + 2;
        if (raw.Length < headerLen) return results;
        var lenOffset = 1 + nameLen + 1 + 4 + 4 + 2;
        var dataLen = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(lenOffset, 4));
        var resLen = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(lenOffset + 4, 4));
        var dataStart = headerLen;
        if ((ulong)dataStart + dataLen + 2UL > (ulong)raw.Length) return results;
        var name = nameLen == 0 ? "binhex-data" : Encoding.ASCII.GetString(raw, 1, nameLen);
        var dataCount = (int)Math.Min((ulong)dataLen, (ulong)options.Limits.MaxFileSize);
        if (dataCount > 0) { var fork = raw.AsSpan(dataStart, dataCount).ToArray(); if (ConsumeBudget(budget, options.Limits, fork.Length)) results.AddRange(ScanChild(fork, name, "BINHEX", state, options, parents, depth, budget, cancellationToken)); }
        var resourceStart = dataStart + (int)dataLen + 2;
        if ((ulong)resourceStart + resLen + 2UL <= (ulong)raw.Length && resLen > 0 && resLen <= (uint)options.Limits.MaxEmbeddedStreamSize) { var fork = raw.AsSpan(resourceStart, (int)resLen).ToArray(); if (ConsumeBudget(budget, options.Limits, fork.Length)) results.AddRange(ScanChild(fork, name + ".rsrc", "BINHEX", state, options, parents, depth, budget, cancellationToken)); }
        return results;
    }

    private static List<Detection> ScanUuEncoded(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>(); var text = Encoding.ASCII.GetString(data); using var output = new MemoryStream(); string? fileName = null; var started = false;
        foreach (var rawLine in text.Split('\n'))
        {
            cancellationToken.ThrowIfCancellationRequested(); var line = rawLine.TrimEnd('\r');
            if (!started) { if (!line.StartsWith("begin ", StringComparison.Ordinal)) continue; var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries); if (parts.Length < 3) return results; fileName = parts[2]; started = true; continue; }
            if (line.Equals("end", StringComparison.OrdinalIgnoreCase)) break; if (line.Length == 0) continue;
            var expected = (line[0] - ' ') & 0x3f; if (expected == 0) continue; var i = 1; var produced = 0;
            while (i + 3 < line.Length && produced < expected) { var c0=UuValue(line[i++]); var c1=UuValue(line[i++]); var c2=UuValue(line[i++]); var c3=UuValue(line[i++]); if (produced < expected) { output.WriteByte((byte)((c0<<2)|(c1>>4))); produced++; } if (produced < expected) { output.WriteByte((byte)((c1<<4)|(c2>>2))); produced++; } if (produced < expected) { output.WriteByte((byte)((c2<<6)|c3)); produced++; } if (output.Length > options.Limits.MaxFileSize || output.Length > options.Limits.MaxEmbeddedStreamSize) return results; }
            if (produced != expected) break;
        }
        if (!started || output.Length == 0) return results; var child = output.ToArray(); if (!ConsumeBudget(budget, options.Limits, child.Length)) return results;
        results.AddRange(ScanChild(child, fileName ?? "uuencoded", "UUENCODED", state, options, parents, depth, budget, cancellationToken)); return results;
    }

    private static int UuValue(char c) => c < ' ' || c > '`' ? 0 : (c - ' ') & 0x3f;

    private static List<Detection> ScanTnef(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>(); if (data.Length < 6 || BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) != 0x223E9F78u) return results;
        var pos = 6; MemoryStream? attachment = null; string? attachmentName = null;
        void FlushAttachment() { if (attachment is null || attachment.Length == 0) return; var child=attachment.ToArray(); if (ConsumeBudget(budget, options.Limits, child.Length)) results.AddRange(ScanChild(child, attachmentName ?? "tnef-attachment", "TNEF", state, options, parents, depth, budget, cancellationToken)); attachment.Dispose(); attachment=null; attachmentName=null; }
        while (pos + 11 <= data.Length && budget.Entries < options.Limits.MaxArchiveEntries)
        {
            cancellationToken.ThrowIfCancellationRequested(); var level=data[pos++]; var typeTag=BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos,4)); pos+=4; var tag=(ushort)(typeTag & 0xffff); var length=BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos,4)); pos+=4;
            if (length < 0 || length > options.Limits.MaxFileSize || pos + (long)length + 2 > data.Length) break; var value=data.Slice(pos,length); pos += length + 2;
            if (level==2 && tag==0x800f) { attachment ??= new MemoryStream(); if (attachment.Length + value.Length > options.Limits.MaxEmbeddedStreamSize) { FlushAttachment(); continue; } attachment.Write(value); }
            else if (level==2 && tag==0x8010) { if (attachment is not null && attachment.Length > 0 && attachmentName is not null) FlushAttachment(); attachmentName=Encoding.ASCII.GetString(value).TrimEnd('\0',' ','\r','\n'); }
        }
        FlushAttachment(); return results;
    }

    private static List<Detection> ScanMimeMail(
        ReadOnlySpan<byte> data, string mailType, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (depth >= Math.Max(1, options.Limits.MaxArchiveDepth) || data.Length == 0) return results;
        var text = Encoding.Latin1.GetString(data);
        var headerEnd = FindHeaderEnd(text);
        if (headerEnd < 0) return results;
        var headers = text[..headerEnd];
        var bodyStart = headerEnd;
        while (bodyStart < text.Length && (text[bodyStart] == '\r' || text[bodyStart] == '\n')) bodyStart++;

        var contentType = GetHeader(headers, "Content-Type");
        var boundary = GetBoundary(contentType);
        if (string.IsNullOrWhiteSpace(boundary)) return results;

        var body = text[bodyStart..];
        var marker = "--" + boundary;
        var search = 0;
        while (search < body.Length && budget.Entries < options.Limits.MaxArchiveEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var start = body.IndexOf(marker, search, StringComparison.Ordinal);
            if (start < 0) break;
            start += marker.Length;
            if (start + 2 <= body.Length && body[start..].StartsWith("--", StringComparison.Ordinal)) break;
            while (start < body.Length && body[start] is '\r' or '\n' or ' ') start++;
            var partEndMarker = body.IndexOf(marker, start, StringComparison.Ordinal);
            if (partEndMarker < 0) partEndMarker = body.Length;
            var part = body[start..partEndMarker].TrimStart('\r', '\n');
            var partHeaderEnd = FindHeaderEnd(part);
            if (partHeaderEnd < 0) { search = partEndMarker + marker.Length; continue; }
            var partHeaders = part[..partHeaderEnd];
            var partBodyStart = partHeaderEnd;
            while (partBodyStart < part.Length && (part[partBodyStart] == '\r' || part[partBodyStart] == '\n')) partBodyStart++;
            var rawPartBody = part[partBodyStart..].TrimEnd('\r', '\n');
            var decoded = DecodeMimeBody(rawPartBody, GetHeader(partHeaders, "Content-Transfer-Encoding"), options.Limits.MaxEmbeddedStreamSize);
            if (decoded is not null && decoded.Length != 0)
            {
                if (!ConsumeBudget(budget, options.Limits, decoded.Length)) break;
                budget.Entries++;
                var childName = GetMimeFilename(partHeaders) ?? (mailType == "MHTML" ? "mhtml-part" : "mail-part");
                results.AddRange(ScanChild(decoded, childName, mailType, state, options, parents, depth, budget, cancellationToken));
            }
            search = partEndMarker + marker.Length;
        }
        return results;
    }

    private static int FindHeaderEnd(string text)
    {
        var crlf = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var lf = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (crlf < 0) return lf < 0 ? -1 : lf;
        return lf < 0 ? crlf : Math.Min(crlf, lf);
    }

    private static string? GetHeader(string headers, string name)
    {
        var lines = headers.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        string? current = null;
        var value = new StringBuilder();
        foreach (var raw in lines)
        {
            if (raw.Length != 0 && char.IsWhiteSpace(raw[0]) && current is not null)
            {
                value.Append(' ').Append(raw.Trim());
                continue;
            }
            var colon = raw.IndexOf(':');
            if (colon <= 0) { current = null; continue; }
            current = raw[..colon].Trim();
            if (current.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                value.Clear();
                value.Append(raw[(colon + 1)..].Trim());
            }
        }
        return value.Length == 0 ? null : value.ToString();
    }

    private static string? GetBoundary(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return null;
        var marker = "boundary=";
        var at = contentType.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        var value = contentType[(at + marker.Length)..].Trim();
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"') value = value[1..^1];
        var semi = value.IndexOf(';');
        return (semi >= 0 ? value[..semi] : value).Trim();
    }

    private static string? GetMimeFilename(string headers)
    {
        foreach (var header in new[] { "Content-Disposition", "Content-Type" })
        {
            var value = GetHeader(headers, header);
            if (value is null) continue;
            foreach (var key in new[] { "filename=", "name=" })
            {
                var at = value.IndexOf(key, StringComparison.OrdinalIgnoreCase);
                if (at < 0) continue;
                var name = value[(at + key.Length)..].Trim();
                if (name.Length >= 2 && name[0] == '"' && name[^1] == '"') name = name[1..^1];
                var semi = name.IndexOf(';');
                if (semi >= 0) name = name[..semi];
                if (name.Length > 0) return name.Trim();
            }
        }
        return null;
    }

    private static byte[]? DecodeMimeBody(string body, string? transferEncoding, long maxBytes)
    {
        try
        {
            if (transferEncoding?.Trim().Equals("base64", StringComparison.OrdinalIgnoreCase) == true)
            {
                var normalized = new string(body.Where(static c => !char.IsWhiteSpace(c)).ToArray());
                if (normalized.Length > ((maxBytes + 2) / 3) * 4 + 4) return null;
                return Convert.FromBase64String(normalized);
            }
            if (transferEncoding?.Trim().Equals("quoted-printable", StringComparison.OrdinalIgnoreCase) == true)
                return DecodeQuotedPrintable(body, maxBytes);
            var raw = Encoding.Latin1.GetBytes(body);
            return raw.LongLength <= maxBytes ? raw : null;
        }
        catch (FormatException) { return null; }
        catch (OverflowException) { return null; }
    }

    private static byte[]? DecodeQuotedPrintable(string body, long maxBytes)
    {
        using var output = new MemoryStream();
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c == '=')
            {
                if (i + 2 < body.Length && body[i + 1] == '\r' && body[i + 2] == '\n') { i += 2; continue; }
                if (i + 2 < body.Length && body[i + 1] == '\n') { i += 1; continue; }
                if (i + 2 < body.Length)
                {
                    var hi = HexNibble((byte)body[i + 1]);
                    var lo = HexNibble((byte)body[i + 2]);
                    if (hi >= 0 && lo >= 0) { output.WriteByte((byte)((hi << 4) | lo)); i += 2; if (output.Length > maxBytes) return null; continue; }
                }
            }
            output.WriteByte((byte)c);
            if (output.Length > maxBytes) return null;
        }
        return output.ToArray();
    }

    private static List<Detection> ScanFlash(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (data.Length < 8) return results;
        if (data[..3].SequenceEqual("FWS"u8)) return results;
        if (data[..3].SequenceEqual("ZWS"u8)) return results; // LZMA SWF requires a dedicated decoder; keep type detection intact.
        if (!data[..3].SequenceEqual("CWS"u8)) return results;

        var advertised = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        var wanted = advertised >= 8 ? advertised - 8u : 0u;
        if (wanted == 0 || wanted > options.Limits.MaxFileSize || wanted > int.MaxValue || data.Length <= 8) return results;

        try
        {
            using var source = new MemoryStream(data.Slice(8).ToArray(), writable: false);
            using var zlib = new ZLibStream(source, CompressionMode.Decompress, leaveOpen: false);
            var decodedBody = ReadLimited(zlib, Math.Min(wanted, options.Limits.MaxFileSize));
            if (decodedBody.Length == 0) return results;
            if (!ConsumeBudget(budget, options.Limits, decodedBody.Length)) return results;
            budget.Entries++;
            // Scan the reconstructed SWF as a FLASH child so Target:11 / Container:SWF
            // signatures can operate on the uncompressed tag stream.
            using var rebuilt = new MemoryStream(decodedBody.Length + 8);
            rebuilt.Write("FWS"u8);
            rebuilt.WriteByte(data[3]);
            rebuilt.Write(data.Slice(4, 4));
            rebuilt.Write(decodedBody);
            results.AddRange(ScanChild(rebuilt.ToArray(), "decompressed.swf", "FLASH", state, options, parents, depth, budget, cancellationToken));
        }
        catch (InvalidDataException) { }
        catch (IOException) { }
        return results;
    }

    private static List<Detection> ScanPdfEmbeddedStreams(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        var ascii = Encoding.ASCII.GetString(data);
        var search = 0;
        while (search < ascii.Length && budget.Entries < options.Limits.MaxArchiveEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var streamPos = ascii.IndexOf("stream", search, StringComparison.Ordinal);
            if (streamPos < 0) break;
            var endMarker = ascii.IndexOf("endstream", streamPos + 6, StringComparison.Ordinal);
            if (endMarker < 0) break;
            var lineEnd = streamPos + 6;
            if (lineEnd < ascii.Length && ascii[lineEnd] == '\r') lineEnd++;
            if (lineEnd < ascii.Length && ascii[lineEnd] == '\n') lineEnd++;
            var dictStart = ascii.LastIndexOf("<<", streamPos, StringComparison.Ordinal);
            var dictEnd = dictStart >= 0 ? ascii.IndexOf(">>", dictStart + 2, StringComparison.Ordinal) : -1;
            if (dictStart < 0 || dictEnd < 0 || dictEnd > streamPos)
            {
                search = endMarker + 9;
                continue;
            }

            var dictionary = ascii[dictStart..dictEnd];
            var filters = ParsePdfFilters(dictionary);
            if (filters.Count == 0)
            {
                search = endMarker + 9;
                continue;
            }

            var length = TryReadPdfLength(dictionary);
            var available = endMarker - lineEnd;
            if (available <= 0 || available > options.Limits.MaxEmbeddedStreamSize) { search = endMarker + 9; continue; }
            var take = length is >= 0 and <= int.MaxValue ? Math.Min(length.Value, available) : available;
            if (take <= 0 || take > options.Limits.MaxEmbeddedStreamSize) { search = endMarker + 9; continue; }

            var compressed = data.Slice(lineEnd, (int)take).ToArray();
            var earlyChange = TryReadPdfEarlyChange(dictionary);
            if (!TryDecodePdfFilters(compressed, filters, options.Limits.MaxFileSize, earlyChange, out var child))
            {
                search = endMarker + 9;
                continue;
            }
            if (!ConsumeBudget(budget, options.Limits, child.Length)) break;
            budget.Entries++;
            results.AddRange(ScanChild(child, "embedded-stream", "PDF", state, options, parents, depth, budget, cancellationToken));
            search = endMarker + 9;
        }
        return results;
    }

    private static IReadOnlyList<string> ParsePdfFilters(string dictionary)
    {
        var marker = dictionary.IndexOf("/Filter", StringComparison.Ordinal);
        if (marker < 0) return [];
        var tail = dictionary[(marker + 7)..].TrimStart();
        var filters = new List<string>();

        if (tail.StartsWith("[", StringComparison.Ordinal))
        {
            var close = tail.IndexOf(']');
            if (close < 0) return [];
            tail = tail[1..close];
            var i = 0;
            while (i < tail.Length)
            {
                if (tail[i] != '/') { i++; continue; }
                i++;
                var start = i;
                while (i < tail.Length && (char.IsLetterOrDigit(tail[i]) || tail[i] is '#')) i++;
                if (i > start) filters.Add(tail[start..i]);
            }
            return filters;
        }

        if (!tail.StartsWith("/", StringComparison.Ordinal)) return [];
        var first = 1;
        while (first < tail.Length && (char.IsLetterOrDigit(tail[first]) || tail[first] is '#')) first++;
        return first > 1 ? [tail[1..first]] : [];
    }

    private static int TryReadPdfEarlyChange(string dictionary)
    {
        var marker = dictionary.IndexOf("/EarlyChange", StringComparison.Ordinal);
        if (marker < 0) return 1; // PDF default, matching ClamAV's default.

        var i = marker + "/EarlyChange".Length;
        while (i < dictionary.Length && char.IsWhiteSpace(dictionary[i])) i++;
        var start = i;
        if (i < dictionary.Length && dictionary[i] is '+' or '-') i++;
        while (i < dictionary.Length && char.IsDigit(dictionary[i])) i++;
        if (i <= start || !int.TryParse(dictionary[start..i], out var value))
            return 1;
        return value == 0 ? 0 : 1;
    }

    private static bool TryDecodePdfFilters(
        byte[] input,
        IReadOnlyList<string> filters,
        long maxOutput,
        int earlyChange,
        out byte[] output)
    {
        output = input;
        foreach (var filter in filters)
        {
            try
            {
                output = filter switch
                {
                    "FlateDecode" or "Fl" => DecodeFlate(output, maxOutput),
                    "ASCIIHexDecode" or "AHx" => DecodeAsciiHex(output, maxOutput),
                    "ASCII85Decode" or "A85" => DecodeAscii85(output, maxOutput),
                    "RunLengthDecode" or "RL" => DecodeRunLength(output, maxOutput),
                    "LZWDecode" or "LZW" => DecodeLzw(output, maxOutput, earlyChange),
                    _ => throw new InvalidDataException("Unsupported PDF filter.")
                };
            }
            catch (InvalidDataException)
            {
                return false;
            }
            catch (OverflowException)
            {
                return false;
            }
            if (output.LongLength > maxOutput) return false;
        }
        return true;
    }

    private static byte[] DecodeFlate(byte[] input, long maxOutput)
    {
        using var source = new MemoryStream(input, writable: false);
        try
        {
            using var decoder = new ZLibStream(source, CompressionMode.Decompress, leaveOpen: false);
            return ReadLimited(decoder, maxOutput);
        }
        catch (InvalidDataException)
        {
            source.Position = 0;
            using var raw = new DeflateStream(source, CompressionMode.Decompress, leaveOpen: false);
            return ReadLimited(raw, maxOutput);
        }
    }

    private static byte[] DecodeAsciiHex(byte[] input, long maxOutput)
    {
        using var output = new MemoryStream();
        var haveHigh = false;
        byte high = 0;
        foreach (var b in input)
        {
            if (b == (byte)'>') break;
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)'\f' or (byte)'\0') continue;
            var nibble = HexNibble(b);
            if (nibble < 0) throw new InvalidDataException("Invalid PDF ASCIIHex data.");
            if (!haveHigh) { high = (byte)nibble; haveHigh = true; }
            else
            {
                output.WriteByte((byte)((high << 4) | nibble));
                haveHigh = false;
                if (output.Length > maxOutput) throw new InvalidDataException("PDF stream exceeded limit.");
            }
        }
        if (haveHigh)
        {
            output.WriteByte((byte)(high << 4));
            if (output.Length > maxOutput) throw new InvalidDataException("PDF stream exceeded limit.");
        }
        return output.ToArray();
    }

    private static byte[] DecodeAscii85(byte[] input, long maxOutput)
    {
        using var output = new MemoryStream();
        uint tuple = 0;
        var count = 0;
        for (var i = 0; i < input.Length; i++)
        {
            var b = input[i];
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)'\f') continue;
            if (b == (byte)'~') break;
            if (b == (byte)'z' && count == 0)
            {
                WriteBigEndian(output, 0, 4, maxOutput);
                continue;
            }
            if (b < 33 || b > 117) throw new InvalidDataException("Invalid PDF ASCII85 data.");
            tuple = checked(tuple * 85 + (uint)(b - 33));
            count++;
            if (count == 5)
            {
                WriteBigEndian(output, tuple, 4, maxOutput);
                tuple = 0;
                count = 0;
            }
        }
        if (count is > 1 and < 5)
        {
            for (var i = count; i < 5; i++) tuple = checked(tuple * 85 + 84);
            WriteBigEndian(output, tuple, count - 1, maxOutput);
        }
        return output.ToArray();
    }

    private static byte[] DecodeRunLength(byte[] input, long maxOutput)
    {
        using var output = new MemoryStream();
        var i = 0;
        while (i < input.Length)
        {
            var length = input[i++];
            if (length == 128) break;
            if (length <= 127)
            {
                var count = length + 1;
                if (i > input.Length - count) throw new InvalidDataException("Invalid PDF RunLength data.");
                if (output.Length > maxOutput - count) throw new InvalidDataException("PDF stream exceeded limit.");
                output.Write(input, i, count);
                i += count;
            }
            else
            {
                var count = 257 - length;
                if (i >= input.Length) throw new InvalidDataException("Invalid PDF RunLength data.");
                if (output.Length > maxOutput - count) throw new InvalidDataException("PDF stream exceeded limit.");
                for (var n = 0; n < count; n++) output.WriteByte(input[i]);
                i++;
            }
        }
        return output.ToArray();
    }

    private static byte[] DecodeLzw(byte[] input, long maxOutput, int earlyChange)
    {
        if (input.Length == 0) return [];

        const int clearCode = 256;
        const int endCode = 257;
        const int firstCode = 258;
        const int maxCodes = 4096;

        var prefix = new short[maxCodes];
        var suffix = new byte[maxCodes];
        var stack = new byte[maxCodes];
        using var output = new MemoryStream();

        var codeSize = 9;
        var nextCode = firstCode;
        var previousCode = -1;

        ulong bitBuffer = 0;
        var bitCount = 0;
        var inputIndex = 0;

        int ReadCode()
        {
            while (bitCount < codeSize && inputIndex < input.Length)
            {
                bitBuffer = (bitBuffer << 8) | input[inputIndex++];
                bitCount += 8;
            }

            if (bitCount < codeSize)
                return -1;

            bitCount -= codeSize;
            var code = (int)((bitBuffer >> bitCount) & ((1UL << codeSize) - 1UL));
            if (bitCount == 0)
                bitBuffer = 0;
            else
                bitBuffer &= (1UL << bitCount) - 1UL;
            return code;
        }

        int EmitCode(int code, out byte firstByte)
        {
            firstByte = 0;
            var top = 0;
            var current = code;

            while (current >= firstCode)
            {
                if ((uint)current >= maxCodes || top >= stack.Length)
                    return -1;
                stack[top++] = suffix[current];
                current = prefix[current];
            }

            if ((uint)current > 255)
                return -1;

            stack[top++] = (byte)current;
            firstByte = stack[top - 1];

            for (var i = top - 1; i >= 0; i--)
            {
                if (output.Length >= maxOutput)
                    return -1;
                output.WriteByte(stack[i]);
            }
            return top;
        }

        while (true)
        {
            var code = ReadCode();
            if (code < 0) break;

            if (code == clearCode)
            {
                codeSize = 9;
                nextCode = firstCode;
                previousCode = -1;
                continue;
            }

            if (code == endCode)
                break;

            if (code > 4095)
                throw new InvalidDataException("Invalid PDF LZW code.");

            var currentCode = code;
            byte firstByte;

            if (code == nextCode)
            {
                if (previousCode < 0)
                    throw new InvalidDataException("Invalid first PDF LZW code.");
                var emitted = EmitCode(previousCode, out firstByte);
                if (emitted < 0) throw new InvalidDataException("Invalid PDF LZW dictionary.");
                if (output.Length >= maxOutput)
                    throw new InvalidDataException("PDF stream exceeded limit.");
                output.WriteByte(firstByte);
            }
            else
            {
                if (code < 0 || code >= nextCode && code >= firstCode)
                    throw new InvalidDataException("Invalid PDF LZW dictionary reference.");
                if (code >= nextCode)
                    throw new InvalidDataException("Invalid PDF LZW dictionary reference.");

                var emitted = EmitCode(currentCode, out firstByte);
                if (emitted < 0) throw new InvalidDataException("Invalid PDF LZW dictionary.");
            }

            if (previousCode >= 0)
            {
                if (nextCode < maxCodes)
                {
                    prefix[nextCode] = (short)previousCode;
                    suffix[nextCode] = firstByte;
                    nextCode++;

                    var threshold = (1 << codeSize) - earlyChange;
                    if (codeSize < 12 && nextCode >= threshold)
                        codeSize++;
                }
            }

            previousCode = currentCode;
        }

        return output.ToArray();
    }

    private static void WriteBigEndian(Stream output, uint value, int count, long maxOutput)
    {
        if (output.Length > maxOutput - count) throw new InvalidDataException("PDF stream exceeded limit.");
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        output.Write(buffer[..count]);
    }

    private static int HexNibble(byte value)
        => value is >= (byte)'0' and <= (byte)'9' ? value - '0' :
           value is >= (byte)'A' and <= (byte)'F' ? value - 'A' + 10 :
           value is >= (byte)'a' and <= (byte)'f' ? value - 'a' + 10 : -1;

    private static byte[] ReadLimited(Stream input, long maxBytes)
    {
        using var output = new MemoryStream((int)Math.Min(maxBytes, 4L * 1024 * 1024));
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            if (output.Length > maxBytes - read) throw new InvalidDataException("Decoded stream exceeded limit.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static List<Detection> ScanChild(
        byte[] child,
        string childPath,
        string parentType,
        CompiledState state,
        ScanOptions options,
        IReadOnlyList<string> parents,
        int depth,
        ArchiveScanBudget budget,
        CancellationToken cancellationToken)
    {
        // ClamAV cli_check_fp()/cli_trust_layers() verifies each recursion layer.
        // When the embedded object's whole-file hash matches .fp/.sfp, suppress all
        // evidence for that layer and do not descend into its contents.
        if (state.Compiled.MatchesFalsePositive(child))
            return [];

        var type = ScannerEngine.DetectType(child, childPath, state.Database.SpecialDatabases.FileTypes);
        var results = new List<Detection>();
        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        var childParents = parents.Concat([parentType]).ToArray();

        if (ScanTypePolicy.RequiresSpecializedPreRaw(type))
        {
            results.AddRange(SpecializedFileHandlers.ScanPreRaw(child, type, state, options, childPath, cancellationToken));
            if (!options.CollectAllMatches && results.Count != 0)
                return [results[0]];
        }

        // Match ClamAV's layer ordering: container/document parsing happens before
        // the ordinary raw scan. Executables remain raw-first in the specialized
        // path below. The child is already materialized, so parser-first avoids an
        // otherwise duplicate read and preserves FTM-selected handler types.
        if (ScanTypePolicy.IsArchiveContainer(type) &&
            depth + 1 < options.Limits.MaxArchiveDepth &&
            budget.Entries < options.Limits.MaxArchiveEntries)
        {
            results.AddRange(ScanInternal(child, childPath, state, options, childParents, depth + 1, budget, cancellationToken, type));
            if (!options.CollectAllMatches && results.Count != 0)
                return [results[0]];
        }

        results.AddRange(state.Compiled.Match(child, "compiled-database", includeNdb: false, collectAllMatches: options.CollectAllMatches));
        if (!options.CollectAllMatches && results.Count != 0)
            return [results[0]];

        results.AddRange(ScannerEngine.EvaluateNdb(ndb, child, options.Limits, type, cancellationToken));
        if (!options.CollectAllMatches && results.Count != 0)
            return [results[0]];

        results.AddRange(ScannerEngine.EvaluateLogical(
            state.Database.Signatures.OfType<LogicalSignature>(),
            ndb,
            child,
            options.Limits,
            type,
            state.Database.IconDatabase,
            childParents,
            cancellationToken,
            scanState: state,
            scanOptions: options));
        if (!options.CollectAllMatches && results.Count != 0)
            return [results[0]];

        if (ScanTypePolicy.IsPe(type))
        {
            results.AddRange(PeSpecializedMatcher.Match(child, state, options.Limits, cancellationToken));
            if (!options.CollectAllMatches && results.Count != 0)
                return [results[0]];
        }
        foreach (var contentScanner in options.ContentScanners)
        {
            results.AddRange(contentScanner.Scan(child, childPath, cancellationToken));
            if (!options.CollectAllMatches && results.Count != 0)
                return [results[0]];
        }

        return results;
    }

    private static string? DetectContainerType(ReadOnlySpan<byte> data, string path)
    {
        if (data.Length >= 8 && data[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return "OLE2";
        if (data.Length >= 3 && (data[..3].SequenceEqual("FWS"u8) || data[..3].SequenceEqual("CWS"u8) || data[..3].SequenceEqual("ZWS"u8))) return "FLASH";
        if (data.IndexOf("BEA01"u8) is var udfPos && udfPos >= 0 && udfPos <= 32768) return "UDF";
        if (data.Length >= 5 && data[..5].SequenceEqual("{\\rtf"u8)) return "RTF";
        if (data.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) == 0x223E9F78u) return "TNEF";
        if (LooksLikeAutoIt(data)) return "AUTOIT";
        if (LooksLikeInstallShield(data)) return "ISHIELD_MSI";
        if (data.Length >= 6 && data[..6].SequenceEqual("begin "u8)) return "UUENCODED";
        if (data.IndexOf("(This file must be converted with BinHex 4.0)"u8) >= 0) return "BINHEX";
        var mime = DetectMimeType(data);
        if (mime is not null) return mime;
        if (data.Length >= 4 && data[..4].SequenceEqual(new byte[] { 0x50, 0x4B, 0x03, 0x04 })) return "ZIP";
        if (data.Length >= 4 && (data[..4].SequenceEqual(new byte[] { 0x50, 0x4B, 0x05, 0x06 }) || data[..4].SequenceEqual(new byte[] { 0x50, 0x4B, 0x07, 0x08 }))) return "ZIP";
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B) return "GZ";
        if (data.Length >= 6 && (data[..6].SequenceEqual("070701"u8) || data[..6].SequenceEqual("070702"u8))) return data[5] == (byte)'2' ? "CPIO_CRC" : "CPIO_NEWC";
        if (data.Length >= 6 && data[..6].SequenceEqual("070707"u8)) return "CPIO_ODC";
        if (data.Length >= 2 && ((data[0] == 0xC7 && data[1] == 0x71) || (data[0] == 0x71 && data[1] == 0xC7))) return "CPIO_OLD";
        if (data.Length >= 512 && data.Slice(257, 5).SequenceEqual("ustar"u8)) return "POSIX_TAR";
        if (data.Length >= 512 && LooksLikeTarHeader(data[..512])) return "OLD_TAR";
        if (data.Length >= 2 && data[0] == 0x60 && data[1] == 0xEA) return "ARJ";
        if (data.Length >= 6 && data[..4].SequenceEqual("EGGA"u8) &&
            data[4] == 0x00 && data[5] == 0x01) return "EGG";
        if (data.Length >= 4 && data[..4].SequenceEqual("ALZ\x01"u8)) return "ALZ";
        if (data.Length >= 16 && IsSymbianSisHeader(data)) return "SIS";
        if (data.Length >= 14 &&
            BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) == 0x44445A53 &&
            BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4)) == 0x3327F088 &&
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2)) == 0x0041) return "SZDD";
        if (data.Length >= 4 && data[..4].SequenceEqual("MSCF"u8)) return "CAB";
        if (data.Length >= 4 && data[..4].SequenceEqual("ITSF"u8)) return "CHM";
        if (data.Length >= 4 && data[..4].SequenceEqual("xar!"u8)) return "XAR";
        if (data.Length >= 32774 && data.Slice(32769, 5).SequenceEqual("CD001"u8)) return "ISO";
        if (LooksLikeDmg(data)) return "DMG";
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".swf" => "FLASH",
            ".eml" or ".msg" => "MAIL",
            ".mht" or ".mhtml" => "MHTML",
            ".a3x" or ".a3x64" or ".au3" => "AUTOIT",
            ".ism" or ".ish" => "ISHIELD_MSI",
            ".zip" or ".jar" or ".apk" or ".docx" or ".xlsx" or ".pptx" => "ZIP",
            ".gz" or ".tgz" => "GZ",
            ".bz2" or ".tbz" or ".tbz2" => "BZ",
            ".xz" or ".txz" => "XZ",
            ".rar" => "RAR",
            ".7z" => "7Z",
            ".egg" => "EGG",
            ".alz" => "ALZ",
            ".sis" => "SIS",
            ".nsis" or ".nsi" => "NULSFT",
            ".szdd" or ".cabinet" => "SZDD",
            ".arj" => "ARJ",
            ".cab" => "CAB",
            ".chm" => "CHM",
            ".iso" => "ISO",
            ".xar" or ".pkg" => "XAR",
            ".dmg" => "DMG",
            ".lha" or ".lzh" => "LHA",
            ".tar" => "POSIX_TAR",
            ".cpio" => "CPIO_NEWC",
            ".ole" or ".doc" or ".xls" or ".ppt" => "OLE2",
            ".rtf" => "RTF",
            ".hqx" => "BINHEX",
            ".tnef" => "TNEF",
            ".uue" or ".uu" => "UUENCODED",
            ".pdf" => "PDF",
            _ => null
        };
    }

    private static bool IsMachOMagic(uint magic)
        => magic is 0xCAFEBABEu or 0xBEBAFECAu or 0xCAFEBABFu or 0xBFBAFECAu or
                  0xFEEDFACEu or 0xCEFAEDFEu or 0xFEEDFACFu or 0xCFFAEDFEu;

    private static bool TryReadEntry(Stream input, long expectedLength, ScanLimits limits, ArchiveScanBudget budget, CancellationToken token, out byte[] child)
        => TryReadStream(input, Math.Min(expectedLength, limits.MaxFileSize), limits, budget, token, out child);

    private static bool TryReadStream(Stream input, long maxBytes, ScanLimits limits, ArchiveScanBudget budget, CancellationToken token, out byte[] child)
    {
        child = [];
        if (maxBytes < 0 || maxBytes > limits.MaxFileSize) return false;
        using var output = new MemoryStream((int)Math.Min(maxBytes, 4 * 1024 * 1024));
        var buffer = new byte[64 * 1024];
        long count = 0;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            count += read;
            if (count > maxBytes || count > limits.MaxFileSize) return false;
            output.Write(buffer, 0, read);
        }
        if (!ConsumeBudget(budget, limits, count)) return false;
        child = output.ToArray();
        return true;
    }

    private static bool ConsumeBudget(ArchiveScanBudget budget, ScanLimits limits, long bytes)
    {
        if (bytes < 0 || budget.ExpandedBytes > limits.MaxArchiveExpandedBytes - bytes) return false;
        budget.ExpandedBytes += bytes;
        return true;
    }

    internal static bool LooksLikeDmg(ReadOnlySpan<byte> data)
    {
        // UDIF images carry a "koly" trailer near EOF. Validate the trailer
        // location instead of classifying arbitrary files by a loose extension.
        if (data.Length < 512) return false;
        return data[^512..^508].SequenceEqual("koly"u8);
    }

    private static string? DetectMimeType(ReadOnlySpan<byte> data)
    {
        var sample = Encoding.Latin1.GetString(data[..Math.Min(data.Length, 64 * 1024)]);
        var headerEnd = FindHeaderEnd(sample);
        if (headerEnd < 0) headerEnd = Math.Min(sample.Length, 16 * 1024);
        var headers = sample[..headerEnd];
        var hasMime = headers.IndexOf("MIME-Version:", StringComparison.OrdinalIgnoreCase) >= 0;
        var hasContentType = headers.IndexOf("Content-Type:", StringComparison.OrdinalIgnoreCase) >= 0;
        var hasMailHeader = headers.IndexOf("From:", StringComparison.OrdinalIgnoreCase) >= 0 || headers.IndexOf("Received:", StringComparison.OrdinalIgnoreCase) >= 0;
        if (!hasContentType || (!hasMime && !hasMailHeader)) return null;
        return headers.IndexOf("multipart/related", StringComparison.OrdinalIgnoreCase) >= 0 ? "MHTML" : "MAIL";
    }

    private static bool LooksLikeAutoIt(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> magic = new byte[] { 0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D, 0x41, 0x55, 0x53, 0x21, 0x45, 0x41, 0x30 };
        for (var i = 0; i + magic.Length + 1 < data.Length; i++)
            if (data.Slice(i, magic.Length).SequenceEqual(magic) && data[i + magic.Length] is 0x35 or 0x36) return true;
        return false;
    }

    private static bool LooksLikeInstallShield(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> prefix = "InstallShield\0"u8;
        for (var i = 0; i + prefix.Length + 0x120 < data.Length; i++)
        {
            if (!data.Slice(i, prefix.Length).SequenceEqual(prefix)) continue;
            var p = i + prefix.Length + 292;
            if (p + 8 + 16 + 4 > data.Length) break;
            if (data[p] != 0x06 || !data.Slice(p + 1, 7).SequenceEqual(new byte[7])) continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(p + 24, 4)) == 1) return true;
        }
        return false;
    }

    private static bool LooksLikeTarHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < 512) return false;
        var name = ReadTarString(header[..100]);
        if (name.Length == 0) return false;
        var stored = ReadTarNumber(header.Slice(148, 8));
        if (stored <= 0) return false;
        var sum = 0L;
        for (var i = 0; i < 512; i++)
            sum += i is >= 148 and < 156 ? 32 : header[i];
        return sum == stored;
    }

    private static bool IsTarRegularFile(byte type) => type is 0 or (byte)'0' or 7;
    private static bool IsAllZero(ReadOnlySpan<byte> data) => data.IndexOfAnyExcept((byte)0) < 0;

    private static long ReadTarNumber(ReadOnlySpan<byte> field)
    {
        if (field.Length == 0) return -1;
        if ((field[0] & 0x80) != 0)
        {
            Span<byte> tmp = stackalloc byte[8];
            tmp.Clear();
            field[^Math.Min(8, field.Length)..].CopyTo(tmp[^Math.Min(8, field.Length)..]);
            tmp[0] &= 0x7f;
            return BinaryPrimitives.ReadInt64BigEndian(tmp);
        }
        long value = 0;
        var saw = false;
        foreach (var b in field)
        {
            if (b == 0 || b == (byte)' ' || b == (byte)'\0')
            {
                if (saw) break;
                continue;
            }
            if (b is < (byte)'0' or > (byte)'7') return -1;
            saw = true;
            value = checked(value * 8 + (b - (byte)'0'));
        }
        return saw ? value : 0;
    }

    private static string ReadTarString(ReadOnlySpan<byte> field)
    {
        var end = field.IndexOf((byte)0);
        if (end < 0) end = field.Length;
        return Encoding.UTF8.GetString(field[..end]).TrimEnd('/');
    }

    private static string? ParsePaxPath(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        foreach (var line in text.Split('\n'))
        {
            var sp = line.IndexOf(' ');
            var eq = line.IndexOf('=', sp + 1);
            if (sp > 0 && eq > sp && line[(sp + 1)..eq] == "path")
                return line[(eq + 1)..].TrimEnd('\0');
        }
        return null;
    }

    private static int Align4(long value) => checked((int)((value + 3) & ~3L));
    private static int Align4(int value) => checked((value + 3) & ~3);

    private static bool TryReadOctalField(ReadOnlySpan<byte> data, out long value)
    {
        value = 0;
        var saw = false;
        foreach (var b in data)
        {
            if (b is 0 or (byte)' ')
            {
                if (saw) break;
                continue;
            }
            if (b is < (byte)'0' or > (byte)'7') return false;
            saw = true;
            value = checked(value * 8 + b - (byte)'0');
        }
        return saw;
    }

    private static bool TryReadHex(ReadOnlySpan<byte> data, out ulong value)
        => ulong.TryParse(Encoding.ASCII.GetString(data), System.Globalization.NumberStyles.HexNumber, null, out value);

    private static string ReadCString(ReadOnlySpan<byte> data)
    {
        var end = data.IndexOf((byte)0);
        return Encoding.ASCII.GetString(end < 0 ? data : data[..end]);
    }

    private static long? TryReadPdfLength(string dictionary)
    {
        var marker = dictionary.IndexOf("/Length", StringComparison.Ordinal);
        if (marker < 0) return null;
        var tail = dictionary[(marker + 7)..].TrimStart();
        var digits = new StringBuilder();
        foreach (var c in tail)
        {
            if (!char.IsDigit(c)) break;
            digits.Append(c);
        }
        return digits.Length != 0 && long.TryParse(digits.ToString(), out var length) ? length : null;
    }

    private static bool LooksAscii(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return false;
        var printable = 0;
        foreach (var b in data)
        {
            if (b == 0) return false;
            if (b is >= 0x20 and <= 0x7e or 0x09 or 0x0a or 0x0d or 0x0c) printable++;
        }
        return printable >= data.Length * 0.9;
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
