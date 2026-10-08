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
        // ClamAV scan_layer dispatches each format parser only when the module's
        // dconf flag is enabled for the engine flevel (e.g. ARCH_CONF_ZIP, DOC_CONF_PDF).
        var dconf = state.Database.DynamicConfiguration;
        return type switch
        {
            "ZIP" when (dconf.Archive & DynamicConfigFlags.ArchiveZip) != 0 => ScanZip(data, state, options, parents, depth, budget, cancellationToken),
            "GZ" when (dconf.Archive & DynamicConfigFlags.ArchiveGz) != 0 => ScanGzip(data, state, options, parents, depth, budget, cancellationToken),
            "BZ" when (dconf.Archive & DynamicConfigFlags.ArchiveBz) != 0 => ScanSingleExternalCodec(data, "BZ", state, options, parents, depth, budget, cancellationToken),
            "XZ" when (dconf.Archive & DynamicConfigFlags.ArchiveXz) != 0 => ScanSingleExternalCodec(data, "XZ", state, options, parents, depth, budget, cancellationToken),
            "RAR" when (dconf.Archive & DynamicConfigFlags.ArchiveRar) != 0 => ScanExternalArchive(data, "RAR", state, options, parents, depth, budget, cancellationToken),
            "7Z" when (dconf.Archive & DynamicConfigFlags.ArchiveSevenZip) != 0 => ScanExternalArchive(data, "7Z", state, options, parents, depth, budget, cancellationToken),
            "ARJ" when (dconf.Archive & DynamicConfigFlags.ArchiveArj) != 0 => ScanExternalArchive(data, "ARJ", state, options, parents, depth, budget, cancellationToken),
            "CAB" when (dconf.Archive & DynamicConfigFlags.ArchiveCab) != 0 => ScanExternalArchive(data, "CAB", state, options, parents, depth, budget, cancellationToken),
            "CHM" when (dconf.Archive & DynamicConfigFlags.ArchiveChm) != 0 => ScanExternalArchive(data, "CHM", state, options, parents, depth, budget, cancellationToken),
            "ISO" when (dconf.Archive & DynamicConfigFlags.ArchiveIso9660) != 0 => ScanExternalArchive(data, "ISO", state, options, parents, depth, budget, cancellationToken),
            "XAR" when (dconf.Archive & DynamicConfigFlags.ArchiveXar) != 0 => ScanExternalArchive(data, "XAR", state, options, parents, depth, budget, cancellationToken),
            "DMG" when (dconf.Archive & DynamicConfigFlags.ArchiveDmg) != 0 => ScanExternalArchive(data, "DMG", state, options, parents, depth, budget, cancellationToken),
            "LHA" when (dconf.Archive & DynamicConfigFlags.ArchiveLhaLzh) != 0 => ScanExternalArchive(data, "LHA", state, options, parents, depth, budget, cancellationToken),
            "EGG" when (dconf.Archive & DynamicConfigFlags.ArchiveEgg) != 0 => ScanExternalArchive(data, "EGG", state, options, parents, depth, budget, cancellationToken),
            "ALZ" when (dconf.Archive & DynamicConfigFlags.ArchiveAlz) != 0 => ScanExternalArchive(data, "ALZ", state, options, parents, depth, budget, cancellationToken),
            "SIS" when (dconf.Archive & DynamicConfigFlags.ArchiveSis) != 0 => ScanExternalArchive(data, "SIS", state, options, parents, depth, budget, cancellationToken),
            "NULSFT" when (dconf.Archive & DynamicConfigFlags.ArchiveNsis) != 0 => ScanExternalArchive(data, "NULSFT", state, options, parents, depth, budget, cancellationToken),
            "SZDD" when (dconf.Archive & DynamicConfigFlags.ArchiveSzdd) != 0 => ScanSzdd(data, state, options, parents, depth, budget, cancellationToken),
            "POSIX_TAR" or "OLD_TAR" when (dconf.Archive & DynamicConfigFlags.ArchiveTar) != 0 => ScanTar(data, type!, state, options, parents, depth, budget, cancellationToken),
            "CPIO_NEWC" or "CPIO_CRC" or "CPIO_ODC" or "CPIO_OLD" when (dconf.Archive & DynamicConfigFlags.ArchiveCpio) != 0 => ScanCpio(data, type, state, options, parents, depth, budget, cancellationToken),
            "OLE2" when (dconf.Archive & DynamicConfigFlags.ArchiveOle2) != 0 => OfficeOleExtractor.ScanOle2(data, state, options, parents, depth, budget, cancellationToken),
            "RTF" when (dconf.Doc & DynamicConfigFlags.DocumentRtf) != 0 => OfficeOleExtractor.ScanRtfEmbeddedObjects(data, state, options, parents, depth, budget, cancellationToken),
            "BINHEX" when (dconf.Archive & DynamicConfigFlags.ArchiveBinHex) != 0 => MailDocumentExtractor.ScanBinHex(data, state, options, parents, depth, budget, cancellationToken),
            "UUENCODED" when (dconf.Other & DynamicConfigFlags.OtherUuEnc) != 0 => MailDocumentExtractor.ScanUuEncoded(data, state, options, parents, depth, budget, cancellationToken),
            "TNEF" when (dconf.Mail & DynamicConfigFlags.MailTnef) != 0 => MailDocumentExtractor.ScanTnef(data, state, options, parents, depth, budget, cancellationToken),
            "MAIL" or "MHTML" when (dconf.Mail & DynamicConfigFlags.MailMbox) != 0 => MailDocumentExtractor.ScanMimeMail(data, type, state, options, parents, depth, budget, cancellationToken),
            "FLASH" when (dconf.Doc & DynamicConfigFlags.DocumentSwf) != 0 => PdfSwfExtractor.ScanFlash(data, state, options, parents, depth, budget, cancellationToken),
            "UDF" when (dconf.Archive & DynamicConfigFlags.ArchiveUdf) != 0 => ScanExternalArchive(data, type!, state, options, parents, depth, budget, cancellationToken),
            "AUTOIT" when (dconf.Archive & DynamicConfigFlags.ArchiveAutoIt) != 0 => ScanExternalArchive(data, type!, state, options, parents, depth, budget, cancellationToken),
            "ISHIELD_MSI" when (dconf.Archive & DynamicConfigFlags.ArchiveIshield) != 0 => ScanExternalArchive(data, type!, state, options, parents, depth, budget, cancellationToken),
            "PDF" when (dconf.Doc & DynamicConfigFlags.DocumentPdf) != 0 => PdfSwfExtractor.ScanPdfEmbeddedStreams(data, state, options, parents, depth, budget, cancellationToken),
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

    internal static int FindHeaderEnd(string text)
    {
        var crlf = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var lf = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (crlf < 0) return lf < 0 ? -1 : lf;
        return lf < 0 ? crlf : Math.Min(crlf, lf);
    }

    internal static int HexNibble(byte value)
        => value is >= (byte)'0' and <= (byte)'9' ? value - '0' :
           value is >= (byte)'A' and <= (byte)'F' ? value - 'A' + 10 :
           value is >= (byte)'a' and <= (byte)'f' ? value - 'a' + 10 : -1;

    internal static List<Detection> ScanChild(
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

    internal static bool ConsumeBudget(ArchiveScanBudget budget, ScanLimits limits, long bytes)
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
