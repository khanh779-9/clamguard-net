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
        var budget = new ArchiveScanBudget { ExpandedBytes = data.Length };
        if (!ScanTypePolicy.ShouldParseContainer(forcedType ?? ScannerEngine.DetectType(data, hintPath, state.Database.SpecialDatabases.FileTypes), options))
            return [];
        if (data.Length > options.Limits.MaxArchiveExpandedBytes)
        {
            return options.EnableHeuristics && options.HeuristicExceedsMax
                ? [new Detection("Heuristics.Limits.Exceeded", SignatureType.Metadata, null, "heuristics", "Container exceeds the configured total scan-size limit.")]
                : [];
        }
        try
        {
            var results = ScanInternal(data, hintPath, state, options, parents ?? [], depth, budget, cancellationToken, forcedType).ToList();
            if (budget.LimitExceeded && options.EnableHeuristics && options.HeuristicExceedsMax && !results.Any(x => x.Name.Equals("Heuristics.Limits.Exceeded", StringComparison.OrdinalIgnoreCase)))
                results.Add(new Detection("Heuristics.Limits.Exceeded", SignatureType.Metadata, null, "heuristics", "One or more embedded objects could not be scanned because a configured scan limit was reached."));
            return options.FilterDetections(results);
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
        if (depth >= Math.Max(1, options.Limits.MaxArchiveDepth))
        {
            budget.LimitExceeded = true;
            return [];
        }
        if (budget.ExpandedBytes > options.Limits.MaxArchiveExpandedBytes)
        {
            budget.LimitExceeded = true;
            return [];
        }

        // Once the scan layer has a ClamAV file type (including an FTM override),
        // that type is authoritative for selecting the parser. Re-detecting from
        // bytes here could discard a dynamic FTM re-type and skip its handler.
        var detectedType = (forcedType ?? DetectContainerType(data, hintPath))?.ToUpperInvariant();
        // Native CL_TYPE_OOXML_* dispatch uses XMLDOCS for the optional OOXML
        // metadata processor, but ARCHIVE for actual ZIP member extraction. The
        // managed result model has no metadata-collection contract, so this path
        // deliberately scans the members under ScanArchive and does not pretend
        // that ScanXMLDocs disables native ZIP extraction.
        var dconf = state.Database.DynamicConfiguration;
        var type = NormalizeHandlerType(detectedType);
        // ClamAV scan_layer dispatches each format parser only when the module's
        // dconf flag is enabled for the engine flevel (e.g. ARCH_CONF_ZIP, DOC_CONF_PDF).
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
}
