using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

/// <summary>
/// Managed counterparts for high-value ClamAV specialized file handlers that run
/// before/around the ordinary raw layer. The implementation deliberately keeps the
/// raw layer scan separate: a parser extracts a logical child layer, then that layer
/// is scanned by the normal engine again.
/// </summary>
internal static partial class SpecializedFileHandlers
{
    /// <summary>
    /// Managed subset of libclamav/msxml.c: inspect MS Office 2003 XML
    /// BinaryData/binData elements encoded as Base64 and scan the decoded bytes
    /// as a nested layer. Metadata extraction is intentionally not emulated.
    /// </summary>
    private static IReadOnlyList<Detection> ScanMsXml(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken,
        ScanContext? context = null)
    {
        if (data.IsEmpty || data.Length > options.Limits.MaxEmbeddedStreamSize)
            return [];

        var results = new List<Detection>();
        try
        {
            using var stream = new MemoryStream(data.ToArray(), writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = false,
                IgnoreWhitespace = false,
                MaxCharactersInDocument = options.Limits.MaxEmbeddedStreamSize
            });

            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reader.NodeType != XmlNodeType.Element ||
                    !reader.LocalName.Equals("bindata", StringComparison.OrdinalIgnoreCase))
                    continue;

                var encoded = reader.ReadElementContentAsString();
                if (string.IsNullOrWhiteSpace(encoded))
                    continue;

                byte[] decoded;
                try
                {
                    decoded = Convert.FromBase64String(encoded);
                }
                catch (FormatException)
                {
                    continue;
                }

                if (decoded.Length == 0 || decoded.LongLength > options.Limits.MaxEmbeddedStreamSize)
                    continue;

                results.AddRange(ScanNestedBytes(decoded, state, options,
                    $"{path}#msxml-bindata", cancellationToken, context));
                if (!options.CollectAllMatches && options.HasBlockingDetections(results))
                    return options.FilterDetections(results).Take(1).ToArray();
            }
        }
        catch (XmlException)
        {
            // Keep raw matching intact when an XML document is malformed.
        }
        catch (InvalidOperationException)
        {
            // A binData element with nested markup is not a plain Base64 payload.
            // Treat it as a parser miss instead of failing the outer file scan.
        }

        return results;
    }

    private static IReadOnlyList<Detection> ScanHwpMl(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken,
        ScanContext? context = null)
    {
        if (data.Length == 0 || data.Length > options.Limits.MaxEmbeddedStreamSize)
            return [];

        var results = new List<Detection>();
        try
        {
            using var stream = new MemoryStream(data.ToArray(), writable: false);
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                IgnoreComments = false,
                IgnoreWhitespace = false,
                MaxCharactersInDocument = options.Limits.MaxEmbeddedStreamSize
            };
            using var reader = XmlReader.Create(stream, settings);
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (reader.NodeType != XmlNodeType.Element)
                    continue;

                var local = reader.LocalName;
                if (!local.Equals("bindata", StringComparison.OrdinalIgnoreCase) &&
                    !local.Equals("scriptheader", StringComparison.OrdinalIgnoreCase) &&
                    !local.Equals("scriptsource", StringComparison.OrdinalIgnoreCase))
                    continue;

                var compress = ParseBoolAttribute(reader, "Compress");
                var encoding = reader.GetAttribute("Encoding");
                var value = reader.ReadElementContentAsString();
                if (string.IsNullOrEmpty(value)) continue;

                byte[] content;
                if (string.Equals(encoding, "Base64", StringComparison.OrdinalIgnoreCase))
                {
                    try { content = Convert.FromBase64String(value); }
                    catch (FormatException) { continue; }
                }
                else
                {
                    content = Encoding.UTF8.GetBytes(value);
                }

                if (content.Length == 0 || content.Length > options.Limits.MaxEmbeddedStreamSize)
                    continue;

                if (compress == true)
                {
                    if (!TryInflateZlibBounded(content, options.Limits.MaxEmbeddedStreamSize, out content))
                        continue;
                }

                results.AddRange(ScanNestedBytes(content, state, options,
                    $"{path}#{local.ToLowerInvariant()}", cancellationToken, context));
                if (!options.CollectAllMatches && options.HasBlockingDetections(results))
                    return options.FilterDetections(results).Take(1).ToArray();
            }
        }
        catch (XmlException)
        {
            // Non-critical parse failure; retain normal raw scanning behavior.
        }
        return results;
    }

    private static bool? ParseBoolAttribute(XmlReader reader, string name)
    {
        var value = reader.GetAttribute(name);
        if (value is null) return null;
        if (bool.TryParse(value, out var b)) return b;
        return null;
    }

    private static bool TryInflateZlibBounded(ReadOnlySpan<byte> compressed, long maxOutput, out byte[] output)
    {
        output = [];
        if (compressed.IsEmpty || maxOutput <= 0 || maxOutput > int.MaxValue)
            return false;
        try
        {
            using var input = new MemoryStream(compressed.ToArray(), writable: false);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var result = new MemoryStream();
            var buffer = new byte[64 * 1024];
            while (true)
            {
                var read = zlib.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                if (result.Length > maxOutput - read) return false;
                result.Write(buffer, 0, read);
            }
            output = result.ToArray();
            return output.Length != 0;
        }
        catch (InvalidDataException) { return false; }
        catch (IOException) { return false; }
    }

    private static IReadOnlyList<Detection> ScanHwp3(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken,
        ScanContext? context = null)
    {
        // ClamAV hwp.c: identity 30 bytes + docinfo 128 + docsummary 1008.
        const int identitySize = 30;
        const int docInfoSize = 128;
        const int docSummarySize = 1008;
        const int docInfoOffset = identitySize;
        const int passwordOffset = 96;
        const int compressedOffset = 124;
        const int infoBlockSizeOffset = 126;
        const int minimumSize = identitySize + docInfoSize + docSummarySize;

        if (data.Length < minimumSize)
            return [];

        var docInfo = data.Slice(docInfoOffset, docInfoSize);
        var password = BinaryPrimitives.ReadUInt16LittleEndian(docInfo.Slice(passwordOffset, 2));
        var compressed = docInfo[compressedOffset] != 0;
        var infoBlockSize = BinaryPrimitives.ReadUInt16LittleEndian(docInfo.Slice(infoBlockSizeOffset, 2));
        if (password != 0)
            return [];

        var bodyOffsetLong = (long)minimumSize + infoBlockSize;
        if (bodyOffsetLong < minimumSize || bodyOffsetLong >= data.Length || bodyOffsetLong > int.MaxValue)
            return [];

        var body = data.Slice((int)bodyOffsetLong);
        if (!compressed)
            return ScanNestedBytes(body, state, options, $"{path}#hwp3-body", cancellationToken, context);

        if (!TryInflateRaw(body, options.Limits.MaxEmbeddedStreamSize, out var inflated))
            return [];
        return ScanNestedBytes(inflated, state, options, $"{path}#hwp3-decompressed", cancellationToken, context);
    }

    private static IReadOnlyList<Detection> ScanHwpoLe2(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken,
        ScanContext? context = null)
    {
        // ClamAV cli_scanhwpole2(): 4-byte uncompressed-size prefix followed by OLE2.
        if (data.Length <= 4)
            return [];

        var expectedSize = BinaryPrimitives.ReadUInt32LittleEndian(data[..4]);
        var actualSize = (uint)(data.Length - 4);
        _ = expectedSize; // native code warns on mismatch but still scans the OLE2 body.
        return ScanNestedBytes(data[4..], state, options, $"{path}#hwp-ole2", cancellationToken, context);
    }

    private static IReadOnlyList<Detection> ScanNestedBytes(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken,
        ScanContext? context = null)
    {
        if (data.Length == 0 || data.Length > int.MaxValue)
            return [];

        var child = data.ToArray();
        var result = ScannerEngine.ScanBuffer(
            child,
            child.Length,
            state,
            options,
            path,
            cancellationToken,
            (context ?? ScanContext.CreateRoot()).Descend());
        return result.Detections;
    }

}
