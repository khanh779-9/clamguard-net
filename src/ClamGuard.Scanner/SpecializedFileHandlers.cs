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
internal static class SpecializedFileHandlers
{
    public static IReadOnlyList<Detection> ScanPreRaw(
        ReadOnlySpan<byte> data,
        string fileType,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty) return [];

        // ClamAV scan_layer dispatches document handlers only when the DOCUMENT
        // dconf flag is enabled for the engine flevel.
        var dconf = state.Database.DynamicConfiguration;
        return fileType.ToUpperInvariant() switch
        {
            "HWP3" when (dconf.Doc & DynamicConfigFlags.DocumentHwp) != 0 => ScanHwp3(data, state, options, path, cancellationToken),
            "HWPOLE2" when (dconf.Doc & DynamicConfigFlags.DocumentHwp) != 0 => ScanHwpoLe2(data, state, options, path, cancellationToken),
            "HTML" when (dconf.Doc & DynamicConfigFlags.DocumentHtml) != 0 => ScanHtmlVariants(data, state, options, path, cancellationToken),
            "HTML_UTF16" when (dconf.Doc & DynamicConfigFlags.DocumentHtml) != 0 => ScanHtmlUtf16Variants(data, state, options, path, cancellationToken),
            "ONENOTE" when (dconf.Doc & DynamicConfigFlags.DocumentOneNote) != 0 => ScanOneNoteAttachments(data, state, options, path, cancellationToken),
            "XDP" => ScanXdp(data, state, options, path, cancellationToken),
            "XML_HWP" when (dconf.Doc & DynamicConfigFlags.DocumentHwp) != 0 => ScanHwpMl(data, state, options, path, cancellationToken),
            _ => []
        };
    }

    public static IReadOnlyList<Detection> ScanPostRaw(
        ReadOnlySpan<byte> data,
        string fileType,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty) return [];

        var dconf = state.Database.DynamicConfiguration;
        return fileType.ToUpperInvariant() switch
        {
            "HTML" when (dconf.Doc & DynamicConfigFlags.DocumentHtml) != 0 => ScanHtmlVariants(data, state, options, path, cancellationToken),
            "HTML_UTF16" when (dconf.Doc & DynamicConfigFlags.DocumentHtml) != 0 => ScanHtmlUtf16Variants(data, state, options, path, cancellationToken),
            _ => []
        };
    }

    private static readonly byte[] OneNoteMagic =
    [
        0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
        0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3
    ];

    private static readonly byte[] OneNoteFileDataStoreObject =
    [
        0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
        0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC
    ];

    private static IReadOnlyList<Detection> ScanOneNoteAttachments(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        // ClamAV 1.5.4 delegates OneNote extraction to its onenote.rs component.
        // Keep the managed implementation aligned with the documented fallback
        // path in that component: validate the 16-byte OneStore magic, then walk
        // FileDataStoreObject records and scan each embedded payload as a new layer.
        if (data.Length < OneNoteMagic.Length || !data[..OneNoteMagic.Length].SequenceEqual(OneNoteMagic))
            return [];

        var results = new List<Detection>();
        var search = 0;
        var attachmentIndex = 0;
        while (search <= data.Length - OneNoteFileDataStoreObject.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rel = data[search..].IndexOf(OneNoteFileDataStoreObject);
            if (rel < 0) break;
            var marker = checked(search + rel);
            var headerSize = 36; // guid[16] + cbLength[8] + unused[4] + reserved[8]
            if (marker > data.Length - headerSize)
                break;

            // ClamAV's fallback reads the low 32-bit length at offset 16.
            var payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(marker + 16, 4));
            if (payloadLength > options.Limits.MaxEmbeddedStreamSize ||
                marker + headerSize > data.Length - payloadLength)
            {
                search = marker + OneNoteFileDataStoreObject.Length;
                continue;
            }

            var payload = data.Slice(marker + headerSize, checked((int)payloadLength));
            if (payload.Length != 0)
            {
                results.AddRange(ScanNestedBytes(payload, state, options,
                    $"{path}#onenote-attachment-{attachmentIndex++}", cancellationToken));
                if (!options.CollectAllMatches && results.Count != 0)
                    return [results[0]];
            }

            search = marker + headerSize + checked((int)payloadLength);
        }

        return results;
    }

    private static IReadOnlyList<Detection> ScanXdp(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        if (data.Length > options.Limits.MaxEmbeddedStreamSize || data.Length == 0)
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
                if (reader.NodeType != XmlNodeType.Element ||
                    !reader.LocalName.Equals("chunk", StringComparison.OrdinalIgnoreCase))
                    continue;

                var text = reader.ReadElementContentAsString();
                if (string.IsNullOrWhiteSpace(text)) continue;
                byte[] decoded;
                try
                {
                    decoded = Convert.FromBase64String(text);
                }
                catch (FormatException)
                {
                    continue;
                }

                if (decoded.Length == 0 || decoded.Length > options.Limits.MaxEmbeddedStreamSize)
                    continue;

                // Native xdp.c only submits a decoded chunk when a %PDF- marker is
                // found near the beginning, avoiding arbitrary non-PDF base64 blobs.
                var probe = decoded.AsSpan(0, Math.Min(1028, decoded.Length));
                var pdfAt = FindPdfMarker(probe);
                if (pdfAt < 0) break;

                results.AddRange(ScanNestedBytes(decoded, state, options,
                    $"{path}#xdp-pdf-{pdfAt}", cancellationToken));
                if (!options.CollectAllMatches && results.Count != 0)
                    return [results[0]];
            }
        }
        catch (XmlException)
        {
            // ClamAV treats malformed XDP as non-fatal so the normal layer scan can continue.
        }
        return results;
    }

    private static int FindPdfMarker(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i + 5 <= data.Length; i++)
        {
            if (data[i] != (byte)'%') continue;
            var p = data[i + 1] is (byte)'P' or (byte)'p';
            var d = data[i + 2] is (byte)'D' or (byte)'d';
            var f = data[i + 3] is (byte)'F' or (byte)'f';
            if (p && d && f && data[i + 4] == (byte)'-') return i;
        }
        return -1;
    }

    private static IReadOnlyList<Detection> ScanHwpMl(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
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
                    $"{path}#{local.ToLowerInvariant()}", cancellationToken));
                if (!options.CollectAllMatches && results.Count != 0)
                    return [results[0]];
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
        CancellationToken cancellationToken)
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
            return ScanNestedBytes(body, state, options, $"{path}#hwp3-body", cancellationToken);

        if (!TryInflateRaw(body, options.Limits.MaxEmbeddedStreamSize, out var inflated))
            return [];
        return ScanNestedBytes(inflated, state, options, $"{path}#hwp3-decompressed", cancellationToken);
    }

    private static IReadOnlyList<Detection> ScanHwpoLe2(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        // ClamAV cli_scanhwpole2(): 4-byte uncompressed-size prefix followed by OLE2.
        if (data.Length <= 4)
            return [];

        var expectedSize = BinaryPrimitives.ReadUInt32LittleEndian(data[..4]);
        var actualSize = (uint)(data.Length - 4);
        _ = expectedSize; // native code warns on mismatch but still scans the OLE2 body.
        return ScanNestedBytes(data[4..], state, options, $"{path}#hwp-ole2", cancellationToken);
    }

    private static IReadOnlyList<Detection> ScanNestedBytes(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
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
            cancellationToken);
        return result.Detections;
    }

    private static IReadOnlyList<Detection> ScanHtmlUtf16Variants(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        var text = DecodeUtf16(data);
        if (text is null)
            return [];
        return ScanHtmlVariants(Encoding.Latin1.GetBytes(text), state, options, path, cancellationToken);
    }

    private static IReadOnlyList<Detection> ScanHtmlVariants(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        if (data.Length > options.Limits.MaxHtmlNormalize)
            return [];

        var text = Encoding.Latin1.GetString(data);
        var noComments = StripHtmlComments(text);
        var nocomment = NormalizeHtmlKeepTags(noComments);

        var results = new List<Detection>();
        results.AddRange(ScanNormalizedLayer(
            Encoding.Latin1.GetBytes(nocomment),
            "HTML",
            $"{path}#nocomment.html",
            state,
            options,
            cancellationToken));

        if (nocomment.Length <= options.Limits.MaxHtmlNoTags)
        {
            var noTags = NormalizeHtmlNoTags(noComments);
            results.AddRange(ScanNormalizedLayer(
                Encoding.Latin1.GetBytes(noTags),
                "HTML",
                $"{path}#notags.html",
                state,
                options,
                cancellationToken));
        }

        var javascript = ExtractAndNormalizeJavascript(noComments);
        if (javascript.Length != 0 && javascript.Length <= options.Limits.MaxScriptNormalize)
        {
            var jsBytes = Encoding.Latin1.GetBytes(javascript);
            results.AddRange(ScanNormalizedLayer(jsBytes, "HTML", $"{path}#javascript-as-html", state, options, cancellationToken));
            results.AddRange(ScanNormalizedLayer(jsBytes, "ASCII", $"{path}#javascript-as-text-ascii", state, options, cancellationToken));
        }

        // html_normalise.c also emits scans of data: RFC2397 resources discovered
        // in tags. Reconstructing that full parser is deferred; ordinary normalized
        // signatures and JavaScript are handled here.
        return results;
    }

    private static IReadOnlyList<Detection> ScanNormalizedLayer(
        ReadOnlySpan<byte> data,
        string fileType,
        string path,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty) return [];
        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        var results = new List<Detection>();
        results.AddRange(state.Compiled.Match(data, path, includeNdb: false, collectAllMatches: options.CollectAllMatches));
        results.AddRange(ScannerEngine.EvaluateNdb(ndb, data, options.Limits, fileType, cancellationToken));
        results.AddRange(ScannerEngine.EvaluateLogical(
            state.Database.Signatures.OfType<LogicalSignature>(),
            ndb,
            data,
            options.Limits,
            fileType,
            state.Database.IconDatabase,
            [],
            cancellationToken,
            scanState: state,
            scanOptions: options));
        foreach (var scanner in options.ContentScanners)
            results.AddRange(scanner.Scan(data, path, cancellationToken));
        return results;
    }

    private static string StripHtmlComments(string input)
    {
        var output = new StringBuilder(input.Length);
        var pos = 0;
        while (pos < input.Length)
        {
            var start = input.IndexOf("<!--", pos, StringComparison.Ordinal);
            if (start < 0)
            {
                output.Append(input, pos, input.Length - pos);
                break;
            }

            output.Append(input, pos, start - pos);
            var end = input.IndexOf("-->", start + 4, StringComparison.Ordinal);
            if (end < 0)
                break;
            pos = end + 3;
        }
        return output.ToString();
    }

    private static string NormalizeHtmlKeepTags(string input)
    {
        var decoded = WebUtility.HtmlDecode(input) ?? string.Empty;
        var output = new StringBuilder(decoded.Length);
        var pendingSpace = false;
        var inTag = false;
        foreach (var ch in decoded)
        {
            if (ch == '<') inTag = true;
            if (inTag)
            {
                output.Append(char.ToLowerInvariant(ch));
                if (ch == '>') inTag = false;
                continue;
            }

            if (char.IsWhiteSpace(ch))
            {
                pendingSpace = output.Length != 0;
                continue;
            }

            if (pendingSpace && output.Length != 0)
                output.Append(' ');
            pendingSpace = false;
            output.Append(char.ToLowerInvariant(ch));
        }
        return output.ToString();
    }

    private static string NormalizeHtmlNoTags(string input)
    {
        var decoded = WebUtility.HtmlDecode(input) ?? string.Empty;
        var noTags = Regex.Replace(decoded, "<[^>]*>", " ", RegexOptions.Singleline | RegexOptions.CultureInvariant);
        var output = new StringBuilder(noTags.Length);
        var pendingSpace = false;
        foreach (var ch in noTags)
        {
            if (char.IsWhiteSpace(ch))
            {
                pendingSpace = output.Length != 0;
                continue;
            }
            if (pendingSpace && output.Length != 0) output.Append(' ');
            pendingSpace = false;
            output.Append(char.ToLowerInvariant(ch));
        }
        return output.ToString();
    }

    private static string ExtractAndNormalizeJavascript(string input)
    {
        var builder = new StringBuilder();
        var search = 0;
        while (search < input.Length)
        {
            var open = input.IndexOf("<script", search, StringComparison.OrdinalIgnoreCase);
            if (open < 0) break;
            var openEnd = input.IndexOf('>', open + 7);
            if (openEnd < 0) break;
            var close = input.IndexOf("</script", openEnd + 1, StringComparison.OrdinalIgnoreCase);
            var bodyEnd = close >= 0 ? close : input.Length;
            var body = input.Substring(openEnd + 1, bodyEnd - (openEnd + 1));
            body = WebUtility.HtmlDecode(body) ?? body;
            body = DecodeJScriptEncodedMarker(body);
            AppendScriptWhitespaceNormalized(builder, body);
            if (close < 0) break;
            search = close + 8;
        }
        return builder.ToString();
    }

    private static string DecodeJScriptEncodedMarker(string value)
    {
        // ClamAV's HTML normalizer recognizes JScript/VBScript.encode and decodes
        // the #@~^ ... marker. Full JS token normalization lives in jsparse.c and is
        // intentionally not reimplemented here; preserving decoded char refs and
        // the marker body is the safe managed subset.
        return value;
    }

    private static void AppendScriptWhitespaceNormalized(StringBuilder output, string value)
    {
        var pendingSpace = false;
        foreach (var ch in value)
        {
            if (char.IsWhiteSpace(ch))
            {
                pendingSpace = true;
                continue;
            }
            var lower = char.ToLowerInvariant(ch);
            var isPunct = !char.IsLetterOrDigit(lower) && lower != '$' && lower != '_';
            if (pendingSpace && output.Length != 0)
            {
                var prev = output[^1];
                var prevIsPunct = !char.IsLetterOrDigit(prev) && prev != '$' && prev != '_';
                // In ClamAV js-norm tokenization, spaces are only needed between word tokens
                if (!isPunct && !prevIsPunct)
                {
                    output.Append(' ');
                }
            }
            pendingSpace = false;
            output.Append(lower);
        }
        if (output.Length != 0) output.Append('\n');
    }

    private static string? DecodeUtf16(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        try
        {
            if (data[0] == 0xff && data[1] == 0xfe)
                return Encoding.Unicode.GetString(data[2..]);
            if (data[0] == 0xfe && data[1] == 0xff)
                return Encoding.BigEndianUnicode.GetString(data[2..]);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
        return null;
    }

    private static bool TryInflateRaw(ReadOnlySpan<byte> compressed, long maxOutput, out byte[] output)
    {
        output = [];
        if (compressed.IsEmpty || maxOutput <= 0 || maxOutput > int.MaxValue)
            return false;

        try
        {
            using var input = new MemoryStream(compressed.ToArray(), writable: false);
            using var inflater = new DeflateStream(input, CompressionMode.Decompress, leaveOpen: false);
            using var buffer = new MemoryStream();
            var temp = new byte[64 * 1024];
            while (true)
            {
                var read = inflater.Read(temp, 0, temp.Length);
                if (read == 0) break;
                if (buffer.Length + read > maxOutput)
                    return false;
                buffer.Write(temp, 0, read);
            }
            output = buffer.ToArray();
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
}
