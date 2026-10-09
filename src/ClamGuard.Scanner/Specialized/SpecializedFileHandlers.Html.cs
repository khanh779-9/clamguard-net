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
