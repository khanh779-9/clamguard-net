using System.Diagnostics;
using System.Buffers;
using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Matching;
using ClamGuard.Signatures.Patterns;
using ClamGuard.Yara;
using ClamGuard.Bytecode;

namespace ClamGuard.Scanner;
public sealed partial class ScannerEngine
{
    private static IReadOnlyList<Detection> RescanAsHandlerType(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string handlerType,
        IReadOnlyList<string> parentTypes,
        CancellationToken cancellationToken)
    {
        // HandlerType creates a retyped scan layer. Apply FP trust before running the
        // handler matchers/scanners so a trusted layer produces no evidence.
        if (state.Compiled.MatchesFalsePositive(data))
            return [];

        var results = new List<Detection>();
        var ndb = state.Database.NdbSignatures;
        var logical = state.Database.LogicalSignatures;

        // cli_magic_scan() performs the ordinary compiled/raw matcher again on
        // the retyped fmap before/alongside its type-specific scanners.
        results.AddRange(state.Compiled.Match(
            data,
            $"handler-type:{handlerType}",
            includeNdb: false,
            collectAllMatches: (options.CollectAllMatches || !options.DetectPUA)));

        results.AddRange(EvaluateNdb(
            ndb,
            data,
            options.Limits,
            handlerType,
            cancellationToken,
            scanOptions: options));

        results.AddRange(EvaluateLogical(
            logical,
            ndb,
            data,
            options.Limits,
            handlerType,
            state.Database.IconDatabase,
            parentTypes,
            cancellationToken,
            retyped: true,
            scanState: state,
            scanOptions: options));

        // Dispatch only the handler requested by the retyping layer. ClamAV's
        // cli_magic_scan() switches on the active layer type; it does not run the
        // PE parser on an ELF/ZIP/etc merely because HandlerType exists.
        if (options.ScanPE && ScanTypePolicy.IsPe(handlerType))
            results.AddRange(PeSpecializedMatcher.Match(data, state, options.Limits, cancellationToken));

        foreach (var contentScanner in options.ContentScanners)
            results.AddRange(contentScanner.Scan(data, $"handler-type:{handlerType}", cancellationToken));

        if (options.ScanPE && (handlerType.Equals("PE", StringComparison.OrdinalIgnoreCase) ||
            handlerType.Equals("MSEXE", StringComparison.OrdinalIgnoreCase)))
        {
            results.AddRange(PeOverlayScanner.ScanPeOverlay(data, state, options, cancellationToken));
        }

        if (handlerType.Equals("MACH-O", StringComparison.OrdinalIgnoreCase) ||
            handlerType.Equals("MACHO_UNIBIN", StringComparison.OrdinalIgnoreCase))
        {
            results.AddRange(ScanMachOFatSlices(data, state, options, cancellationToken));
        }

        // Archive/document handlers are dispatched only for the active handler
        // type. ArchiveScanner still performs the concrete byte-level subtype
        // detection before extraction.
        if (ScanTypePolicy.IsArchiveContainer(handlerType) && ScanTypePolicy.ShouldParseContainer(handlerType, options))
        {
            results.AddRange(ArchiveScanner.Scan(
                data,
                $"handler-type.{handlerType}",
                state,
                options,
                parentTypes,
                parentTypes.Count + 1,
                cancellationToken));
        }

        return results;
    }

    private static byte[]? NormalizeTargetData(ReadOnlySpan<byte> data, string fileType, SignatureTargetType target, ScanOptions? options = null)
        => NormalizeTargetData(data, fileType, (int)target, options);

    private static byte[]? NormalizeTargetData(ReadOnlySpan<byte> data, string fileType, int target, ScanOptions? options = null)
    {
        if ((target == 3 || target == (int)SignatureTargetType.Html) && (fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase) || fileType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase)))
        {
            if (options is not null && (!options.ScanHTML || data.Length > options.Limits.MaxHtmlNormalize))
                return null;
            if (fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase))
                return NormalizeHtml(data);
            var text = DecodeUtf16Text(data);
            return text is null ? null : NormalizeHtml(Encoding.Latin1.GetBytes(text));
        }
        if (target == 7 && fileType.Equals("ASCII", StringComparison.OrdinalIgnoreCase))
            return NormalizeAscii(data);
        return null;
    }

    private static string? DecodeUtf16Text(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        try
        {
            if (data[0] == 0xff && data[1] == 0xfe)
                return Encoding.Unicode.GetString(data[2..]);
            if (data[0] == 0xfe && data[1] == 0xff)
                return Encoding.BigEndianUnicode.GetString(data[2..]);
            return null;
        }
        catch (DecoderFallbackException) { return null; }
    }

    private static byte[] NormalizeAscii(ReadOnlySpan<byte> data)
    {
        // Operate directly on byte spans to eliminate string/StringBuilder allocation
        var output = new byte[data.Length];
        var outLen = 0;
        var pendingSpace = false;
        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            if (b is >= (byte)0x21 and <= (byte)0x7e)
            {
                if (pendingSpace && outLen != 0)
                    output[outLen++] = (byte)' ';
                // Fast ASCII lowercase
                if (b is >= (byte)'A' and <= (byte)'Z')
                    b = (byte)(b | 0x20);
                output[outLen++] = b;
                pendingSpace = false;
                continue;
            }
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)'\f' or (byte)'\v')
                pendingSpace = outLen != 0;
            // Other ASCII controls are dropped, matching the same compatibility
            // objective as ASCII-normalise rather than preserving binary noise.
        }
        if (outLen == output.Length)
            return output;
        var result = new byte[outLen];
        output.AsSpan(0, outLen).CopyTo(result);
        return result;
    }

    private static byte[] NormalizeHtml(ReadOnlySpan<byte> data)
    {
        var input = Encoding.Latin1.GetString(data);
        var withoutComments = new StringBuilder(input.Length);
        var i = 0;
        while (i < input.Length)
        {
            if (i + 3 < input.Length && input[i] == '<' && input[i + 1] == '!' && input[i + 2] == '-' && input[i + 3] == '-')
            {
                var end = input.IndexOf("-->", i + 4, StringComparison.Ordinal);
                if (end < 0) break;
                i = end + 3;
                continue;
            }
            withoutComments.Append(input[i++]);
        }

        var decoded = WebUtility.HtmlDecode(withoutComments.ToString()) ?? string.Empty;
        var normalized = new StringBuilder(decoded.Length);
        var pendingSpace = false;
        foreach (var ch in decoded)
        {
            if (ch is >= '\x21' and <= '\x7e')
            {
                if (pendingSpace && normalized.Length != 0) normalized.Append(' ');
                normalized.Append(char.ToLowerInvariant(ch));
                pendingSpace = false;
            }
            else if (char.IsWhiteSpace(ch))
            {
                pendingSpace = normalized.Length != 0;
            }
        }
        return Encoding.Latin1.GetBytes(normalized.ToString());
    }

    private static bool TryEvaluateTrigger(string expression, IReadOnlyList<SubsigMatches> matches, int maxDepth)
    {
        try
        {
            return LogicalExpressionEvaluator.Evaluate(expression, matches, maxDepth);
        }
        catch (FormatException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static bool TryReadByteCompareValue(
        ReadOnlySpan<byte> data,
        int offset,
        LdbByteCompareSubSignature spec,
        out long value)
    {
        value = 0;
        if (offset < 0 || offset >= data.Length || spec.ByteLength <= 0)
            return false;

        var available = data.Length - offset;
        var requested = spec.ByteLength;
        var take = Math.Min(available, requested);
        if (spec.Options.HasFlag(ByteCompareOptions.Exact) && take != requested)
            return false;

        var bytes = data.Slice(offset, take);
        if (spec.Options.HasFlag(ByteCompareOptions.Binary))
        {
            if (take != requested || take is not (1 or 2 or 4 or 8))
                return false;
            ulong raw = spec.Options.HasFlag(ByteCompareOptions.LittleEndian) ? take switch
            {
                1 => bytes[0],
                2 => BinaryPrimitives.ReadUInt16LittleEndian(bytes),
                4 => BinaryPrimitives.ReadUInt32LittleEndian(bytes),
                8 => BinaryPrimitives.ReadUInt64LittleEndian(bytes),
                _ => 0UL
            } : take switch
            {
                1 => bytes[0],
                2 => BinaryPrimitives.ReadUInt16BigEndian(bytes),
                4 => BinaryPrimitives.ReadUInt32BigEndian(bytes),
                8 => BinaryPrimitives.ReadUInt64BigEndian(bytes),
                _ => 0UL
            };
            value = unchecked((long)raw);
            return true;
        }

        var text = Encoding.ASCII.GetString(bytes).TrimStart();
        if (text.Length == 0)
            return false;
        var isHex = spec.Options.HasFlag(ByteCompareOptions.Hex) ||
                    (spec.Options.HasFlag(ByteCompareOptions.Auto) && text.StartsWith("0x", StringComparison.OrdinalIgnoreCase));
        if (isHex)
        {
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
            var digits = text.TakeWhile(Uri.IsHexDigit).ToArray();
            if (digits.Length == 0 || digits.Length > 16)
                return false;
            var hex = new string(digits);
            if (spec.Options.HasFlag(ByteCompareOptions.Exact) && digits.Length != text.Length)
                return false;
            if ((hex.Length & 1) != 0) hex = "0" + hex;
            if (spec.Options.HasFlag(ByteCompareOptions.LittleEndian))
            {
                var pairs = Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)).Reverse();
                hex = string.Concat(pairs);
            }
            return long.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out value);
        }

        var digitsDec = text.TakeWhile(c => char.IsDigit(c) || (c is '+' or '-') && c == text[0]).ToArray();
        if (digitsDec.Length == 0)
            return false;
        var decimalText = new string(digitsDec);
        if (spec.Options.HasFlag(ByteCompareOptions.Exact) && digitsDec.Length != text.Length)
            return false;
        return long.TryParse(decimalText, out value);
    }

    private static bool CompareByteValue(long value, ByteCompareComparison comparison) => comparison.Operator switch
    {
        '>' => value > comparison.Value,
        '<' => value < comparison.Value,
        '=' => value == comparison.Value,
        _ => false
    };

    private static int GetSubsigIndex(ContentSignature signature)
    {
        var hash = signature.Name.LastIndexOf('#');
        return hash >= 0 && int.TryParse(signature.Name[(hash + 1)..], out var index) ? index : 0;
    }

    private static bool OffsetAllows(string value, int position, int length)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "*") return true;
        if (value.Equals("EOF", StringComparison.OrdinalIgnoreCase)) return position == length;
        if (value.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value.AsSpan(4), out var eofShift))
            return position == length - eofShift;
        if (int.TryParse(value, out var exact)) return position == exact;
        // Allocation-free range check — avoid string.Split() per-match.
        var comma = value.IndexOf(',');
        if (comma > 0 && comma < value.Length - 1 &&
            int.TryParse(value.AsSpan(0, comma).Trim(), out var min) &&
            int.TryParse(value.AsSpan(comma + 1).Trim(), out var max))
            return position >= min && position <= max;
        return false;
    }

    internal sealed class SubsigMatches
    {
        public int Index { get; }
        public List<int> Positions { get; } = [];
        public int Count => Positions.Count;

        public SubsigMatches(int index) => Index = index;
    }

}
