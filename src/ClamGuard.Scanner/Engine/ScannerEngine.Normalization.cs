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
        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        var logical = state.Database.Signatures.OfType<LogicalSignature>().ToArray();

        // cli_magic_scan() performs the ordinary compiled/raw matcher again on
        // the retyped fmap before/alongside its type-specific scanners.
        results.AddRange(state.Compiled.Match(
            data,
            $"handler-type:{handlerType}",
            includeNdb: false));

        results.AddRange(EvaluateNdb(
            ndb,
            data,
            options.Limits,
            handlerType,
            cancellationToken));

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
        if (ScanTypePolicy.IsPe(handlerType))
            results.AddRange(PeSpecializedMatcher.Match(data, state, options.Limits, cancellationToken));

        foreach (var contentScanner in options.ContentScanners)
            results.AddRange(contentScanner.Scan(data, $"handler-type:{handlerType}", cancellationToken));

        if (handlerType.Equals("PE", StringComparison.OrdinalIgnoreCase) ||
            handlerType.Equals("MSEXE", StringComparison.OrdinalIgnoreCase))
        {
            results.AddRange(PeOverlayScanner.ScanPeOverlay(data.ToArray(), state, options, cancellationToken));
        }

        if (handlerType.Equals("MACH-O", StringComparison.OrdinalIgnoreCase) ||
            handlerType.Equals("MACHO_UNIBIN", StringComparison.OrdinalIgnoreCase))
        {
            results.AddRange(ScanMachOFatSlices(data.ToArray(), state, options, cancellationToken));
        }

        // Archive/document handlers are dispatched only for the active handler
        // type. ArchiveScanner still performs the concrete byte-level subtype
        // detection before extraction.
        if (ScanTypePolicy.IsArchiveContainer(handlerType))
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

    private static byte[]? NormalizeTargetData(ReadOnlySpan<byte> data, string fileType, int target)
    {
        if (target == 3 && fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase))
            return NormalizeHtml(data);
        if (target == 3 && fileType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase))
        {
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
        var text = Encoding.Latin1.GetString(data);
        var normalized = new StringBuilder(text.Length);
        var pendingSpace = false;
        foreach (var ch in text)
        {
            if (ch is >= '\x21' and <= '\x7e')
            {
                if (pendingSpace && normalized.Length != 0) normalized.Append(' ');
                normalized.Append(char.ToLowerInvariant(ch));
                pendingSpace = false;
                continue;
            }
            if (ch is ' ' or '\t' or '\r' or '\n' or '\f' or '\v')
                pendingSpace = normalized.Length != 0;
            // Other ASCII controls are dropped, matching the same compatibility
            // objective as ASCII-normalise rather than preserving binary noise.
        }
        return Encoding.Latin1.GetBytes(normalized.ToString());
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
            int.TryParse(value[4..], out var eofShift))
            return position == length - eofShift;
        if (int.TryParse(value, out var exact)) return position == exact;
        var parts = value.Split(',', 2, StringSplitOptions.TrimEntries);
        return parts.Length == 2 && int.TryParse(parts[0], out var min) && int.TryParse(parts[1], out var max)
            ? position >= min && position <= max
            : false;
    }

    internal sealed class SubsigMatches
    {
        public int Index { get; }
        public List<int> Positions { get; } = [];
        public int Count => Positions.Count;

        public SubsigMatches(int index) => Index = index;
    }

}
