using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;

namespace ClamGuard.Scanner;

/// <summary>
/// Trích xuất riêng PDF (embedded streams) và SWF (compressed streams).
/// </summary>
internal static class PdfSwfExtractor
{
    internal static List<Detection> ScanFlash(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (data.Length < 8) return results;
        if (data[..3].SequenceEqual("FWS"u8)) return results;
        if (data[..3].SequenceEqual("ZWS"u8)) return results; // LZMA SWF requires a dedicated decoder; keep type detection intact.
        if (!data[..3].SequenceEqual("CWS"u8)) return results;

        var advertised = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        var wanted = advertised >= 8 ? advertised - 8u : 0u;
        if (wanted == 0 || data.Length <= 8) return results;
        if (wanted > options.Limits.MaxFileSize || wanted > int.MaxValue)
        {
            budget.LimitExceeded = true;
            return results;
        }

        try
        {
            using var source = new MemoryStream(data.Slice(8).ToArray(), writable: false);
            using var zlib = new ZLibStream(source, CompressionMode.Decompress, leaveOpen: false);
            var decodedBody = ReadLimited(zlib, Math.Min(wanted, options.Limits.MaxFileSize));
            if (decodedBody.Length == 0) return results;
            if (!ArchiveScanner.ConsumeBudget(budget, options.Limits, decodedBody.Length)) return results;
            budget.Entries++;
            // Scan the reconstructed SWF as a FLASH child so Target:11 / Container:SWF
            // signatures can operate on the uncompressed tag stream.
            using var rebuilt = new MemoryStream(decodedBody.Length + 8);
            rebuilt.Write("FWS"u8);
            rebuilt.WriteByte(data[3]);
            rebuilt.Write(data.Slice(4, 4));
            rebuilt.Write(decodedBody);
            results.AddRange(ArchiveScanner.ScanChild(rebuilt.ToArray(), "decompressed.swf", "FLASH", state, options, parents, depth, budget, cancellationToken));
        }
        catch (InvalidDataException) { }
        catch (IOException) { }
        return results;
    }

    internal static List<Detection> ScanPdfEmbeddedStreams(
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
        if (options.EnableHeuristics && options.HeuristicEncryptedDoc && ascii.Contains("/Encrypt", StringComparison.Ordinal))
            results.Add(new Detection("Heuristics.Encrypted.PDF", SignatureType.Metadata, null, "heuristics", "PDF declares an encryption dictionary; encrypted content may be unscannable."));
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
            if (available <= 0) { search = endMarker + 9; continue; }
            if (available > options.Limits.MaxEmbeddedStreamSize) budget.LimitExceeded = true;
            if (available > options.Limits.MaxEmbeddedStreamSize) { search = endMarker + 9; continue; }
            var take = length is >= 0 and <= int.MaxValue ? Math.Min(length.Value, available) : available;
            if (take <= 0) { search = endMarker + 9; continue; }
            if (take > options.Limits.MaxEmbeddedStreamSize) { budget.LimitExceeded = true; search = endMarker + 9; continue; }

            var compressed = data.Slice(lineEnd, (int)take).ToArray();
            var earlyChange = TryReadPdfEarlyChange(dictionary);
            if (!TryDecodePdfFilters(compressed, filters, options.Limits.MaxFileSize, earlyChange, out var child))
            {
                search = endMarker + 9;
                continue;
            }
            if (!ArchiveScanner.ConsumeBudget(budget, options.Limits, child.Length)) break;
            budget.Entries++;
            results.AddRange(ArchiveScanner.ScanChild(child, "embedded-stream", "PDF", state, options, parents, depth, budget, cancellationToken));
            search = endMarker + 9;
        }
        if (budget.Entries >= options.Limits.MaxArchiveEntries && search < ascii.Length &&
            ascii.IndexOf("stream", search, StringComparison.Ordinal) >= 0)
            budget.LimitExceeded = true;
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
            var nibble = ArchiveScanner.HexNibble(b);
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
}
