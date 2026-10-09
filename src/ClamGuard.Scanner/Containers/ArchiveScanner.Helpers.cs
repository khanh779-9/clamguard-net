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

}
