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
    internal static string DetectType(ReadOnlySpan<byte> data, string path)
        => DetectType(data, path, null);

    internal static string DetectType(
        ReadOnlySpan<byte> data,
        string path,
        IReadOnlyList<ClamGuard.Database.Storage.FileTypeMagicRule>? fileTypeRules)
    {
        // ClamAV's primary file-typing mechanism is File Type Magic (FTM).
        // Mode 0 direct-magic rules are tried before the built-in fallbacks.
        if (data.Length != 0 && FileTypeMagicDetector.TryDetectDirect(data, fileTypeRules, out var magicType))
        {
            // CL_TYPE_BINARY_DATA is the fallback type in libclamav, not an
            // instruction to stop file-type refinement. Keep specialized built-in
            // checks active when an FTM rule only confirms generic binary data.
            if (!magicType.Equals("OTHER", StringComparison.OrdinalIgnoreCase))
            {
                if (magicType.Equals("ZIP", StringComparison.OrdinalIgnoreCase) && TryRefineZipType(data) is { } refinedZip)
                    return refinedZip;
                return magicType;
            }
        }

        if (data.Length >= 8 && data[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return "OLE2";
        if (data.Length >= 4 && data[..4].SequenceEqual(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' })) return "ELF";
        if (data.Length >= 3 && (data[..3].SequenceEqual("FWS"u8) || data[..3].SequenceEqual("CWS"u8) || data[..3].SequenceEqual("ZWS"u8))) return "FLASH";
        if (data.Length >= 2 && data[0] == 'M' && data[1] == 'Z')
        {
            // Keep MZ as a useful type hint for truncated files, but prefer a
            // validated PE header whenever the DOS header gives us enough data.
            if (data.Length >= 0x40)
            {
                var pe = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c, 4));
                if (pe >= 0 && pe <= data.Length - 4 && BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pe, 4)) == 0x00004550)
                    return "PE";
            }
            return "PE";
        }
        if (data.Length >= 4)
        {
            var magic = BinaryPrimitives.ReadUInt32BigEndian(data[..4]);
            if (magic is 0xFEEDFACE or 0xCEFAEDFE or 0xFEEDFACF or 0xCFFAEDFE or
                        0xCAFEBABE or 0xBEBAFECA or 0xCAFEBABF or 0xBFBAFECA) return "MACH-O";
        }
        if (LooksLikeAutoIt(data)) return "AUTOIT";
        if (LooksLikeInstallShield(data)) return "ISHIELD_MSI";
        var udfMarker = data.IndexOf("BEA01"u8);
        if (udfMarker >= 0 && udfMarker <= 32768) return "UDF";
        var utf16Html = DecodeUtf16Text(data);
        if (utf16Html is not null)
        {
            var prefix = utf16Html[..Math.Min(4096, utf16Html.Length)];
            if (prefix.IndexOf("<html", StringComparison.OrdinalIgnoreCase) >= 0 ||
                prefix.IndexOf("<!doctype", StringComparison.OrdinalIgnoreCase) >= 0)
                return "HTML_UTF16";
        }
        var mimeType = DetectMimeType(data);
        if (mimeType is not null) return mimeType;
        if (data.Length >= 5 && data[..5].SequenceEqual("%PDF-"u8)) return "PDF";
        if (data.Length >= 5 && data[..5].SequenceEqual("{\\rtf"u8)) return "RTF";
        if (data.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) == 0x223E9F78u) return "TNEF";
        if (data.Length >= 6 && data[..6].SequenceEqual("begin "u8)) return "UUENCODED";
        if (data.IndexOf("(This file must be converted with BinHex 4.0)"u8) >= 0) return "BINHEX";
        if (data.Length >= 4 && (data[..4].SequenceEqual(new byte[] { 0x50, 0x4b, 0x03, 0x04 }) ||
                                  data[..4].SequenceEqual(new byte[] { 0x50, 0x4b, 0x05, 0x06 }) ||
                                  data[..4].SequenceEqual(new byte[] { 0x50, 0x4b, 0x07, 0x08 })))
            return TryRefineZipType(data) ?? "ZIP";
        if (data.Length >= 2 && data[0] == 0x1f && data[1] == 0x8b) return "GZ";
        if (data.Length >= 3 && data[..3].SequenceEqual("BZh"u8)) return "BZ";
        if (data.Length >= 6 && data[..4].SequenceEqual("EGGA"u8) && data[4] == 0x00 && data[5] == 0x01) return "EGG";
        if (data.Length >= 4 && data[..4].SequenceEqual("ALZ\x01"u8)) return "ALZ";
        if (data.Length >= 16 && ArchiveScanner.IsSymbianSisHeader(data)) return "SIS";
        if (data.Length >= 10 &&
            BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) == 0x44445A53 &&
            BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4)) == 0x3327F088 &&
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2)) == 0x0041) return "SZDD";
        if (data.Length >= 6 && (data[..6].SequenceEqual("070701"u8) || data[..6].SequenceEqual("070702"u8))) return "CPIO_NEWC";
        if (data.Length >= 6 && data[..6].SequenceEqual("070707"u8)) return "CPIO_ODC";
        if (data.Length >= 2 && ((data[0] == 0xC7 && data[1] == 0x71) || (data[0] == 0x71 && data[1] == 0xC7))) return "CPIO_OLD";
        if (data.Length >= 8 && data[..8].SequenceEqual(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) return "7Z";
        if (data.Length >= 7 && data[..7].SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 })) return "RAR";
        if (data.Length >= 2 && data[0] == 0x60 && data[1] == 0xEA) return "ARJ";
        if (data.Length >= 4 && data[..4].SequenceEqual("MSCF"u8)) return "CAB";
        if (data.Length >= 4 && data[..4].SequenceEqual("ITSF"u8)) return "CHM";
        if (data.Length >= 4 && data[..4].SequenceEqual("xar!"u8)) return "XAR";
        if (data.Length >= 32774 && data.Slice(32769, 5).SequenceEqual("CD001"u8)) return "ISO";
        if (data.Length >= 512 && (data[^512..^508].SequenceEqual("koly"u8) || data[^512..].Slice(0, 4).SequenceEqual("koly"u8))) return "DMG";
        if (data.Length >= 6 && data[..6].SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 })) return "XZ";
        if (data.Length >= 512 && data.Slice(257, 5).SequenceEqual("ustar"u8)) return "POSIX_TAR";
        if (data.Length >= 512 && LooksLikeTarHeader(data[..512])) return "OLD_TAR";
        if (data.Length >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4e && data[3] == 0x47) return "PNG";
        if (data.Length >= 3 && data[..3].SequenceEqual(new byte[] { 0xff, 0xd8, 0xff })) return "JPEG";
        if (data.Length >= 3 && data[..3].SequenceEqual("GIF"u8)) return "GIF";
        if (data.Length >= 2 && data[0] == 'B' && data[1] == 'M') return "GRAPHICS";

        // Mode 1 FTM rules are loaded into ClamAV's content matcher and are used
        // for retyping text/binary layers after the direct magic pass.
        if (fileTypeRules is not null && fileTypeRules.Count != 0)
        {
            var baseType = LooksLikeAsciiText(data) ? "ASCII" : "OTHER";
            if (FileTypeMagicDetector.TryDetectContent(data, fileTypeRules, baseType, out var contentType))
                return contentType;
        }

        var ext = Path.GetExtension(path).ToLowerInvariant();
        var extensionType = ext switch
        {
            ".exe" or ".dll" or ".sys" => "PE",
            ".pdf" => "PDF",
            ".rtf" => "RTF",
            ".hqx" => "BINHEX",
            ".tnef" => "TNEF",
            ".uue" or ".uu" => "UUENCODED",
            ".zip" or ".jar" or ".apk" or ".docx" or ".xlsx" or ".pptx" => "ZIP",
            ".rar" => "RAR",
            ".7z" => "7Z",
            ".egg" => "EGG",
            ".alz" => "ALZ",
            ".sis" => "SIS",
            ".szdd" => "SZDD",
            ".nsis" => "NULSFT",
            ".a3x" or ".a3x64" or ".au3" => "AUTOIT",
            ".ism" or ".ish" => "ISHIELD_MSI",
            ".arj" => "ARJ",
            ".cab" => "CAB",
            ".chm" => "CHM",
            ".iso" => "ISO",
            ".xar" or ".pkg" => "XAR",
            ".dmg" => "DMG",
            ".swf" => "FLASH",
            ".lha" or ".lzh" => "LHA",
            ".gz" or ".tgz" => "GZ",
            ".bz2" => "BZ",
            ".xz" => "XZ",
            ".tar" => "POSIX_TAR",
            ".cpio" => "CPIO_NEWC",
            ".doc" or ".xls" or ".ppt" => "OLE2",
            ".htm" or ".html" => "HTML",
            ".eml" or ".msg" => "MAIL",
            ".mht" or ".mhtml" => "MHTML",
            ".class" => "JAVA",
            ".txt" or ".log" or ".csv" or ".xml" or ".json" or ".js" or ".css" => "ASCII",
            _ => "Unknown"
        };
        if (!extensionType.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) return extensionType;
        return LooksLikeAsciiText(data) ? "ASCII" : "Unknown";
    }

    private static string? TryRefineZipType(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        ReadOnlySpan<byte> localHeader = new byte[] { 0x50, 0x4b, 0x03, 0x04 };
        var searchOffset = 0;
        var checkedHeaders = 0;
        while (checkedHeaders < 3 && searchOffset < data.Length)
        {
            var relative = data[searchOffset..].IndexOf(localHeader);
            if (relative < 0) break;
            var header = searchOffset + relative;
            if (header > data.Length - 30) break;

            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(header + 26, 2));
            var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(header + 28, 2));
            var nameStart = header + 30;
            if (nameLength > data.Length - nameStart) break;
            var name = Encoding.UTF8.GetString(data.Slice(nameStart, nameLength)).Replace('\\', '/');

            if (name.StartsWith("word/", StringComparison.OrdinalIgnoreCase)) return "OOXML_WORD";
            if (name.StartsWith("xl/", StringComparison.OrdinalIgnoreCase)) return "OOXML_XL";
            if (name.StartsWith("ppt/", StringComparison.OrdinalIgnoreCase)) return "OOXML_PPT";
            if (name.Equals("Contents/content.hpf", StringComparison.OrdinalIgnoreCase)) return "OOXML_HWP";

            checkedHeaders++;
            var next = nameStart + nameLength + extraLength;
            searchOffset = next > header ? Math.Min(next, data.Length) : header + 4;
        }
        return null;
    }

    private static string? DetectMimeType(ReadOnlySpan<byte> data)
    {
        var sample = Encoding.Latin1.GetString(data[..Math.Min(data.Length, 64 * 1024)]);
        var headersEnd = sample.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headersEnd < 0) headersEnd = sample.IndexOf("\n\n", StringComparison.Ordinal);
        if (headersEnd < 0) headersEnd = Math.Min(sample.Length, 16 * 1024);
        var headers = sample[..headersEnd];
        var hasMime = Regex.IsMatch(headers, @"(?im)^\s*MIME-Version\s*:");
        var hasContentType = Regex.IsMatch(headers, @"(?im)^\s*Content-Type\s*:");
        var hasMailHeader = Regex.IsMatch(headers, @"(?im)^\s*(From|Received|Message-Id)\s*:");
        if (!hasContentType || (!hasMime && !hasMailHeader)) return null;
        return headers.IndexOf("multipart/related", StringComparison.OrdinalIgnoreCase) >= 0 ? "MHTML" : "MAIL";
    }

    private static bool LooksLikeAutoIt(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> magic = new byte[] { 0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D, 0x41, 0x55, 0x53, 0x21, 0x45, 0x41, 0x30 };
        for (var i = 0; i + magic.Length + 1 < data.Length; i++)
        {
            if (!data.Slice(i, magic.Length).SequenceEqual(magic)) continue;
            var version = data[i + magic.Length];
            if (version is 0x35 or 0x36) return true;
        }
        return false;
    }

    private static bool LooksLikeInstallShield(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> prefix = "InstallShield\0"u8;
        for (var i = 0; i + prefix.Length + 0x120 < data.Length; i++)
        {
            if (!data.Slice(i, prefix.Length).SequenceEqual(prefix)) continue;
            var p = i + prefix.Length + 292;
            if (p + 8 + 16 + 4 > data.Length) return false;
            if (data[p] != 0x06 || !data.Slice(p + 1, 7).SequenceEqual(new byte[7])) continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(p + 24, 4)) == 1) return true;
        }
        return false;
    }

    private static bool LooksLikeTarHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < 512) return false;
        var nameEnd = header[..100].IndexOf((byte)0);
        if (nameEnd == 0) return false;
        var storedText = Encoding.ASCII.GetString(header.Slice(148, 8)).TrimEnd('\0').Trim();
        if (!long.TryParse(storedText, System.Globalization.NumberStyles.Integer, null, out var stored)) return false;
        var sum = 0L;
        for (var i = 0; i < 512; i++) sum += i is >= 148 and < 156 ? 32 : header[i];
        return stored > 0 && sum == stored;
    }

    private static bool LooksLikeAsciiText(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data.Length > 4 * 1024 * 1024) return false;
        var printable = 0;
        var suspicious = 0;
        foreach (var b in data)
        {
            if (b == 0) return false;
            if (b is >= 0x20 and <= 0x7e || b is 0x09 or 0x0a or 0x0d or 0x0c) printable++;
            else if (b < 0x20) suspicious++;
            else suspicious++;
        }
        return printable >= data.Length * 0.90 && suspicious <= data.Length * 0.10;
    }

    private static string DetectType(string path) => DetectType(ReadOnlySpan<byte>.Empty, path);
}
