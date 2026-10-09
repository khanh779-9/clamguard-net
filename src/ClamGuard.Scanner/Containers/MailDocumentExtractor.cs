using System.Buffers.Binary;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;

namespace ClamGuard.Scanner;

/// <summary>
/// Trích xuất riêng các định dạng mail / tài liệu đính kèm: MIME (MAIL, MHTML),
/// uuencode, BinHex 4.0 và TNEF (Outlook).
/// </summary>
internal static class MailDocumentExtractor
{
    internal static List<Detection> ScanBinHex(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        var marker = "(This file must be converted with BinHex 4.0)"u8;
        var markerPos = data.IndexOf(marker);
        if (markerPos < 0) return results;
        var colonRel = data[(markerPos + marker.Length)..].IndexOf((byte)':');
        if (colonRel < 0) return results;
        var colon = markerPos + marker.Length + colonRel;
        const string alphabet = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        var reverse = new sbyte[128];
        Array.Fill(reverse, (sbyte)-1);
        for (var i = 0; i < alphabet.Length; i++) reverse[(byte)alphabet[i]] = (sbyte)i;
        using var decoded = new MemoryStream();
        uint acc = 0; var bits = 0; var rle = false; byte last = 0;
        for (var i = colon + 1; i < data.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ch = data[i];
            if (ch == (byte)':') break;
            if (ch is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') continue;
            if (ch >= 128 || reverse[ch] < 0) return results;
            acc = (acc << 6) | (uint)(byte)reverse[ch]; bits += 6;
            while (bits >= 8)
            {
                bits -= 8; var value = (byte)((acc >> bits) & 0xff);
                if (rle) {
                    rle = false;
                    if (value == 0) { decoded.WriteByte(0x90); last = 0x90; }
                    else { var repeat = value - 1; if (repeat > options.Limits.MaxEmbeddedStreamSize - decoded.Length) { budget.LimitExceeded = true; return results; } for (var n = 0; n < repeat; n++) decoded.WriteByte(last); }
                }
                else if (value == 0x90) rle = true;
                else { decoded.WriteByte(value); last = value; }
                if (decoded.Length > options.Limits.MaxEmbeddedStreamSize || decoded.Length > options.Limits.MaxFileSize)
                {
                    budget.LimitExceeded = true;
                    return results;
                }
            }
        }
        var raw = decoded.ToArray();
        if (raw.Length < 20) return results;
        var nameLen = raw[0];
        var headerLen = 1 + nameLen + 1 + 4 + 4 + 2 + 4 + 4 + 2;
        if (raw.Length < headerLen) return results;
        var lenOffset = 1 + nameLen + 1 + 4 + 4 + 2;
        var dataLen = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(lenOffset, 4));
        var resLen = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(lenOffset + 4, 4));
        var dataStart = headerLen;
        if ((ulong)dataStart + dataLen + 2UL > (ulong)raw.Length) return results;
        var name = nameLen == 0 ? "binhex-data" : Encoding.ASCII.GetString(raw, 1, nameLen);
        var dataCount = (int)Math.Min((ulong)dataLen, (ulong)options.Limits.MaxFileSize);
        if (dataLen > (uint)dataCount) budget.LimitExceeded = true;
        if (dataCount > 0)
        {
            if (budget.Entries >= options.Limits.MaxArchiveEntries) budget.LimitExceeded = true;
            else
            {
                var fork = raw.AsSpan(dataStart, dataCount).ToArray();
                if (ArchiveScanner.ConsumeBudget(budget, options.Limits, fork.Length))
                {
                    budget.Entries++;
                    results.AddRange(ArchiveScanner.ScanChild(fork, name, "BINHEX", state, options, parents, depth, budget, cancellationToken));
                }
            }
        }
        var resourceStart = dataStart + (int)dataLen + 2;
        if ((ulong)resourceStart + resLen + 2UL <= (ulong)raw.Length && resLen > 0 && resLen <= (uint)options.Limits.MaxEmbeddedStreamSize)
        {
            if (budget.Entries >= options.Limits.MaxArchiveEntries) budget.LimitExceeded = true;
            else
            {
                var fork = raw.AsSpan(resourceStart, (int)resLen).ToArray();
                if (ArchiveScanner.ConsumeBudget(budget, options.Limits, fork.Length))
                {
                    budget.Entries++;
                    results.AddRange(ArchiveScanner.ScanChild(fork, name + ".rsrc", "BINHEX", state, options, parents, depth, budget, cancellationToken));
                }
            }
        }
        else if (resLen > options.Limits.MaxEmbeddedStreamSize) budget.LimitExceeded = true;
        return results;
    }

    internal static List<Detection> ScanUuEncoded(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>(); var text = Encoding.ASCII.GetString(data); using var output = new MemoryStream(); string? fileName = null; var started = false;
        foreach (var rawLine in text.Split('\n'))
        {
            cancellationToken.ThrowIfCancellationRequested(); var line = rawLine.TrimEnd('\r');
            if (!started) { if (!line.StartsWith("begin ", StringComparison.Ordinal)) continue; var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries); if (parts.Length < 3) return results; fileName = parts[2]; started = true; continue; }
            if (line.Equals("end", StringComparison.OrdinalIgnoreCase)) break; if (line.Length == 0) continue;
            var expected = (line[0] - ' ') & 0x3f; if (expected == 0) continue; var i = 1; var produced = 0;
            while (i + 3 < line.Length && produced < expected) { var c0=UuValue(line[i++]); var c1=UuValue(line[i++]); var c2=UuValue(line[i++]); var c3=UuValue(line[i++]); if (produced < expected) { output.WriteByte((byte)((c0<<2)|(c1>>4))); produced++; } if (produced < expected) { output.WriteByte((byte)((c1<<4)|(c2>>2))); produced++; } if (produced < expected) { output.WriteByte((byte)((c2<<6)|c3)); produced++; } if (output.Length > options.Limits.MaxFileSize || output.Length > options.Limits.MaxEmbeddedStreamSize) { budget.LimitExceeded = true; return results; } }
            if (produced != expected) break;
        }
        if (!started || output.Length == 0) return results;
        if (budget.Entries >= options.Limits.MaxArchiveEntries) { budget.LimitExceeded = true; return results; }
        var child = output.ToArray();
        if (!ArchiveScanner.ConsumeBudget(budget, options.Limits, child.Length)) return results;
        budget.Entries++;
        results.AddRange(ArchiveScanner.ScanChild(child, fileName ?? "uuencoded", "UUENCODED", state, options, parents, depth, budget, cancellationToken));
        return results;
    }

    private static int UuValue(char c) => c < ' ' || c > '`' ? 0 : (c - ' ') & 0x3f;

    internal static List<Detection> ScanTnef(
        ReadOnlySpan<byte> data, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>(); if (data.Length < 6 || BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) != 0x223E9F78u) return results;
        var pos = 6; MemoryStream? attachment = null; string? attachmentName = null;
        void FlushAttachment()
        {
            if (attachment is null || attachment.Length == 0) return;
            var child = attachment.ToArray();
            if (budget.Entries >= options.Limits.MaxArchiveEntries) budget.LimitExceeded = true;
            else if (ArchiveScanner.ConsumeBudget(budget, options.Limits, child.Length))
            {
                budget.Entries++;
                results.AddRange(ArchiveScanner.ScanChild(child, attachmentName ?? "tnef-attachment", "TNEF", state, options, parents, depth, budget, cancellationToken));
            }
            attachment.Dispose(); attachment = null; attachmentName = null;
        }
        while (pos + 11 <= data.Length && budget.Entries < options.Limits.MaxArchiveEntries)
        {
            cancellationToken.ThrowIfCancellationRequested(); var level=data[pos++]; var typeTag=BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pos,4)); pos+=4; var tag=(ushort)(typeTag & 0xffff); var length=BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos,4)); pos+=4;
            if (length < 0 || pos + (long)length + 2 > data.Length) break;
            if (length > options.Limits.MaxFileSize) { budget.LimitExceeded = true; break; }
            var value=data.Slice(pos,length); pos += length + 2;
            if (level==2 && tag==0x800f) { attachment ??= new MemoryStream(); if (attachment.Length + value.Length > options.Limits.MaxEmbeddedStreamSize) { FlushAttachment(); continue; } attachment.Write(value); }
            else if (level==2 && tag==0x8010) { if (attachment is not null && attachment.Length > 0 && attachmentName is not null) FlushAttachment(); attachmentName=Encoding.ASCII.GetString(value).TrimEnd('\0',' ','\r','\n'); }
        }
        if (pos + 11 <= data.Length && budget.Entries >= options.Limits.MaxArchiveEntries)
            budget.LimitExceeded = true;
        FlushAttachment(); return results;
    }

    internal static List<Detection> ScanMimeMail(
        ReadOnlySpan<byte> data, string mailType, CompiledState state, ScanOptions options, IReadOnlyList<string> parents, int depth, ArchiveScanBudget budget, CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (depth >= Math.Max(1, options.Limits.MaxArchiveDepth))
        {
            budget.LimitExceeded = true;
            return results;
        }
        if (data.Length == 0) return results;
        var text = Encoding.Latin1.GetString(data);
        var headerEnd = ArchiveScanner.FindHeaderEnd(text);
        if (headerEnd < 0) return results;
        var headers = text[..headerEnd];
        var bodyStart = headerEnd;
        while (bodyStart < text.Length && (text[bodyStart] == '\r' || text[bodyStart] == '\n')) bodyStart++;

        var contentType = GetHeader(headers, "Content-Type");
        var boundary = GetBoundary(contentType);
        if (string.IsNullOrWhiteSpace(boundary)) return results;

        var body = text[bodyStart..];
        var marker = "--" + boundary;
        var search = 0;
        while (search < body.Length && budget.Entries < options.Limits.MaxArchiveEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var start = body.IndexOf(marker, search, StringComparison.Ordinal);
            if (start < 0) break;
            start += marker.Length;
            if (start + 2 <= body.Length && body[start..].StartsWith("--", StringComparison.Ordinal)) break;
            while (start < body.Length && body[start] is '\r' or '\n' or ' ') start++;
            var partEndMarker = body.IndexOf(marker, start, StringComparison.Ordinal);
            if (partEndMarker < 0) partEndMarker = body.Length;
            var part = body[start..partEndMarker].TrimStart('\r', '\n');
            var partHeaderEnd = ArchiveScanner.FindHeaderEnd(part);
            if (partHeaderEnd < 0) { search = partEndMarker + marker.Length; continue; }
            var partHeaders = part[..partHeaderEnd];
            var partBodyStart = partHeaderEnd;
            while (partBodyStart < part.Length && (part[partBodyStart] == '\r' || part[partBodyStart] == '\n')) partBodyStart++;
            var rawPartBody = part[partBodyStart..].TrimEnd('\r', '\n');
            var decoded = DecodeMimeBody(rawPartBody, GetHeader(partHeaders, "Content-Transfer-Encoding"), options.Limits.MaxEmbeddedStreamSize);
            if (decoded is not null && decoded.Length != 0)
            {
                if (!ArchiveScanner.ConsumeBudget(budget, options.Limits, decoded.Length)) break;
                budget.Entries++;
                var childName = GetMimeFilename(partHeaders) ?? (mailType == "MHTML" ? "mhtml-part" : "mail-part");
                results.AddRange(ArchiveScanner.ScanChild(decoded, childName, mailType, state, options, parents, depth, budget, cancellationToken));
            }
            search = partEndMarker + marker.Length;
        }
        if (budget.Entries >= options.Limits.MaxArchiveEntries && search < body.Length)
        {
            var nextMarker = body.IndexOf(marker, search, StringComparison.Ordinal);
            if (nextMarker >= 0)
            {
                nextMarker += marker.Length;
                while (nextMarker < body.Length && (body[nextMarker] is '\r' or '\n' or ' ' or '\t')) nextMarker++;
                if (nextMarker + 2 > body.Length || !body[nextMarker..].StartsWith("--", StringComparison.Ordinal))
                    budget.LimitExceeded = true;
            }
        }
        return results;
    }

    private static string? GetHeader(string headers, string name)
    {
        var lines = headers.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        string? current = null;
        var value = new StringBuilder();
        foreach (var raw in lines)
        {
            if (raw.Length != 0 && char.IsWhiteSpace(raw[0]) && current is not null)
            {
                value.Append(' ').Append(raw.Trim());
                continue;
            }
            var colon = raw.IndexOf(':');
            if (colon <= 0) { current = null; continue; }
            current = raw[..colon].Trim();
            if (current.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                value.Clear();
                value.Append(raw[(colon + 1)..].Trim());
            }
        }
        return value.Length == 0 ? null : value.ToString();
    }

    private static string? GetBoundary(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return null;
        var marker = "boundary=";
        var at = contentType.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        var value = contentType[(at + marker.Length)..].Trim();
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"') value = value[1..^1];
        var semi = value.IndexOf(';');
        return (semi >= 0 ? value[..semi] : value).Trim();
    }

    private static string? GetMimeFilename(string headers)
    {
        foreach (var header in new[] { "Content-Disposition", "Content-Type" })
        {
            var value = GetHeader(headers, header);
            if (value is null) continue;
            foreach (var key in new[] { "filename=", "name=" })
            {
                var at = value.IndexOf(key, StringComparison.OrdinalIgnoreCase);
                if (at < 0) continue;
                var name = value[(at + key.Length)..].Trim();
                if (name.Length >= 2 && name[0] == '"' && name[^1] == '"') name = name[1..^1];
                var semi = name.IndexOf(';');
                if (semi >= 0) name = name[..semi];
                if (name.Length > 0) return name.Trim();
            }
        }
        return null;
    }

    private static byte[]? DecodeMimeBody(string body, string? transferEncoding, long maxBytes)
    {
        try
        {
            if (transferEncoding?.Trim().Equals("base64", StringComparison.OrdinalIgnoreCase) == true)
            {
                var normalized = new string(body.Where(static c => !char.IsWhiteSpace(c)).ToArray());
                if (normalized.Length > ((maxBytes + 2) / 3) * 4 + 4) return null;
                return Convert.FromBase64String(normalized);
            }
            if (transferEncoding?.Trim().Equals("quoted-printable", StringComparison.OrdinalIgnoreCase) == true)
                return DecodeQuotedPrintable(body, maxBytes);
            var raw = Encoding.Latin1.GetBytes(body);
            return raw.LongLength <= maxBytes ? raw : null;
        }
        catch (FormatException) { return null; }
        catch (OverflowException) { return null; }
    }

    private static byte[]? DecodeQuotedPrintable(string body, long maxBytes)
    {
        using var output = new MemoryStream();
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c == '=')
            {
                if (i + 2 < body.Length && body[i + 1] == '\r' && body[i + 2] == '\n') { i += 2; continue; }
                if (i + 2 < body.Length && body[i + 1] == '\n') { i += 1; continue; }
                if (i + 2 < body.Length)
                {
                    var hi = ArchiveScanner.HexNibble((byte)body[i + 1]);
                    var lo = ArchiveScanner.HexNibble((byte)body[i + 2]);
                    if (hi >= 0 && lo >= 0) { output.WriteByte((byte)((hi << 4) | lo)); i += 2; if (output.Length > maxBytes) return null; continue; }
                }
            }
            output.WriteByte((byte)c);
            if (output.Length > maxBytes) return null;
        }
        return output.ToArray();
    }
}
