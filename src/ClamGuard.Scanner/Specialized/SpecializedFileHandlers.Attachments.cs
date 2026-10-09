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

}
