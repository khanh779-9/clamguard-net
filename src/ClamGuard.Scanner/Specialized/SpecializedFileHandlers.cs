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
    public static IReadOnlyList<Detection> ScanPreRaw(
        ReadOnlySpan<byte> data,
        string fileType,
        CompiledState state,
        ScanOptions options,
        string path,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty) return [];

        // ClamAV scan_layer dispatches each specialized handler only when its
        // corresponding module-specific dconf capability is enabled.
        var dconf = state.Database.DynamicConfiguration;
        return fileType.ToUpperInvariant() switch
        {
            "HWP3" when options.ScanHWP3 && (dconf.Doc & DynamicConfigFlags.DocumentHwp) != 0 => ScanHwp3(data, state, options, path, cancellationToken),
            "HWPOLE2" when options.ScanOLE2 && (dconf.Archive & DynamicConfigFlags.ArchiveOle2) != 0 => ScanHwpoLe2(data, state, options, path, cancellationToken),
            "HTML" when (dconf.Doc & DynamicConfigFlags.DocumentHtml) != 0 => ScanHtmlVariants(data, state, options, path, cancellationToken),
            "HTML_UTF16" when (dconf.Doc & DynamicConfigFlags.DocumentHtml) != 0 => ScanHtmlUtf16Variants(data, state, options, path, cancellationToken),
            "ONENOTE" when options.ScanOneNote && (dconf.Archive & DynamicConfigFlags.DocumentOneNote) != 0 => ScanOneNoteAttachments(data, state, options, path, cancellationToken),
            "XDP" when options.ScanPDF && (dconf.Doc & DynamicConfigFlags.DocumentPdf) != 0 => ScanXdp(data, state, options, path, cancellationToken),
            "XML_WORD" or "XML_XL" when options.ScanXMLDocs && (dconf.Doc & DynamicConfigFlags.DocumentMsXml) != 0 => ScanMsXml(data, state, options, path, cancellationToken),
            "XML_HWP" when options.ScanXMLDocs && (dconf.Doc & DynamicConfigFlags.DocumentHwp) != 0 => ScanHwpMl(data, state, options, path, cancellationToken),
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

}
