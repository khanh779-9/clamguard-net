using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using ClamGuard.Core;

namespace ClamGuard.Database;

public sealed record CvdHeader(
    DatabaseFormat Format,
    string CreationTime,
    uint Version,
    uint SignatureCount,
    uint FunctionalityLevel,
    string Md5,
    string DigitalSignature,
    string Builder,
    long CreationTimestamp);

public static class CvdReader
{
    private const int HeaderSize = 512;

    public static CvdHeader ReadHeader(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = File.OpenRead(path);
        var buffer = new byte[HeaderSize];
        var count = stream.Read(buffer, 0, buffer.Length);
        if (count < 11)
            throw new InvalidDataException("The CVD header is shorter than the required magic prefix.");

        var text = Encoding.ASCII.GetString(buffer, 0, count);
        var lineEnd = text.IndexOfAny(['\r', '\n']);
        if (lineEnd >= 0)
            text = text[..lineEnd];

        return ParseHeader(text.TrimEnd(' ', '\t', '\0'), Path.GetExtension(path));
    }

    public static CvdHeader ParseHeader(string text, string extension = ".cvd")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        var parts = text.Split(':');
        // Fields are: magic, time, version, signature count, functionality level,
        // MD5, digital signature, builder, optional creation timestamp.
        if (parts.Length < 8 || !parts[0].Equals("ClamAV-VDB", StringComparison.Ordinal))
            throw new FormatException("The supplied text is not a valid CVD header.");

        static uint ParseUInt(string value, string field)
            => uint.TryParse(value, out var number)
                ? number
                : throw new FormatException($"Invalid {field}: {value}");

        var timestamp = parts.Length >= 9 && long.TryParse(parts[8], out var seconds)
            ? seconds
            : 0;

        var cleanExt = extension.ToLowerInvariant();
        if (cleanExt.EndsWith(".tmp", StringComparison.Ordinal))
            cleanExt = ".cvd";

        var format = cleanExt switch
        {
            ".cld" => DatabaseFormat.Cld,
            ".cud" => DatabaseFormat.Cud,
            ".cvd" => DatabaseFormat.Cvd,
            _ => throw new FormatException($"Unsupported CVD container extension: {extension}")
        };

        return new CvdHeader(
            format,
            parts[1],
            ParseUInt(parts[2], "version"),
            ParseUInt(parts[3], "signature count"),
            ParseUInt(parts[4], "functionality level"),
            parts[5],
            parts[6],
            parts[7],
            timestamp);
    }

    public static Task ExtractAsync(
        string path,
        string destination,
        CancellationToken cancellationToken = default)
    {
        Extract(path, destination, cancellationToken);
        return Task.CompletedTask;
    }

    public static void Extract(
        string path,
        string destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        Directory.CreateDirectory(destination);

        using var input = File.OpenRead(path);
        if (input.Length < HeaderSize + 7)
            throw new InvalidDataException("CVD payload is truncated before the archive data.");

        input.Position = HeaderSize;
        Span<byte> payloadMarker = stackalloc byte[7];
        try
        {
            input.ReadExactly(payloadMarker);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidDataException("CVD payload is truncated before the archive data.", ex);
        }
        input.Position = HeaderSize;

        // ClamAV 1.5.4's cli_tgzload() treats a payload beginning with "COPYING"
        // as an uncompressed tar stream; otherwise it opens the payload with zlib.
        using Stream payload = payloadMarker.SequenceEqual("COPYING"u8)
            ? input
            : new GZipStream(input, CompressionMode.Decompress, leaveOpen: true);
        using var tar = new TarReader(payload, leaveOpen: true);

        var entryCount = 0;
        long extractedBytes = 0;
        const int maxEntries = 100_000;
        const long maxExtractedBytes = 2L * 1024 * 1024 * 1024;

        while (true)
        {
            TarEntry? entry;
            try
            {
                entry = tar.GetNextEntry();
            }
            catch (EndOfStreamException)
            {
                // ClamAV CVD archives may terminate at end-of-archive without standard trailing zero blocks.
                break;
            }
            if (entry is null) break;

            cancellationToken.ThrowIfCancellationRequested();

            if (++entryCount > maxEntries)
                throw new InvalidDataException("The database archive contains too many entries.");

            var name = entry.Name.Replace('\\', '/');
            if (string.IsNullOrWhiteSpace(name) || name.Contains('/') || name is "." or ".." || Path.IsPathRooted(name))
                throw new InvalidDataException($"Unsafe database entry path: {name}");

            if (entry.DataStream is null)
                continue;

            var target = Path.Combine(destination, name);
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: false);
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = entry.DataStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                extractedBytes += read;
                if (extractedBytes > maxExtractedBytes)
                    throw new InvalidDataException("The database archive exceeds the extraction size limit.");
                output.Write(buffer, 0, read);
            }
        }
    }
}
