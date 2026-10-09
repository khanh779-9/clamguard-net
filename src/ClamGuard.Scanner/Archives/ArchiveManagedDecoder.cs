using SharpCompress.Archives;
using SharpCompress.Readers;
using ClamGuard.Core;

namespace ClamGuard.Scanner;

/// <summary>
/// Managed archive backend used for formats supported by SharpCompress.
/// It intentionally returns only bounded entry data and metadata needed by
/// ClamGuard's archive scanner; it does not extract to the filesystem.
/// </summary>
internal static class ArchiveManagedDecoder
{
    private const int MaxMembers = 10000;

    public static bool Supports(string format) => format is "RAR" or "7Z" or "ARJ";

    public static IEnumerable<ExternalArchiveMember> ExtractMembers(
        byte[] data,
        string format,
        ScanLimits limits,
        CancellationToken cancellationToken)
    {
        if (format is not ("RAR" or "7Z" or "ARJ"))
            yield break;

        using var stream = new MemoryStream(data, writable: false);
        if (format is "RAR" or "7Z")
        {
            using var archive = ArchiveFactory.OpenArchive(
                stream,
                new ReaderOptions { LookForHeader = true, LeaveStreamOpen = true });

            foreach (var item in EnumerateEntries(archive.Entries, limits, cancellationToken))
                yield return item;
            yield break;
        }

        using var reader = ReaderFactory.OpenReader(
            stream,
            new ReaderOptions { LookForHeader = true, LeaveStreamOpen = true });
        var position = 0u;
        while (reader.MoveToNextEntry())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (position >= Math.Min(MaxMembers, limits.MaxArchiveEntries))
                yield break;

            position++;
            var entry = reader.Entry;
            var name = entry.Key ?? string.Empty;
            var size = entry.Size;
            var compressedSize = entry.CompressedSize;
            var encrypted = entry.IsEncrypted;
            uint? crc32 = null;
            if (entry.Crc >= 0 && entry.Crc <= uint.MaxValue)
                crc32 = (uint)entry.Crc;

            if (entry.IsDirectory || encrypted || size < 0 || size > limits.MaxFileSize)
            {
                yield return CreateMetadataOnly(name, size, compressedSize, encrypted, crc32, position, entry.IsDirectory);
                continue;
            }

            if (compressedSize > 0 && (double)size > compressedSize * (double)Math.Max(1L, limits.MaxArchiveCompressionRatio))
            {
                yield return CreateMetadataOnly(name, size, compressedSize, encrypted, crc32, position, entry.IsDirectory);
                continue;
            }

            byte[] child;
            try
            {
                using var entryStream = reader.OpenEntryStream();
                child = ReadBounded(entryStream, size, limits.MaxFileSize, cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException or ArgumentException)
            {
                child = [];
            }

            yield return child.LongLength == size
                ? new ExternalArchiveMember(name, size, child, compressedSize >= 0 ? compressedSize : null, encrypted, crc32, position, entry.IsDirectory, CanExtract: true)
                : CreateMetadataOnly(name, size, compressedSize, encrypted, crc32, position, entry.IsDirectory);
        }
    }

    private static IEnumerable<ExternalArchiveMember> EnumerateEntries(
        IEnumerable<SharpCompress.Archives.IArchiveEntry> entries,
        ScanLimits limits,
        CancellationToken cancellationToken)
    {
        var position = 0u;
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (position >= Math.Min(MaxMembers, limits.MaxArchiveEntries))
                yield break;

            position++;
            var name = entry.Key ?? string.Empty;
            var size = entry.Size;
            var compressedSize = entry.CompressedSize;
            var encrypted = entry.IsEncrypted;
            uint? crc32 = entry.Crc >= 0 && entry.Crc <= uint.MaxValue ? (uint)entry.Crc : null;

            if (entry.IsDirectory || encrypted || size < 0 || size > limits.MaxFileSize ||
                (compressedSize > 0 && (double)size > compressedSize * (double)Math.Max(1L, limits.MaxArchiveCompressionRatio)))
            {
                yield return CreateMetadataOnly(name, size, compressedSize, encrypted, crc32, position, entry.IsDirectory);
                continue;
            }

            byte[] child;
            try
            {
                using var entryStream = entry.OpenEntryStream();
                child = ReadBounded(entryStream, size, limits.MaxFileSize, cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException or ArgumentException)
            {
                child = [];
            }

            yield return child.LongLength == size
                ? new ExternalArchiveMember(name, size, child, compressedSize >= 0 ? compressedSize : null, encrypted, crc32, position, entry.IsDirectory, CanExtract: true)
                : CreateMetadataOnly(name, size, compressedSize, encrypted, crc32, position, entry.IsDirectory);
        }
    }

    private static ExternalArchiveMember CreateMetadataOnly(
        string name, long size, long compressedSize, bool encrypted, uint? crc32, uint position, bool isDirectory) =>
        new(name, size, [], compressedSize >= 0 ? compressedSize : null, encrypted, crc32, position, isDirectory, CanExtract: false);

    private static byte[] ReadBounded(Stream input, long expectedSize, long maxSize, CancellationToken token)
    {
        if (expectedSize < 0 || expectedSize > maxSize || expectedSize > int.MaxValue)
            return [];

        using var output = new MemoryStream((int)expectedSize);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            if (output.Length > maxSize - read)
                throw new InvalidDataException("Archive member exceeded the configured scan limit.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }
}
