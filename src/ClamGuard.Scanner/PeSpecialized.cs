using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal sealed record PeSectionView(string Name, long RawOffset, long RawSize, long VirtualAddress, long VirtualSize);

internal sealed record PeImport(string Library, string Function);

internal sealed class PeImageView
{
    public required bool IsPe32Plus { get; init; }
    public required int NumberOfSections { get; init; }
    public required int OptionalHeaderOffset { get; init; }
    public required int OptionalHeaderSize { get; init; }
    public required int DataDirectoryOffset { get; init; }
    public required IReadOnlyList<PeSectionView> Sections { get; init; }
    public required uint ImportRva { get; init; }
    public required uint ImportSize { get; init; }
    public required long OverlayOffset { get; init; }
    public required long OverlaySize { get; init; }
}

internal static class PeSpecializedMatcher
{
    private const uint ImportDirectoryIndex = 1;
    private const int MaxImports = 65536;
    private const int MaxImportNameLength = 4096;

    public static async Task<IReadOnlyList<Detection>> MatchSectionsFromFileAsync(
        string path,
        long fileLength,
        IReadOnlyList<HashSignature> rules,
        int maxMatches,
        CancellationToken cancellationToken)
    {
        if (rules.Count == 0 || fileLength <= 0)
            return [];

        const int HeaderProbeSize = 4 * 1024 * 1024;
        var headerLength = (int)Math.Min((long)HeaderProbeSize, fileLength);
        var header = new byte[headerLength];
        await using (var input = File.OpenRead(path))
        {
            var read = 0;
            while (read < header.Length)
            {
                var n = await input.ReadAsync(header.AsMemory(read), cancellationToken);
                if (n == 0) break;
                read += n;
            }
            if (read != header.Length)
                Array.Resize(ref header, read);
        }

        if (!TryParseHeaders(header, fileLength, out var pe))
            return [];

        var results = new List<Detection>();
        var emitted = 0;
        var wanted = rules
            .Where(static r => IsSectionHash(r.SourceFile))
            .ToArray();
        if (wanted.Length == 0)
            return results;

        await using var stream = File.OpenRead(path);
        var buffer = new byte[128 * 1024];
        foreach (var section in pe.Sections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (section.RawSize <= 0 || section.RawOffset < 0 || section.RawOffset > fileLength - section.RawSize)
                continue;

            var applicable = wanted.Where(r => r.FileSize is null || r.FileSize.Value == section.RawSize).ToArray();
            if (applicable.Length == 0)
                continue;

            using var md5 = applicable.Any(static r => r.Algorithm == HashAlgorithmKind.Md5) ? IncrementalHash.CreateHash(HashAlgorithmName.MD5) : null;
            using var sha1 = applicable.Any(static r => r.Algorithm == HashAlgorithmKind.Sha1) ? IncrementalHash.CreateHash(HashAlgorithmName.SHA1) : null;
            using var sha256 = applicable.Any(static r => r.Algorithm == HashAlgorithmKind.Sha256) ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;

            stream.Position = section.RawOffset;
            var remaining = section.RawSize;
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var take = (int)Math.Min(buffer.Length, remaining);
                var read = 0;
                while (read < take)
                {
                    var n = await stream.ReadAsync(buffer.AsMemory(read, take - read), cancellationToken);
                    if (n == 0) return results;
                    read += n;
                }
                md5?.AppendData(buffer, 0, read);
                sha1?.AppendData(buffer, 0, read);
                sha256?.AppendData(buffer, 0, read);
                remaining -= read;
            }

            var digests = new Dictionary<HashAlgorithmKind, byte[]>();
            if (md5 is not null) digests[HashAlgorithmKind.Md5] = md5.GetHashAndReset();
            if (sha1 is not null) digests[HashAlgorithmKind.Sha1] = sha1.GetHashAndReset();
            if (sha256 is not null) digests[HashAlgorithmKind.Sha256] = sha256.GetHashAndReset();

            foreach (var rule in applicable)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!digests.TryGetValue(rule.Algorithm, out var digest) || !digest.AsSpan().SequenceEqual(rule.Hash))
                    continue;
                results.Add(new Detection(
                    rule.Name,
                    SignatureType.Hash,
                    section.RawOffset,
                    rule.SourceFile,
                    $"PE section '{section.Name}' ({section.RawSize} bytes) hash matched."));
                emitted++;
                if (emitted >= Math.Max(1, maxMatches))
                    return results;
            }
        }

        return results;
    }

    public static IReadOnlyList<Detection> Match(ReadOnlySpan<byte> data, CompiledState state, ScanLimits limits, CancellationToken cancellationToken)
    {
        if (!TryParse(data, out var pe)) return [];

        // ClamAV pe.c gates the section-hash and import-table matchers behind
        // PE_CONF_MD5SECT / PE_CONF_IMPTBL dconf flags.
        var peFlags = state.Database.DynamicConfiguration.Pe;
        var results = new List<Detection>();
        var sectionRules = state.Database.Signatures
            .OfType<HashSignature>()
            .Where(static s => IsSectionHash(s.SourceFile))
            .ToArray();
        if (sectionRules.Length != 0 && (peFlags & DynamicConfigFlags.PeMd5Sect) != 0)
            MatchSections(data, pe, sectionRules, limits.MaxPatternMatchesPerSignature, results, cancellationToken);

        var importRules = state.Database.Signatures
            .OfType<HashSignature>()
            .Where(static s => IsImportHash(s.SourceFile))
            .ToArray();
        if (importRules.Length != 0 && (peFlags & DynamicConfigFlags.PeImpTbl) != 0)
            MatchImports(data, pe, importRules, results, cancellationToken);

        return results;
    }

    private static void MatchSections(
        ReadOnlySpan<byte> data,
        PeImageView pe,
        IReadOnlyList<HashSignature> rules,
        int maxMatches,
        List<Detection> results,
        CancellationToken cancellationToken)
    {
        var emitted = 0;
        foreach (var section in pe.Sections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (section.RawSize <= 0 || section.RawSize > data.Length || section.RawOffset < 0 || section.RawOffset > data.Length - section.RawSize)
                continue;
            if (section.RawSize > int.MaxValue)
                continue;

            var span = data.Slice((int)section.RawOffset, (int)section.RawSize);
            foreach (var rule in rules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rule.FileSize is not null && rule.FileSize.Value != section.RawSize)
                    continue;
                if (!HashMatches(span, rule))
                    continue;

                results.Add(new Detection(
                    rule.Name,
                    SignatureType.Hash,
                    section.RawOffset,
                    rule.SourceFile,
                    $"PE section '{section.Name}' ({section.RawSize} bytes) hash matched."));
                emitted++;
                if (emitted >= Math.Max(1, maxMatches))
                    return;
            }
        }
    }

    private static void MatchImports(
        ReadOnlySpan<byte> data,
        PeImageView pe,
        IReadOnlyList<HashSignature> rules,
        List<Detection> results,
        CancellationToken cancellationToken)
    {
        if (pe.ImportRva == 0 || pe.ImportSize == 0) return;
        if (!TryReadImports(data, pe, out var imports, out var hashedLength)) return;
        if (imports.Count == 0) return;

        var hashInput = BuildImportHashInput(imports);
        var digest = MD5.HashData(Encoding.ASCII.GetBytes(hashInput));
        foreach (var rule in rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // .imp uses MD5 in ClamAV; reject other digest lengths instead of
            // accidentally interpreting them as another import-table algorithm.
            if (rule.Algorithm != HashAlgorithmKind.Md5 || rule.Hash.Length != 16)
                continue;
            if (rule.FileSize is not null && rule.FileSize.Value != hashedLength)
                continue;
            if (!digest.AsSpan().SequenceEqual(rule.Hash))
                continue;

            results.Add(new Detection(
                rule.Name,
                SignatureType.Hash,
                null,
                rule.SourceFile,
                $"PE import-table hash matched ({hashedLength} bytes)."));
        }
    }

    private static string BuildImportHashInput(IReadOnlyList<PeImport> imports)
    {
        var builder = new StringBuilder(imports.Count * 24);
        for (var i = 0; i < imports.Count; i++)
        {
            if (i != 0) builder.Append(',');
            builder.Append(imports[i].Library);
            builder.Append('.');
            builder.Append(imports[i].Function);
        }
        return builder.ToString();
    }

    private static bool HashMatches(ReadOnlySpan<byte> data, HashSignature signature)
    {
        byte[] digest = signature.Algorithm switch
        {
            HashAlgorithmKind.Md5 => MD5.HashData(data),
            HashAlgorithmKind.Sha1 => SHA1.HashData(data),
            HashAlgorithmKind.Sha256 => SHA256.HashData(data),
            _ => []
        };
        return digest.AsSpan().SequenceEqual(signature.Hash);
    }

    internal static bool IsSectionHash(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".mdb" or ".msb" or ".mdu" or ".msu";
    }

    internal static bool IsImportHash(string path)
        => Path.GetExtension(path).Equals(".imp", StringComparison.OrdinalIgnoreCase);

    private static bool TryParseHeaders(ReadOnlySpan<byte> data, long fileLength, out PeImageView pe)
    {
        pe = null!;
        if (fileLength <= 0 || data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c, 4));
        if (peOffset < 0 || (long)peOffset + 24 > data.Length) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(peOffset, 4)) != 0x00004550) return false;

        var coff = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 2, 2));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 16, 2));
        var optional = coff + 20;
        if (optionalSize < 96 || optional > data.Length - optionalSize) return false;

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optional, 2));
        var is64 = magic == 0x20b;
        if (!is64 && magic != 0x10b) return false;

        var dataDirectoryOffset = optional + (is64 ? 112 : 96);
        if (dataDirectoryOffset > optional + optionalSize ||
            dataDirectoryOffset + 8 * (int)(ImportDirectoryIndex + 1) > optional + optionalSize)
            return false;

        var importOffset = dataDirectoryOffset + 8 * (int)ImportDirectoryIndex;
        var importRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset, 4));
        var importSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset + 4, 4));

        var table = optional + optionalSize;
        var tableBytes = checked((long)sections * 40L);
        if (table < 0 || tableBytes < 0 || table + tableBytes > data.Length) return false;

        var parsedSections = new List<PeSectionView>(sections);
        for (var i = 0; i < sections; i++)
        {
            var o = table + i * 40;
            var nameBytes = data.Slice((int)o, 8);
            var zero = nameBytes.IndexOf((byte)0);
            if (zero < 0) zero = 8;
            var name = Encoding.ASCII.GetString(nameBytes[..zero]);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 8, 4));
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 12, 4));
            var declaredRawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 16, 4));
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 20, 4));
            var rawSize = rawOffset >= fileLength
                ? 0u
                : Math.Min(declaredRawSize, (uint)Math.Min((long)uint.MaxValue, fileLength - rawOffset));
            parsedSections.Add(new PeSectionView(name, rawOffset, rawSize, virtualAddress, virtualSize));
        }

        var overlayStart = Math.Clamp(table + tableBytes, 0, fileLength);
        foreach (var section in parsedSections)
        {
            var end = section.RawOffset + section.RawSize;
            if (section.RawSize > 0 && end > overlayStart && end <= fileLength)
                overlayStart = end;
        }

        pe = new PeImageView
        {
            IsPe32Plus = is64,
            NumberOfSections = sections,
            OptionalHeaderOffset = optional,
            OptionalHeaderSize = optionalSize,
            DataDirectoryOffset = dataDirectoryOffset,
            Sections = parsedSections,
            ImportRva = importRva,
            ImportSize = importSize,
            OverlayOffset = overlayStart,
            OverlaySize = fileLength - overlayStart
        };
        return true;
    }

    private static bool TryParse(ReadOnlySpan<byte> data, out PeImageView pe)
    {
        pe = null!;
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c, 4));
        if (peOffset < 0 || peOffset > data.Length - 24) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(peOffset, 4)) != 0x00004550) return false;

        var coff = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 2, 2));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(coff + 16, 2));
        var optional = coff + 20;
        if (optionalSize < 96 || optional > data.Length - optionalSize) return false;

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optional, 2));
        var is64 = magic == 0x20b;
        if (!is64 && magic != 0x10b) return false;

        var dataDirectoryOffset = optional + (is64 ? 112 : 96);
        if (dataDirectoryOffset > optional + optionalSize || dataDirectoryOffset + 8 * (int)(ImportDirectoryIndex + 1) > optional + optionalSize)
            return false;

        var importOffset = dataDirectoryOffset + 8 * (int)ImportDirectoryIndex;
        var importRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset, 4));
        var importSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(importOffset + 4, 4));

        var table = optional + optionalSize;
        var tableBytes = checked((long)sections * 40L);
        if (table < 0 || tableBytes < 0 || table + tableBytes > data.Length) return false;

        var parsedSections = new List<PeSectionView>(sections);
        for (var i = 0; i < sections; i++)
        {
            var o = table + i * 40;
            var nameBytes = data.Slice((int)o, 8);
            var zero = nameBytes.IndexOf((byte)0);
            if (zero < 0) zero = 8;
            var name = Encoding.ASCII.GetString(nameBytes[..zero]);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 8, 4));
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 12, 4));
            var declaredRawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 16, 4));
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)o + 20, 4));

            // ClamAV's PE parser treats bytes beyond EOF as unavailable section
            // content. Keep only the file-backed portion for hash/RVA operations.
            var rawSize = rawOffset >= data.Length
                ? 0u
                : Math.Min(declaredRawSize, (uint)(data.Length - rawOffset));

            parsedSections.Add(new PeSectionView(name, rawOffset, rawSize, virtualAddress, virtualSize));
        }

        long overlayStart = Math.Clamp(table + tableBytes, 0, data.Length);
        foreach (var section in parsedSections)
        {
            var end = section.RawOffset + section.RawSize;
            if (section.RawSize > 0 && end > overlayStart && end <= data.Length)
                overlayStart = end;
        }

        pe = new PeImageView
        {
            IsPe32Plus = is64,
            NumberOfSections = sections,
            OptionalHeaderOffset = optional,
            OptionalHeaderSize = optionalSize,
            DataDirectoryOffset = dataDirectoryOffset,
            Sections = parsedSections,
            ImportRva = importRva,
            ImportSize = importSize,
            OverlayOffset = overlayStart,
            OverlaySize = data.Length - overlayStart
        };
        return true;
    }

    public static bool TryGetOverlayRange(ReadOnlySpan<byte> headerData, long fileLength, out long offset, out long length)
    {
        offset = 0;
        length = 0;
        if (fileLength <= 0 || headerData.Length < 0x40 || headerData[0] != 'M' || headerData[1] != 'Z')
            return false;

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(headerData.Slice(0x3c, 4));
        if (peOffset < 0 || (long)peOffset + 24 > headerData.Length || BinaryPrimitives.ReadUInt32LittleEndian(headerData.Slice(peOffset, 4)) != 0x00004550)
            return false;

        var coff = peOffset + 4;
        var sections = BinaryPrimitives.ReadUInt16LittleEndian(headerData.Slice(coff + 2, 2));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(headerData.Slice(coff + 16, 2));
        var table = coff + 20 + optionalSize;
        if (sections == 0 || table < 0)
            return false;

        var tableBytes = checked((long)sections * 40L);
        if (tableBytes > int.MaxValue || table + tableBytes > headerData.Length)
            return false; // Caller deliberately bounds the prefix to 4 MiB.

        var overlayStart = Math.Clamp(table + tableBytes, 0, fileLength);
        for (var i = 0; i < sections; i++)
        {
            var section = checked(table + i * 40);
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(headerData.Slice(section + 16, 4));
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(headerData.Slice(section + 20, 4));
            if (rawSize == 0 || rawOffset >= fileLength)
                continue;
            var end = Math.Min(fileLength, (long)rawOffset + rawSize);
            if (end > overlayStart)
                overlayStart = end;
        }

        if (overlayStart >= fileLength)
            return false;

        offset = overlayStart;
        length = fileLength - overlayStart;
        return true;
    }

    public static bool TryGetOverlay(ReadOnlySpan<byte> data, out ReadOnlySpan<byte> overlay, out long offset)
    {
        overlay = default;
        offset = 0;
        if (!TryParse(data, out var pe) || pe.OverlaySize <= 0 || pe.OverlayOffset > int.MaxValue)
            return false;
        var start = (int)pe.OverlayOffset;
        var length = (int)pe.OverlaySize;
        if (start < 0 || length <= 0 || start > data.Length - length)
            return false;
        overlay = data.Slice(start, length);
        offset = start;
        return true;
    }

    private static bool TryReadImports(ReadOnlySpan<byte> data, PeImageView pe, out List<PeImport> imports, out int hashedLength)
    {
        imports = [];
        hashedLength = 0;
        if (!RvaToRaw(pe.ImportRva, pe.Sections, data.Length, out var importRaw)) return false;
        var descriptorLimit = Math.Min((long)pe.ImportSize, data.Length - importRaw);
        if (descriptorLimit < 20) return false;

        var descriptorCount = 0;
        while (descriptorCount++ < MaxImports)
        {
            var d = importRaw + descriptorCount * 20L - 20;
            if (d < importRaw || d + 20 > importRaw + descriptorLimit || d + 20 > data.Length) return false;
            var originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)d, 4));
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)d + 12, 4));
            var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)d + 16, 4));
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                return imports.Count != 0;
            if (nameRva == 0) return false;
            if (!RvaToRaw(nameRva, pe.Sections, data.Length, out var nameRaw)) return false;
            if (!TryReadAsciiZ(data, nameRaw, MaxImportNameLength, out var dllName)) return false;
            var normalizedDll = NormalizeLibraryName(dllName);

            var thunkRva = originalFirstThunk;
            if (thunkRva == 0 || !RvaToRaw(thunkRva, pe.Sections, data.Length, out var thunkRaw) || thunkRaw == 0)
            {
                thunkRva = firstThunk;
                if (thunkRva == 0 || !RvaToRaw(thunkRva, pe.Sections, data.Length, out thunkRaw) || thunkRaw == 0)
                    return false;
            }
            var thunkSize = pe.IsPe32Plus ? 8 : 4;
            var ordinalMask = pe.IsPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
            var functionCount = 0;
            while (functionCount++ < MaxImports)
            {
                var to = thunkRaw + (long)(functionCount - 1) * thunkSize;
                if (to < 0 || to > data.Length - thunkSize) return false;
                var thunkValue = pe.IsPe32Plus
                    ? BinaryPrimitives.ReadUInt64LittleEndian(data.Slice((int)to, 8))
                    : BinaryPrimitives.ReadUInt32LittleEndian(data.Slice((int)to, 4));
                if (thunkValue == 0) break;

                string function;
                if ((thunkValue & ordinalMask) != 0)
                {
                    var ordinal = (ushort)(thunkValue & 0xffff);
                    function = ResolveKnownOrdinal(normalizedDll, ordinal) ?? $"ord{ordinal}";
                }
                else
                {
                    var hintNameRva = checked((uint)thunkValue);
                    if (!RvaToRaw(hintNameRva, pe.Sections, data.Length, out var hintNameRaw) || hintNameRaw > data.Length - 2)
                        return false;
                    if (!TryReadAsciiZ(data, hintNameRaw + 2, MaxImportNameLength, out function)) return false;
                }

                if (!IsValidImportName(function)) return false;
                var normalizedFunction = function.ToLowerInvariant();
                imports.Add(new PeImport(normalizedDll, normalizedFunction));
                hashedLength += normalizedDll.Length + 1 + normalizedFunction.Length + (imports.Count > 1 ? 1 : 0);
                if (imports.Count >= MaxImports) return false;
            }
        }

        return false;
    }

    private static string NormalizeLibraryName(string library)
    {
        var value = library.Trim();
        // ClamAV looks at the FIRST dot and strips only when that suffix is
        // exactly .dll/.sys/.ocx. Do not turn foo.bar.dll into foo.bar.
        var dot = value.IndexOf('.');
        if (dot > 0)
        {
            var ext = value[dot..];
            if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase))
                value = value[..dot];
        }
        return value.ToLowerInvariant();
    }

    private static bool IsValidImportName(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxImportNameLength) return false;
        foreach (var c in value)
        {
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                c == '_' || c == '.')
                continue;
            return false;
        }
        return true;
    }

    private static string? ResolveKnownOrdinal(string library, ushort ordinal)
    {
        // ClamAV has special ordinal-name maps for WS2_32/wsock32. Keeping the
        // common Winsock exports here removes a frequent source of imphash drift;
        // unknown ordinals remain deterministic as ordNNN.
        if (library is "ws2_32" or "wsock32")
        {
            return ordinal switch
            {
                1 => "accept", 2 => "bind", 3 => "closesocket", 4 => "connect", 5 => "getpeername",
                6 => "getsockname", 7 => "getsockopt", 8 => "htonl", 9 => "htons", 10 => "ioctlsocket",
                11 => "inet_addr", 12 => "inet_ntoa", 13 => "listen", 14 => "ntohl", 15 => "ntohs",
                16 => "recv", 17 => "recvfrom", 18 => "select", 19 => "send", 20 => "sendto",
                21 => "setsockopt", 22 => "shutdown", 23 => "socket", 24 => "gethostbyaddr", 25 => "gethostbyname",
                _ => null
            };
        }
        return null;
    }

    private static bool TryReadAsciiZ(ReadOnlySpan<byte> data, long offset, int maxLength, out string value)
    {
        value = string.Empty;
        if (offset < 0 || offset >= data.Length) return false;
        var end = Math.Min(data.Length, checked((int)Math.Min(int.MaxValue, offset + maxLength)));
        var start = (int)offset;
        var slice = data[start..end];
        var zero = slice.IndexOf((byte)0);
        if (zero < 0) return false;
        value = Encoding.ASCII.GetString(slice[..zero]);
        return value.Length != 0;
    }

    private static bool RvaToRaw(uint rva, IReadOnlyList<PeSectionView> sections, int fileLength, out int raw)
    {
        raw = -1;
        foreach (var section in sections)
        {
            var start = (ulong)section.VirtualAddress;
            var rawSpan = (ulong)section.RawSize;
            if ((ulong)rva < start || (ulong)rva - start >= rawSpan) continue;
            var candidate = (long)section.RawOffset + ((long)rva - (long)start);
            if (candidate < 0 || candidate >= fileLength) return false;
            raw = (int)candidate;
            return true;
        }

        return rva < fileLength && rva <= int.MaxValue
            ? (raw = (int)rva) >= 0
            : false;
    }
}
