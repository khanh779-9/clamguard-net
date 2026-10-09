using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal static partial class PeSpecializedMatcher
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

}
