using System.Security.Cryptography;
using System.Text;
using ClamGuard.Core;

namespace ClamGuard.Database;

public enum DatabaseVerificationStatus
{
    Verified,
    Failed,
    Unsupported
}

public sealed record DatabaseVerificationResult(
    DatabaseVerificationStatus Status,
    string Path,
    string? Signer,
    string Message,
    int VerifiedFiles,
    int TotalListedFiles);

/// <summary>Validates official ClamAV CVD containers using header, detached/legacy signatures and the signed .info manifest.</summary>
public static class DatabaseVerifier
{
    private const int CvdHeaderSize = 512;
    private const int MaxInfoBytes = 8 * 1024 * 1024;
    private const int MaxInfoLineBytes = 64 * 1024;

    public static DatabaseVerificationResult VerifyCvd(string path)
        => VerifyCvd(path, certsDirectory: null, detachedSignaturePath: null);

    public static DatabaseVerificationResult VerifyCvd(string path, string? certsDirectory)
        => VerifyCvd(path, certsDirectory, detachedSignaturePath: null);

    public static DatabaseVerificationResult VerifyCvd(string path, string? certsDirectory, string? detachedSignaturePath)
    {
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            if (!File.Exists(path)) throw new FileNotFoundException("Database file not found.", path);
            var header = CvdReader.ReadHeader(path);
            if (header.Format != DatabaseFormat.Cvd)
                return new(DatabaseVerificationStatus.Unsupported, path, null, "Only CVD containers are cryptographically verified by this path.", 0, 0);

            var detached = TryVerifyDetached(path, header, certsDirectory, detachedSignaturePath);
            if (detached?.Status == DetachedVerificationStatus.Invalid)
                throw new InvalidDataException(detached.Message);

            if (detached?.Status != DetachedVerificationStatus.Verified)
            {
                var payloadMd5 = ComputePayloadMd5(path);
                if (!payloadMd5.Equals(header.Md5, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("CVD payload MD5 does not match the header.");
                if (!ClamAvSignatureVerifier.VerifyLegacyCvdMd5(payloadMd5, header.DigitalSignature))
                    throw new InvalidDataException("CVD legacy RSA/MD5 signature verification failed.");
            }

            var root = Path.Combine(Path.GetTempPath(), $"clamguard-cvd-verify-{Guid.NewGuid():N}");
            try
            {
                CvdReader.Extract(path, root);
                var infoPaths = Directory.EnumerateFiles(root, "*.info", SearchOption.TopDirectoryOnly).ToArray();
                if (infoPaths.Length != 1)
                    throw new InvalidDataException(infoPaths.Length == 0
                        ? "Official CVD container is missing its .info manifest."
                        : "CVD contains multiple .info manifests.");

                var infoPath = infoPaths[0];
                var manifest = ParseInfo(infoPath);
                ValidateInfoHeader(header, manifest.Header);
                if (!ClamAvSignatureVerifier.VerifyInfoSha256Pss2(manifest.ContentSha256, manifest.DigitalSignature))
                    throw new InvalidDataException("CVD .info digital signature verification failed.");

                var verified = 0;
                var listedNames = new HashSet<string>(StringComparer.Ordinal);
                foreach (var item in manifest.Entries)
                {
                    if (!listedNames.Add(item.Name))
                        throw new InvalidDataException($"CVD .info contains duplicate entry '{item.Name}'.");
                    var filePath = Path.Combine(root, item.Name);
                    if (!File.Exists(filePath))
                        throw new InvalidDataException($"CVD manifest references missing file '{item.Name}'.");
                    var info = new FileInfo(filePath);
                    if (info.Length != item.Size)
                        throw new InvalidDataException($"CVD manifest size mismatch for '{item.Name}'.");
                    using var stream = File.OpenRead(filePath);
                    var sha = SHA256.HashData(stream);
                    if (!sha.AsSpan().SequenceEqual(item.Sha256))
                        throw new InvalidDataException($"CVD manifest checksum mismatch for '{item.Name}'.");
                    verified++;
                }

                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
                {
                    var name = Path.GetFileName(file);
                    if (name.Equals("COPYING", StringComparison.Ordinal) || name.Equals(Path.GetFileName(infoPath), StringComparison.Ordinal))
                        continue;
                    if (IsClamAvDatabaseExtension(name) && !listedNames.Contains(name))
                        throw new InvalidDataException($"CVD database file '{name}' is missing from .info.");
                }

                var signer = detached?.Status == DetachedVerificationStatus.Verified
                    ? detached.Signer
                    : "Legacy ClamAV RSA Public Key + .info SHA256 PSS2";
                return new(DatabaseVerificationStatus.Verified, path, signer,
                    $"Verified CVD payload and {verified} manifest entries.", verified, manifest.Entries.Count);
            }
            finally
            {
                TryDelete(root);
            }
        }
        catch (FileNotFoundException ex)
        {
            return new(DatabaseVerificationStatus.Failed, path, null, ex.Message, 0, 0);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or FormatException or UnauthorizedAccessException)
        {
            return new(DatabaseVerificationStatus.Failed, path, null, ex.Message, 0, 0);
        }
    }

    private static DetachedVerificationResult? TryVerifyDetached(string path, CvdHeader header, string? certsDirectory, string? detachedSignaturePath)
    {
        if (string.IsNullOrWhiteSpace(certsDirectory) || !Directory.Exists(certsDirectory))
            return null;
        var signaturePath = detachedSignaturePath;
        if (string.IsNullOrWhiteSpace(signaturePath))
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
            var stem = Path.GetFileNameWithoutExtension(path);
            var databaseName = stem.Split(['-', '.'], StringSplitOptions.RemoveEmptyEntries)[0];
            signaturePath = Path.Combine(directory, $"{databaseName}-{header.Version}.cvd.sign");
        }
        return File.Exists(signaturePath) ? DetachedCmsVerifier.Verify(path, signaturePath, certsDirectory) : null;
    }

    private static void ValidateInfoHeader(CvdHeader outer, CvdHeader inner)
    {
        if (inner.Version != outer.Version ||
            inner.SignatureCount != outer.SignatureCount ||
            inner.FunctionalityLevel != outer.FunctionalityLevel ||
            inner.CreationTimestamp != outer.CreationTimestamp)
            throw new InvalidDataException("CVD .info header does not match the outer CVD header.");
    }

    private static string ComputePayloadMd5(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length < CvdHeaderSize)
            throw new InvalidDataException("CVD is shorter than its 512-byte header.");
        stream.Position = CvdHeaderSize;
        return Convert.ToHexString(MD5.HashData(stream)).ToLowerInvariant();
    }

    private static InfoManifest ParseInfo(string path)
    {
        var fileLength = new FileInfo(path).Length;
        if (fileLength <= 0 || fileLength > MaxInfoBytes)
            throw new InvalidDataException(".info manifest size is outside the supported range.");
        var data = File.ReadAllBytes(path);
        var dsigMarker = Encoding.ASCII.GetBytes("\nDSIG:");
        var marker = data.AsSpan().LastIndexOf(dsigMarker);
        if (marker < 0)
            throw new InvalidDataException(".info manifest signature is missing.");

        var signatureStart = marker + 1 + 5;
        var endRel = data.AsSpan(signatureStart).IndexOf((byte)'\n');
        var end = endRel >= 0 ? signatureStart + endRel : data.Length;
        var signature = Encoding.ASCII.GetString(data, signatureStart, end - signatureStart).Trim();
        if (signature.Length == 0)
            throw new InvalidDataException(".info DSIG is empty.");

        var signedContent = data.AsSpan(0, marker + 1).ToArray();
        var contentHash = SHA256.HashData(signedContent);
        var contentText = new UTF8Encoding(false, true).GetString(signedContent);
        var lines = contentText.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 2 || !lines[0].StartsWith("ClamAV-VDB:", StringComparison.Ordinal))
            throw new InvalidDataException("Malformed .info manifest.");

        var entries = new List<InfoEntry>();
        var utf8 = new UTF8Encoding(false, true);
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (utf8.GetByteCount(line) > MaxInfoLineBytes)
                throw new InvalidDataException(".info line is too large.");
            var parts = line.Split(':', 3);
            if (parts.Length != 3 || !uint.TryParse(parts[1], out var size) || parts[2].Length != 64)
                throw new InvalidDataException($"Malformed .info entry on line {i + 1}.");
            if (parts[0].Length == 0 || parts[0].Any(ch => !(char.IsLetterOrDigit(ch) || ch is '.' or '_')))
                throw new InvalidDataException($"Unsafe .info database name '{parts[0]}'.");
            byte[] sha;
            try { sha = Convert.FromHexString(parts[2]); }
            catch (FormatException) { throw new InvalidDataException($"Malformed .info checksum on line {i + 1}."); }
            entries.Add(new InfoEntry(parts[0], size, sha));
        }

        var header = CvdReader.ParseHeader(lines[0].TrimEnd('\r'), ".cvd");
        return new InfoManifest(contentHash, signature, header, entries);
    }

    private static bool IsClamAvDatabaseExtension(string name)
    {
        return new[] { ".db", ".hdb", ".hdu", ".fp", ".mdb", ".mdu", ".hsb", ".hsu", ".sfp", ".msb", ".msu", ".ndb", ".ndu", ".ldb", ".ldu", ".sdb", ".zmd", ".rmd", ".pdb", ".gdb", ".wdb", ".cbc", ".ftm", ".cfg", ".cvd", ".cld", ".cud", ".cdb", ".cat", ".crb", ".idb", ".ioc", ".yar", ".yara", ".pwdb", ".ign", ".ign2", ".imp" }
            .Contains(Path.GetExtension(name), StringComparer.OrdinalIgnoreCase);
    }

    private static void TryDelete(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
    }

    private sealed record InfoManifest(byte[] ContentSha256, string DigitalSignature, CvdHeader Header, IReadOnlyList<InfoEntry> Entries);
    private sealed record InfoEntry(string Name, uint Size, byte[] Sha256);
}
