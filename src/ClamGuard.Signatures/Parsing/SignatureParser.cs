using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Parsing;

/// <summary>
/// [Facade] Điều phối chính theo extension (.hdb, .ldb, v.v.) sang các parser module hóa.
/// </summary>
public static class SignatureParser
{
    public static IEnumerable<Signature> ParseFile(string path, int engineFunctionalityLevel = 234)
    {
        // File.ReadLines opens the file eagerly. Deferred via a local function so
        // unknown extensions (which return no signatures and are never enumerated)
        // do not leak an open handle on arbitrary payloads stored in a database
        // directory.
        IEnumerable<string> Lines() => File.ReadLines(path);
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension switch
        {
            ".hdb" or ".hsb" or ".hdu" or ".hsu" or ".fp" or ".sfp" or ".mdb" or ".msb" or ".mdu" or ".msu" or ".imp"
                => HashSignatureParser.ParseHashLines(Lines(), path, engineFunctionalityLevel),
            ".ndb" or ".ndu" => NdbSignatureParser.ParseNdbLines(Lines(), path, engineFunctionalityLevel),
            ".sdb" => NdbSignatureParser.ParseNdbLines(Lines(), path, engineFunctionalityLevel, selfProtection: true),
            ".ldb" or ".ldu" => LdbSignatureParser.ParseLdbLines(Lines(), path, engineFunctionalityLevel),
            ".zmd" => ContainerSignatureParser.ParseMetadataLines(Lines(), path, "ZIP"),
            ".rmd" => ContainerSignatureParser.ParseMetadataLines(Lines(), path, "RAR"),
            ".cdb" => ContainerSignatureParser.ParseCdbLines(Lines(), path, engineFunctionalityLevel),
            ".db" => ParseDbLines(Lines(), path),
            ".idb" => Array.Empty<Signature>(),
            _ => Array.Empty<Signature>()
        };
    }

    public static IEnumerable<Signature> ParseLines(IEnumerable<string> lines, string virtualPath, int engineFunctionalityLevel = 234)
    {
        var extension = Path.GetExtension(virtualPath).ToLowerInvariant();
        return extension switch
        {
            ".hdb" or ".hsb" or ".hdu" or ".hsu" or ".fp" or ".sfp" or ".mdb" or ".msb" or ".mdu" or ".msu" or ".imp"
                => HashSignatureParser.ParseHashLines(lines, virtualPath, engineFunctionalityLevel),
            ".ndb" or ".ndu" => NdbSignatureParser.ParseNdbLines(lines, virtualPath, engineFunctionalityLevel),
            ".sdb" => NdbSignatureParser.ParseNdbLines(lines, virtualPath, engineFunctionalityLevel, selfProtection: true),
            ".ldb" or ".ldu" => LdbSignatureParser.ParseLdbLines(lines, virtualPath, engineFunctionalityLevel),
            ".zmd" => ContainerSignatureParser.ParseMetadataLines(lines, virtualPath, "ZIP"),
            ".rmd" => ContainerSignatureParser.ParseMetadataLines(lines, virtualPath, "RAR"),
            ".cdb" => ContainerSignatureParser.ParseCdbLines(lines, virtualPath, engineFunctionalityLevel),
            ".db" => ParseDbLines(lines, virtualPath),
            ".idb" => Array.Empty<Signature>(),
            _ => Array.Empty<Signature>()
        };
    }

    public static IEnumerable<HashSignature> ParseHashFile(string path, int engineFunctionalityLevel = 234)
        => HashSignatureParser.ParseHashFile(path, engineFunctionalityLevel);

    public static IEnumerable<NdbSignature> ParseNdbFile(string path, int engineFunctionalityLevel = 234, bool selfProtection = false)
        => NdbSignatureParser.ParseNdbFile(path, engineFunctionalityLevel, selfProtection);

    public static IEnumerable<CdbSignature> ParseCdbFile(string path, int engineFunctionalityLevel = 234)
        => ContainerSignatureParser.ParseCdbFile(path, engineFunctionalityLevel);

    public static IEnumerable<MetadataSignature> ParseMetadataFile(string path, string containerType)
        => ContainerSignatureParser.ParseMetadataFile(path, containerType);

    public static IEnumerable<LogicalSignature> ParseLdbFile(string path, int engineFunctionalityLevel = 234)
        => LdbSignatureParser.ParseLdbFile(path, engineFunctionalityLevel);

    public static IconDatabase ParseIdbFile(string path)
        => IdbSignatureParser.ParseIdbFile(path);

    public static IconDatabase ParseIdbLines(IEnumerable<string> lines, string virtualPath)
        => IdbSignatureParser.ParseIdbLines(lines, virtualPath);

    public static IEnumerable<ContentSignature> ParseDbFile(string path)
        => ParseDbLines(File.ReadLines(path), path);

    public static IEnumerable<ContentSignature> ParseDbLines(IEnumerable<string> lines, string virtualPath)
    {
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var equals = line.IndexOf('=');
            if (equals <= 0)
                throw new FormatException($"Invalid DB signature in {virtualPath}: {line}");

            var name = line[..equals];
            var pattern = line[(equals + 1)..];
            yield return new ContentSignature(
                name,
                SignatureType.Content,
                virtualPath,
                HexPatternParser.Parse(pattern))
            {
                SourceEntry = raw
            };
        }
    }
}
