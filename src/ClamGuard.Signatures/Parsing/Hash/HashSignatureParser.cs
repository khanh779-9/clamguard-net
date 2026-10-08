using ClamGuard.Core;
using ClamGuard.Signatures;

namespace ClamGuard.Signatures.Parsing;

internal static class HashSignatureParser
{
    internal static IEnumerable<HashSignature> ParseHashFile(string path, int engineFunctionalityLevel)
        => ParseHashLines(File.ReadLines(path), path, engineFunctionalityLevel);

    internal static IEnumerable<HashSignature> ParseHashLines(IEnumerable<string> lines, string path, int engineFunctionalityLevel)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        var type = extension is ".fp" or ".sfp"
            ? SignatureType.Trust
            : SignatureType.Hash;
        var isSectionHash = extension is ".mdb" or ".msb" or ".mdu" or ".msu";
        var isImportHash = extension == ".imp";

        foreach (var raw in lines)
        {
            // ClamAV calls cli_chomp() (line-ending removal only) and treats only
            // a '#' in column 0 as a comment. Do not Trim() the signature line.
            var line = raw;
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var parts = line.Split(':');
            if (parts.Length < 3 || parts.Length > 5)
                throw new FormatException($"Invalid hash signature in {path}: {line}");

            var sizeField = isSectionHash ? parts[0] : parts[1];
            var hashField = isSectionHash ? parts[1] : parts[0];
            var name = parts[2];

            uint? minimumFLevel = null;
            uint? maximumFLevel = null;
            if (parts.Length >= 4)
            {
                minimumFLevel = SignatureParserCommon.ParseUInt(parts[3], "minimum functionality level");
                if (minimumFLevel.Value > engineFunctionalityLevel)
                    continue;

                if (parts.Length == 5)
                {
                    maximumFLevel = SignatureParserCommon.ParseUInt(parts[4], "maximum functionality level");
                    if (maximumFLevel.Value < engineFunctionalityLevel)
                        continue;
                }
            }

            var fileSize = SignatureParserCommon.ParseSize(sizeField);
            if (fileSize is null && !isImportHash && minimumFLevel is null)
            {
                throw new FormatException(
                    $"Wildcard-size hash signature requires a minimum functionality level in {path}: {line}");
            }

            if (!SignatureParserCommon.TryGetAlgorithm(hashField, out var algorithm, out var hash))
                throw new FormatException($"Unsupported hash value in {path}: {hashField}");

            yield return new HashSignature(name, type, path, algorithm, hash, fileSize)
            {
                SourceEntry = raw
            };
        }
    }
}
