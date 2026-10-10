using ClamGuard.Signatures;

namespace ClamGuard.Signatures.Parsing;

internal static class ContainerSignatureParser
{
    internal static IEnumerable<CdbSignature> ParseCdbFile(string path, int engineFunctionalityLevel)
        => ParseCdbLines(File.ReadLines(path), path, engineFunctionalityLevel);

    internal static IEnumerable<CdbSignature> ParseCdbLines(IEnumerable<string> lines, string path, int engineFunctionalityLevel)
    {
        const int maxTokens = 12;

        foreach (var raw in lines)
        {
            // cli_loadcdb(): only a '#' in column 0 is a comment. Do not trim
            // or silently discard blank/whitespace-only records.
            var line = raw;
            if (line.StartsWith('#'))
                continue;

            var parts = line.Split(':');
            if (parts.Length < 10 || parts.Length > maxTokens)
                throw new FormatException($"Invalid CDB signature in {path}: {line}");

            if (parts.Length > 10)
            {
                var minFLevel = ParseClamAvAtoiNumber(parts[10], "minimum functionality level", path, line);
                if (minFLevel > engineFunctionalityLevel)
                    continue;

                if (parts.Length == 12)
                {
                    var maxFLevel = ParseClamAvAtoiNumber(parts[11], "maximum functionality level", path, line);
                    if (maxFLevel < engineFunctionalityLevel)
                        continue;
                }
            }

            var containerType = parts[1] == "*" ? "*" : parts[1];
            if (containerType != "*" && !IsKnownClamAvFileType(containerType))
                throw new FormatException($"Unknown CDB container type '{containerType}' in {path}: {line}");

            PosixEreRegex? nameRegex = null;
            if (parts[3] != "*")
            {
                try
                {
                    nameRegex = new PosixEreRegex(parts[3]);
                }
                catch (ArgumentException ex)
                {
                    throw new FormatException($"Invalid CDB filename regex in {path}: {line}", ex);
                }
            }

            var containerSize = ParseCdbRange(parts[2], "container size", path, line);
            var fileSizeInContainer = ParseCdbRange(parts[4], "file size in container", path, line);
            var fileSizeReal = ParseCdbRange(parts[5], "real file size", path, line);
            var filePosition = ParseCdbRange(parts[7], "file position", path, line);

            var encrypted = parts[6] switch
            {
                "*" => 2,
                "0" => 0,
                "1" => 1,
                _ => throw new FormatException($"Invalid CDB encryption flag in {path}: {line}")
            };

            // cli_loadcdb() does not parse/use Res1, and stores Res2 as an
            // opaque string. cli_matchmeta() currently does not compare either.
            var res2 = parts[9] == "*" ? null : parts[9];

            yield return new CdbSignature(
                parts[0],
                path,
                containerType,
                nameRegex,
                containerSize,
                fileSizeInContainer,
                fileSizeReal,
                encrypted,
                filePosition,
                res2)
            {
                SourceEntry = raw
            };
        }
    }

    private static MetadataRange? ParseCdbRange(string value, string field, string path, string line)
    {
        if (value == "*")
            return null;

        var dash = value.IndexOf('-');
        if (dash >= 0)
        {
            if (dash == 0 || dash == value.Length - 1 ||
                !uint.TryParse(value[..dash], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var min) ||
                !uint.TryParse(value[(dash + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var max) ||
                min > max)
            {
                throw new FormatException($"Invalid {field} in {path}: {line}");
            }

            return new MetadataRange(min, max);
        }

        if (value.Length == 0)
            return new MetadataRange(0, 0);

        if (!uint.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var exact))
            throw new FormatException($"Invalid {field} in {path}: {line}");

        return new MetadataRange(exact, exact);
    }

    private static int ParseClamAvAtoiNumber(string value, string field, string path, string line)
    {
        // cli_isnumber() accepts an empty token; atoi("") is 0.
        if (value.Length == 0)
            return 0;

        if (value.Any(c => c is < '0' or > '9') ||
            !int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result))
            throw new FormatException($"Invalid {field} in {path}: {line}");

        return result;
    }

    private static bool IsKnownClamAvFileType(string value)
        => value is "CL_TYPE_TEXT_ASCII" or "CL_TYPE_TEXT_UTF8" or "CL_TYPE_TEXT_UTF16LE" or "CL_TYPE_TEXT_UTF16BE" or "CL_TYPE_BINARY_DATA" or "CL_TYPE_IGNORED" or "CL_TYPE_ANY" or "CL_TYPE_MSEXE" or "CL_TYPE_ELF" or "CL_TYPE_MACHO" or "CL_TYPE_MACHO_UNIBIN" or "CL_TYPE_POSIX_TAR" or "CL_TYPE_OLD_TAR" or "CL_TYPE_CPIO_OLD" or "CL_TYPE_CPIO_ODC" or "CL_TYPE_CPIO_NEWC" or "CL_TYPE_CPIO_CRC" or "CL_TYPE_GZ" or "CL_TYPE_ZIP" or "CL_TYPE_BZ" or "CL_TYPE_RAR" or "CL_TYPE_ARJ" or "CL_TYPE_MSSZDD" or "CL_TYPE_MSOLE2" or "CL_TYPE_MSCAB" or "CL_TYPE_MSCHM" or "CL_TYPE_SIS" or "CL_TYPE_SCRENC" or "CL_TYPE_GRAPHICS" or "CL_TYPE_GIF" or "CL_TYPE_PNG" or "CL_TYPE_JPEG" or "CL_TYPE_TIFF" or "CL_TYPE_RIFF" or "CL_TYPE_BINHEX" or "CL_TYPE_TNEF" or "CL_TYPE_CRYPTFF" or "CL_TYPE_PDF" or "CL_TYPE_UUENCODED" or "CL_TYPE_HTML_UTF16" or "CL_TYPE_SCRIPT" or "CL_TYPE_RTF" or "CL_TYPE_HTML" or "CL_TYPE_MAIL" or "CL_TYPE_SFX" or "CL_TYPE_ZIPSFX" or "CL_TYPE_RARSFX" or "CL_TYPE_CABSFX" or "CL_TYPE_ARJSFX" or "CL_TYPE_NULSFT" or "CL_TYPE_AUTOIT" or "CL_TYPE_ISHIELD_MSI" or "CL_TYPE_7Z" or "CL_TYPE_7ZSFX" or "CL_TYPE_SWF" or "CL_TYPE_ISO9660" or "CL_TYPE_JAVA" or "CL_TYPE_DMG" or "CL_TYPE_MBR" or "CL_TYPE_GPT" or "CL_TYPE_APM" or "CL_TYPE_XAR" or "CL_TYPE_PART_ANY" or "CL_TYPE_PART_HFSPLUS" or "CL_TYPE_XZ" or "CL_TYPE_OOXML_WORD" or "CL_TYPE_OOXML_PPT" or "CL_TYPE_OOXML_XL" or "CL_TYPE_INTERNAL" or "CL_TYPE_XDP" or "CL_TYPE_XML_WORD" or "CL_TYPE_XML_XL" or "CL_TYPE_HWP3" or "CL_TYPE_XML_HWP" or "CL_TYPE_HWPOLE2" or "CL_TYPE_OOXML_HWP" or "CL_TYPE_PS" or "CL_TYPE_MHTML" or "CL_TYPE_LNK" or "CL_TYPE_EGG" or "CL_TYPE_EGGSFX" or "CL_TYPE_UDF" or "CL_TYPE_ALZ" or "CL_TYPE_ONENOTE" or "CL_TYPE_PYTHON_COMPILED" or "CL_TYPE_LHA_LZH" or "CL_TYPE_AI_MODEL";

    internal static IEnumerable<MetadataSignature> ParseMetadataFile(string path, string containerType)
        => ParseMetadataLines(File.ReadLines(path), path, containerType);

    internal static IEnumerable<MetadataSignature> ParseMetadataLines(IEnumerable<string> lines, string path, string containerType)
    {
        foreach (var raw in lines)
        {
            // ClamAV calls cli_chomp() (line-ending removal only) and treats only
            // a '#' in column 0 as a comment. Do not Trim() the signature line.
            var line = raw;
            if (line.StartsWith('#'))
                continue;

            // ClamAV cli_loadmd expects exactly:
            // VirusName:Encrypted:FileNameREGEX:OriginalSize:CompressedSize:Res1:CompressionMethod:FilePos:MaxDepth
            // The filename regex may itself contain ':' (e.g. POSIX classes such
            // as [[:digit:]]), so the surplus tokens are re-joined into the regex
            // field: the six trailing fields are always the numeric block.
            var parts = line.Split(':');
            if (parts.Length < 9)
                throw new FormatException($"Invalid {containerType} metadata signature in {path}: {line}");
            string[] fields;
            if (parts.Length == 9)
            {
                fields = parts;
            }
            else
            {
                fields = new string[9];
                fields[0] = parts[0];
                fields[1] = parts[1];
                fields[2] = string.Join(":", parts.Skip(2).Take(parts.Length - 8));
                Array.Copy(parts, parts.Length - 6, fields, 3, 6);
            }

            // cli_loadmd accepts any numeric value. cli_matchmeta treats only 2 as
            // the wildcard value; other numeric values are retained and therefore
            // only match the same numeric metadata value.
            var encryptedValue = ParseMetadataWildcardInt(fields[1], "encrypted", path, line);

            PosixEreRegex? fileNameRegex = null;
            if (fields[2] != "*")
            {
                try
                {
                    fileNameRegex = new PosixEreRegex(fields[2]);
                }
                catch (ArgumentException ex)
                {
                    throw new FormatException($"Invalid filename regex in {path}: {line}", ex);
                }
            }

            var originalSize = ParseMetadataRange(fields[3], "original size", path, line);
            var compressedSize = ParseMetadataRange(fields[4], "compressed size", path, line);
            var res1 = ParseMetadataHexWildcard(fields[5], path, line);
            var compressionMethod = ParseMetadataWildcardInt(fields[6], "compression method", path, line);
            var filePosition = ParseMetadataRange(fields[7], "file number", path, line);
            var maxDepth = ParseMetadataWildcardInt(fields[8], "max depth", path, line);

            yield return new MetadataSignature(
                fields[0],
                path,
                containerType,
                encryptedValue ?? 2,
                fileNameRegex,
                originalSize,
                compressedSize,
                res1,
                filePosition,
                compressionMethod,
                maxDepth)
            {
                SourceEntry = raw
            };
        }
    }

    private static int? ParseMetadataWildcardInt(string value, string field, string path, string line)
    {
        if (value == "*") return null;

        // ClamAV cli_isnumber() accepts the empty string because its digit loop
        // is skipped. cli_loadmd() then passes the token to atoi(), yielding 0.
        // Keep that edge case while still rejecting signs/whitespace/non-digits.
        if (value.Length == 0) return 0;
        if (value.Any(c => c is < '0' or > '9') ||
            !int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result))
            throw new FormatException($"Invalid {field} in {path}: {line}");

        return result;
    }

    private static MetadataRange? ParseMetadataRange(string value, string field, string path, string line)
    {
        if (value == "*") return null;

        // cli_loadmd() validates with cli_isnumber(), then stores atoi() into
        // an int-backed metadata bound. cli_isnumber() also accepts an empty
        // token, and atoi("") yields 0.
        if (value.Length == 0) return new MetadataRange(0, 0);
        if (value.Any(c => c is < '0' or > '9') ||
            !int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var exact))
            throw new FormatException($"Invalid {field} in {path}: {line}");

        return new MetadataRange(exact, exact);
    }

    private static int? ParseMetadataHexWildcard(string value, string path, string line)
    {
        if (value == "*") return null;

        // Match ClamAV cli_hex2num() exactly:
        // - odd-length input returns -1 before examining characters;
        // - even-length input accumulates hex nibbles until the first invalid
        //   character, then returns the value accumulated so far;
        // - an empty string therefore returns 0;
        // - there is no explicit 8-digit limit.
        if ((value.Length & 1) != 0)
            throw new FormatException($"Invalid res1 field in {path}: {line}");

        var result = 0;
        foreach (var c in value)
        {
            var nibble = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'A' and <= 'F' => c - 'A' + 10,
                >= 'a' and <= 'f' => c - 'a' + 10,
                _ => -1
            };

            if (nibble < 0)
                break;

            result = unchecked((result << 4) | nibble);
        }

        // cli_loadmd rejects cli_hex2num() == -1.
        if (result == -1)
            throw new FormatException($"Invalid res1 field in {path}: {line}");

        return result;
    }
}
