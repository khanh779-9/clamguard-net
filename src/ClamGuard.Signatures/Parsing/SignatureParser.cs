using System.Text.RegularExpressions;
using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Parsing;

public static class SignatureParser
{
    public static IEnumerable<Signature> ParseFile(string path, int engineFunctionalityLevel = 234)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension switch
        {
            ".hdb" or ".hsb" or ".hdu" or ".hsu" or ".fp" or ".sfp" or ".mdb" or ".msb" or ".mdu" or ".msu" or ".imp"
                => ParseHashFile(path, engineFunctionalityLevel),
            ".ndb" or ".ndu" => ParseNdbFile(path, engineFunctionalityLevel),
            ".sdb" => ParseNdbFile(path, engineFunctionalityLevel, selfProtection: true),
            ".ldb" or ".ldu" => ParseLdbFile(path, engineFunctionalityLevel),
            ".zmd" => ParseMetadataFile(path, "ZIP"),
            ".rmd" => ParseMetadataFile(path, "RAR"),
            ".cdb" => ParseCdbFile(path, engineFunctionalityLevel),
            ".db" => ParseDbFile(path),
            ".idb" => Array.Empty<Signature>(),
            _ => Array.Empty<Signature>()
        };
    }

    public static IEnumerable<HashSignature> ParseHashFile(string path, int engineFunctionalityLevel = 234)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        var type = extension is ".fp" or ".sfp"
            ? SignatureType.Trust
            : SignatureType.Hash;
        var isSectionHash = extension is ".mdb" or ".msb" or ".mdu" or ".msu";
        var isImportHash = extension == ".imp";

        foreach (var raw in File.ReadLines(path))
        {
            // ClamAV calls cli_chomp() (line-ending removal only) and treats only
            // a '#' in column 0 as a comment. Do not Trim() the signature line.
            var line = raw;
            if (line.StartsWith('#'))
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
                minimumFLevel = ParseUInt(parts[3], "minimum functionality level");
                if (minimumFLevel.Value > engineFunctionalityLevel)
                    continue;

                if (parts.Length == 5)
                {
                    maximumFLevel = ParseUInt(parts[4], "maximum functionality level");
                    if (maximumFLevel.Value < engineFunctionalityLevel)
                        continue;
                }
            }

            var fileSize = ParseSize(sizeField);
            if (fileSize is null && !isImportHash && minimumFLevel is null)
            {
                throw new FormatException(
                    $"Wildcard-size hash signature requires a minimum functionality level in {path}: {line}");
            }

            if (!TryGetAlgorithm(hashField, out var algorithm, out var hash))
                throw new FormatException($"Unsupported hash value in {path}: {hashField}");

            yield return new HashSignature(name, type, path, algorithm, hash, fileSize)
            {
                SourceEntry = raw
            };
        }
    }

    public static IEnumerable<NdbSignature> ParseNdbFile(string path, int engineFunctionalityLevel = 234, bool selfProtection = false)
    {
        foreach (var raw in File.ReadLines(path))
        {
            // Match ClamAV cli_loadndb(): only a '#' in column 0 is a comment.
            // cli_chomp() removes line endings only; File.ReadLines already does that.
            // Blank/whitespace-only lines are not silently ignored.
            var line = raw;
            if (line.StartsWith('#'))
                continue;

            var parts = line.Split(':');
            if (parts.Length is < 4 or > 6)
                throw new FormatException($"Invalid NDB signature in {path}: {line}");

            var minimum = parts.Length >= 5 && parts[4].Length != 0 ? ParseInt(parts[4]) : (int?)null;
            var maximum = parts.Length >= 6 && parts[5].Length != 0 ? ParseInt(parts[5]) : (int?)null;
            if (minimum is not null && minimum < 0)
                throw new FormatException($"Invalid minimum functionality level in {path}: {line}");
            if (maximum is not null && maximum < 0)
                throw new FormatException($"Invalid maximum functionality level in {path}: {line}");
            if (minimum is not null && maximum is not null && maximum < minimum)
                throw new FormatException($"Invalid NDB functionality range in {path}: {line}");
            if (minimum is not null && minimum > engineFunctionalityLevel)
                continue;
            if (maximum is not null && maximum < engineFunctionalityLevel)
                continue;

            // ClamAV does: target = atoi(tokens[1]);  "*" therefore becomes 0
            // after passing the explicit (strcmp("*", ...) || cli_isnumber(...)) gate.
            var target = parts[1] == "*" ? 0 : ParseInt(parts[1]);
            if (target is < 0 or > 14)
                throw new FormatException($"Unsupported NDB target {target} in {path}: {line}");

            var offsetExpression = parts[2].Trim();
            if (offsetExpression.Length == 0)
                offsetExpression = "*";
            ValidateNdbOffsetExpression(offsetExpression, path, line);

            int? macroGroup = null;
            if (offsetExpression.StartsWith("$", StringComparison.Ordinal))
            {
                if (!offsetExpression.EndsWith("$", StringComparison.Ordinal) ||
                    !int.TryParse(offsetExpression[1..^1], out var parsedMacroGroup) ||
                    parsedMacroGroup is < 0 or >= 32)
                {
                    throw new FormatException($"Invalid NDB macro group offset '{parts[2]}' in {path}: {line}");
                }
                macroGroup = parsedMacroGroup;
            }

            yield return new NdbSignature(
                parts[0],
                path,
                target,
                offsetExpression,
                HexPatternParser.Parse(parts[3]),
                minimum,
                maximum,
                macroGroup,
                selfProtection)
            {
                SourceEntry = raw
            };
        }
    }


    private static void ValidateNdbOffsetExpression(string expression, string path, string line)
    {
        if (expression == "*") return;

        var comma = expression.IndexOf(',');
        if (comma >= 0)
        {
            if (expression.IndexOf(',', comma + 1) >= 0 ||
                !int.TryParse(expression[(comma + 1)..].Trim(), out var maxShift) || maxShift < 0)
                throw new FormatException($"Invalid NDB floating offset '{expression}' in {path}: {line}");
            expression = expression[..comma].Trim();
        }

        if (int.TryParse(expression, out var absolute) && absolute >= 0) return;
        // ClamAV 1.5.4 accepts EOF-relative offsets only as EOF-<n>. A bare EOF
        // is not a valid cli_caloff() expression and must be rejected.
        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(expression[4..], out var eofShift) && eofShift >= 0) return;
        if (expression.StartsWith("$", StringComparison.Ordinal) && expression.EndsWith("$", StringComparison.Ordinal) &&
            int.TryParse(expression[1..^1], out var group) && group is >= 0 and < 32) return;
        if (expression.StartsWith("EP+", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var epPlus) && epPlus >= 0) return;
        if (expression.StartsWith("EP-", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var epMinus) && epMinus >= 0) return;
        if (expression.StartsWith("SL+", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var slPlus) && slPlus >= 0) return;
        if (expression.StartsWith("SE", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[2..], out var seIndex) && seIndex >= 0) return;
        if (expression.StartsWith("S", StringComparison.OrdinalIgnoreCase))
        {
            var plus = expression.IndexOf('+');
            if (plus > 1 && int.TryParse(expression[1..plus], out var sIndex) && sIndex >= 0 &&
                int.TryParse(expression[(plus + 1)..], out var sOffset) && sOffset >= 0) return;
        }

        throw new FormatException($"Unsupported NDB offset '{expression}' in {path}: {line}");
    }

    public static IEnumerable<CdbSignature> ParseCdbFile(string path, int engineFunctionalityLevel = 234)
    {
        const int maxTokens = 12;

        foreach (var raw in File.ReadLines(path))
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

    public static IEnumerable<MetadataSignature> ParseMetadataFile(string path, string containerType)
    {
        foreach (var raw in File.ReadLines(path))
        {
            // ClamAV calls cli_chomp() (line-ending removal only) and treats only
            // a '#' in column 0 as a comment. Do not Trim() the signature line.
            var line = raw;
            if (line.StartsWith('#'))
                continue;

            // ClamAV cli_loadmd expects exactly:
            // VirusName:Encrypted:FileNameREGEX:OriginalSize:CompressedSize:Res1:CompressionMethod:FilePos:MaxDepth
            var parts = line.Split(':');
            if (parts.Length != 9)
                throw new FormatException($"Invalid {containerType} metadata signature in {path}: {line}");

            // cli_loadmd accepts any numeric value. cli_matchmeta treats only 2 as
            // the wildcard value; other numeric values are retained and therefore
            // only match the same numeric metadata value.
            var encryptedValue = ParseMetadataWildcardInt(parts[1], "encrypted", path, line);

            PosixEreRegex? fileNameRegex = null;
            if (parts[2] != "*")
            {
                try
                {
                    fileNameRegex = new PosixEreRegex(parts[2]);
                }
                catch (ArgumentException ex)
                {
                    throw new FormatException($"Invalid filename regex in {path}: {line}", ex);
                }
            }

            var originalSize = ParseMetadataRange(parts[3], "original size", path, line);
            var compressedSize = ParseMetadataRange(parts[4], "compressed size", path, line);
            var res1 = ParseMetadataHexWildcard(parts[5], path, line);
            var compressionMethod = ParseMetadataWildcardInt(parts[6], "compression method", path, line);
            var filePosition = ParseMetadataRange(parts[7], "file number", path, line);
            var maxDepth = ParseMetadataWildcardInt(parts[8], "max depth", path, line);

            yield return new MetadataSignature(
                parts[0],
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

    public static IEnumerable<LogicalSignature> ParseLdbFile(string path, int engineFunctionalityLevel = 234)
    {
        foreach (var raw in File.ReadLines(path))
        {
            // Match ClamAV cli_loadldb(): only a '#' in column 0 is a comment.
            // cli_chomp() removes line endings only; File.ReadLines already does that.
            // Blank/whitespace-only lines are passed to load_oneldb() and are malformed.
            var line = raw;
            if (line.StartsWith('#'))
                continue;

            var parts = SplitLdbFields(line);
            if (parts.Length < 4)
                throw new FormatException($"Invalid LDB signature in {path}: {line}");

            var targetText = parts[1];
            var target = ParseLdbTarget(targetText);
            // ClamAV skips an LDB signature when the target attributes contain an
            // unsupported attribute/file type. Malformed syntax is still a hard error.
            if (target is null)
                continue;
            if ((target.MinimumFunctionalityLevel is not null && target.MinimumFunctionalityLevel > engineFunctionalityLevel) ||
                (target.MaximumFunctionalityLevel is not null && target.MaximumFunctionalityLevel < engineFunctionalityLevel))
                continue;

            var contentSubs = new List<ContentSignature>(parts.Length - 3);
            var macros = new Dictionary<int, (int MinDistance, int MaxDistance, int MacroGroup)>();
            var regexSubs = new Dictionary<int, LdbRegexSubSignature>();
            var byteCompareSubs = new Dictionary<int, LdbByteCompareSubSignature>();
            var fuzzySubs = new Dictionary<int, LdbFuzzyImageSubSignature>();

            for (var i = 3; i < parts.Length; i++)
            {
                var subsigIndex = i - 3;
                var token = parts[i];
                if (token.Length == 0)
                    throw new FormatException($"Empty LDB sub-signature in {path}: {line}");

                if (token.StartsWith("${", StringComparison.Ordinal) && token.EndsWith("$", StringComparison.Ordinal))
                {
                    var inner = token[2..^1];
                    var close = inner.IndexOf('}');
                    if (close <= 0 || close + 1 >= inner.Length)
                        throw new FormatException($"Invalid LDB macro subsignature in {path}: {token}");
                    var range = inner[..close];
                    var groupText = inner[(close + 1)..];
                    var dash = range.IndexOf('-');
                    if (dash <= 0 || !int.TryParse(range[..dash], out var minDistance) || !int.TryParse(range[(dash + 1)..], out var maxDistance) ||
                        minDistance < 0 || maxDistance < minDistance || !int.TryParse(groupText, out var groupId) || groupId is < 0 or >= 32)
                        throw new FormatException($"Invalid LDB macro subsignature in {path}: {token}");
                    if (subsigIndex == 0)
                        throw new FormatException($"LDB macro subsignature cannot be the first subsignature: {token}");
                    macros[subsigIndex] = (minDistance, maxDistance, groupId);
                    continue;
                }

                if (token.StartsWith("fuzzy_img#", StringComparison.OrdinalIgnoreCase))
                {
                    fuzzySubs[subsigIndex] = ParseFuzzyImageSubSignature(subsigIndex, token, path, line);
                    continue;
                }

                if (LooksLikeRegexSubSignature(token))
                {
                    regexSubs[subsigIndex] = ParseRegexSubSignature(subsigIndex, token, path, line);
                    continue;
                }

                if (LooksLikeByteCompareSubSignature(token))
                {
                    byteCompareSubs[subsigIndex] = ParseByteCompareSubSignature(subsigIndex, token, path, line);
                    continue;
                }

                var fields = token.Split(':');
                string offset;
                string patternText;
                string? modifierText = null;
                switch (fields.Length)
                {
                    case 1:
                        offset = "*";
                        patternText = fields[0];
                        break;
                    case 2:
                        offset = fields[0].Length == 0 ? "*" : fields[0];
                        patternText = fields[1];
                        break;
                    case 3 when fields[1].Length == 0 && fields[2].Length > 0:
                        offset = "*";
                        patternText = fields[0];
                        modifierText = fields[2];
                        break;
                    case 4:
                        offset = fields[0].Length == 0 ? "*" : fields[0];
                        patternText = fields[1];
                        modifierText = fields[3];
                        break;
                    default:
                        throw new FormatException($"Invalid LDB content subsignature format in {path}: {token}");
                }

                if (string.IsNullOrWhiteSpace(patternText))
                    throw new FormatException($"Empty LDB sub-signature pattern in {path}: {line}");
                ValidateLdbOffsetExpression(offset, path, line);

                contentSubs.Add(new ContentSignature(
                    $"{parts[0]}#{subsigIndex}",
                    SignatureType.Content,
                    path,
                    HexPatternParser.Parse(patternText),
                    offset,
                    ParseContentMatchOptions(modifierText, path, line)));
            }

            var allIndexes = contentSubs.Select(GetSubsigIndex)
                .Concat(macros.Keys)
                .Concat(regexSubs.Keys)
                .Concat(byteCompareSubs.Keys)
                .Concat(fuzzySubs.Keys)
                .ToArray();
            var expectedSubsigCount = allIndexes.Length == 0 ? 0 : allIndexes.Max() + 1;
            if (expectedSubsigCount > 64)
                throw new FormatException($"LDB signature has more than 64 subsignatures: {parts[0]}");

            yield return new LogicalSignature(
                parts[0],
                path,
                targetText,
                parts[2],
                contentSubs,
                target,
                macros,
                regexSubs,
                byteCompareSubs,
                fuzzySubs)
            {
                SourceEntry = raw
            };
        }
    }

    private static void ValidateLdbOffsetExpression(string expression, string path, string line)
    {
        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Unsupported LDB offset '{expression}' in {path}: {line}");
    }

    private static bool LooksLikeRegexSubSignature(string token)
    {
        var delimiters = FindRegexDelimiters(token);
        return delimiters.HasValue && delimiters.Value.Start > 0;
    }

    private static (int Start, int End)? FindRegexDelimiters(string token)
    {
        var first = -1;
        var escaped = false;
        for (var i = 0; i < token.Length; i++)
        {
            var c = token[i];
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (c != '/') continue;
            if (first < 0) first = i;
            else return (first, i);
        }
        return null;
    }

    private static LdbRegexSubSignature ParseRegexSubSignature(int index, string token, string path, string line)
    {
        var delimiters = FindRegexDelimiters(token);
        if (delimiters is null)
            throw new FormatException($"Invalid LDB PCRE subsignature in {path}: {token}");

        var firstSlash = delimiters.Value.Start;
        var lastSlash = delimiters.Value.End;
        var prefix = token[..firstSlash];
        var colon = prefix.IndexOf(':');
        var offset = colon >= 0 ? prefix[..colon] : "*";
        var trigger = colon >= 0 ? prefix[(colon + 1)..] : prefix;
        if (string.IsNullOrWhiteSpace(trigger) || string.IsNullOrWhiteSpace(token[(firstSlash + 1)..lastSlash]))
            throw new FormatException($"Invalid LDB PCRE trigger or pattern in {path}: {line}");
        if (offset.Length == 0) offset = "*";
        ValidateLdbOffsetExpression(offset, path, line);

        var flags = token[(lastSlash + 1)..];
        const string supported = "greismxAEU";
        foreach (var flag in flags)
        {
            if (!supported.Contains(flag))
                throw new FormatException($"Unsupported LDB PCRE flag '{flag}' in {path}: {line}");
        }
        if (flags.Distinct().Count() != flags.Length)
            throw new FormatException($"Duplicate LDB PCRE flag in {path}: {line}");
        if (flags.Contains('w') || flags.Contains('W'))
            throw new FormatException($"Wide modifier is not supported for PCRE LDB subsignatures: {path}: {line}");
        return new LdbRegexSubSignature(index, trigger, token[(firstSlash + 1)..lastSlash], flags, offset);
    }

    private static bool LooksLikeByteCompareSubSignature(string token)
    {
        var open = token.IndexOf('(');
        return open > 0 && token.EndsWith(')') &&
               int.TryParse(token[..open], out _);
    }

    private static LdbByteCompareSubSignature ParseByteCompareSubSignature(int index, string token, string path, string line)
    {
        var open = token.IndexOf('(');
        var close = token.LastIndexOf(')');
        if (open <= 0 || close != token.Length - 1 || !int.TryParse(token[..open], out var reference) || reference is < 0 or >= 64)
            throw new FormatException($"Invalid byte-compare LDB subsignature in {path}: {line}");

        var parts = token[(open + 1)..close].Split('#');
        if (parts.Length != 3)
            throw new FormatException($"Byte-compare LDB subsignature requires offset#options#comparisons: {path}: {line}");

        var shift = ParseByteCompareShift(parts[0], path, line);
        var (options, byteLength) = ParseByteCompareOptions(parts[1], path, line);
        var comparisons = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => ParseByteCompareComparison(x, path, line))
            .ToArray();
        if (comparisons.Length is < 1 or > 2)
            throw new FormatException($"Byte-compare LDB subsignature supports one or two comparisons: {path}: {line}");

        return new LdbByteCompareSubSignature(index, reference, shift, options, byteLength, comparisons);
    }

    private static int ParseByteCompareShift(string value, string path, string line)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException($"Invalid byte-compare offset '{value}': {path}: {line}");
        if (value.StartsWith(">>", StringComparison.Ordinal))
        {
            var n = ParseNonNegativeInt(value[2..], path, line);
            if (n <= 0) throw new FormatException($"Byte-compare offset must be positive: {path}: {line}");
            return n;
        }
        if (value.StartsWith("<<", StringComparison.Ordinal))
        {
            var n = ParseNonNegativeInt(value[2..], path, line);
            if (n <= 0) throw new FormatException($"Byte-compare offset must be positive: {path}: {line}");
            return checked(-n);
        }
        throw new FormatException($"Invalid byte-compare offset '{value}': {path}: {line}");
    }

    private static (ByteCompareOptions Options, int ByteLength) ParseByteCompareOptions(string value, string path, string line)
    {
        var i = 0;
        var numeric = ByteCompareOptions.None;
        while (i < value.Length && !char.IsDigit(value[i]))
        {
            numeric |= value[i] switch
            {
                'h' => ByteCompareOptions.Hex,
                'd' => ByteCompareOptions.Decimal,
                'a' => ByteCompareOptions.Auto,
                'i' => ByteCompareOptions.Binary,
                'l' => ByteCompareOptions.LittleEndian,
                'b' => ByteCompareOptions.BigEndian,
                'e' => ByteCompareOptions.Exact,
                _ => throw new FormatException($"Invalid byte-compare option '{value[i]}': {path}: {line}")
            };
            i++;
        }

        var numericKinds = new[] { ByteCompareOptions.Hex, ByteCompareOptions.Decimal, ByteCompareOptions.Auto, ByteCompareOptions.Binary }
            .Count(flag => numeric.HasFlag(flag));
        var endianKinds = new[] { ByteCompareOptions.LittleEndian, ByteCompareOptions.BigEndian }
            .Count(flag => numeric.HasFlag(flag));
        if (numericKinds != 1 || endianKinds != 1 || i >= value.Length)
            throw new FormatException($"Invalid byte-compare options '{value}': {path}: {line}");

        var byteLength = ParseNonNegativeInt(value[i..], path, line);
        if (byteLength <= 0)
            throw new FormatException($"Byte-compare length must be positive: {path}: {line}");
        if (numeric.HasFlag(ByteCompareOptions.Decimal) && numeric.HasFlag(ByteCompareOptions.LittleEndian))
            throw new FormatException($"Decimal byte-compare cannot use little-endian: {path}: {line}");
        if (numeric.HasFlag(ByteCompareOptions.Binary) && byteLength is not (1 or 2 or 4 or 8))
            throw new FormatException($"Binary byte-compare length must be 1, 2, 4 or 8: {path}: {line}");
        if (numeric.HasFlag(ByteCompareOptions.Binary)) numeric |= ByteCompareOptions.Exact;
        return (numeric, byteLength);
    }

    private static ByteCompareComparison ParseByteCompareComparison(string value, string path, string line)
    {
        if (value.Length < 2 || value[0] is not ('<' or '>' or '='))
            throw new FormatException($"Invalid byte-compare comparison '{value}': {path}: {line}");
        var number = ParseNumericLong(value[1..], path, line);
        return new ByteCompareComparison(value[0], number);
    }

    private static LdbFuzzyImageSubSignature ParseFuzzyImageSubSignature(int index, string token, string path, string line)
    {
        var parts = token.Split('#');
        if (parts.Length is < 2 or > 3 || !Core.HexCodec.TryDecode(parts[1], out var hash) || hash.Length != 8)
            throw new FormatException($"Invalid fuzzy_img LDB subsignature: {path}: {line}");
        uint distance = 0;
        if (parts.Length == 3 && (!uint.TryParse(parts[2], out distance) || distance != 0))
            throw new FormatException($"ClamAV 1.5 image fuzzy hashes require hamming distance 0: {path}: {line}");
        return new LdbFuzzyImageSubSignature(index, hash, distance);
    }

    private static int ParseNonNegativeInt(string value, string path, string line)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) && hex >= 0)
            return hex;
        if (int.TryParse(value, out var dec) && dec >= 0)
            return dec;
        throw new FormatException($"Invalid non-negative integer '{value}': {path}: {line}");
    }

    private static long ParseNumericLong(string value, string path, string line)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            long.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) && hex >= 0)
            return hex;
        if (long.TryParse(value, out var dec) && dec >= 0)
            return dec;
        throw new FormatException($"Invalid numeric value '{value}': {path}: {line}");
    }

    private static int GetSubsigIndex(ContentSignature signature)
    {
        var hash = signature.Name.LastIndexOf('#');
        return hash >= 0 && int.TryParse(signature.Name[(hash + 1)..], out var index) ? index : 0;
    }

    private static ContentMatchOptions ParseContentMatchOptions(string? text, string path, string line)
    {
        if (string.IsNullOrEmpty(text)) return ContentMatchOptions.None;
        var result = ContentMatchOptions.None;
        foreach (var option in text)
        {
            result |= option switch
            {
                'i' => ContentMatchOptions.IgnoreCase,
                'w' => ContentMatchOptions.Wide,
                'f' => ContentMatchOptions.FullWord,
                'a' => ContentMatchOptions.Ascii,
                _ => throw new FormatException($"Unsupported LDB subsignature modifier '{option}' in {path}: {line}")
            };
        }
        return result;
    }

    private static LdbTargetDescription? ParseLdbTarget(string text)
    {
        var targetValue = 0;
        var targetSpecified = false;
        var minEngine = 0;
        var maxEngine = int.MaxValue;
        long? minFileSize = null, maxFileSize = null, minEp = null, maxEp = null;
        int? minSections = null, maxSections = null;
        string? container = null, handlerType = null, iconGroup1 = null, iconGroup2 = null;
        IReadOnlyList<string>? intermediates = null;
        var hasNewExtension = false;
        var engineSpecified = false;

        var attrs = text.Split(',', StringSplitOptions.RemoveEmptyEntries);
        if (attrs.Length == 0)
            throw new FormatException("Empty LDB target description.");

        for (var i = 0; i < attrs.Length; i++)
        {
            var token = attrs[i];
            var colon = token.IndexOf(':');
            if (colon <= 0)
                throw new FormatException($"Invalid LDB target attribute: {token}");

            var key = token[..colon];
            var value = token[(colon + 1)..];

            // ClamAV 1.5.4 requires Engine to be the first attribute for backward compatibility.
            if (key.Equals("Engine", StringComparison.Ordinal))
            {
                if (i != 0)
                    throw new FormatException("LDB Engine attribute must be first.");
                (minEngine, maxEngine) = ParseIntRange(value, int.MaxValue, allowWildcard: false, requireRange: true);
                engineSpecified = true;
                continue;
            }

            if (key.Equals("Target", StringComparison.Ordinal))
            {
                if (!int.TryParse(value, out targetValue) || targetValue is < 0 or > 14)
                    throw new FormatException($"Invalid LDB target: {value}");
                targetSpecified = true;
                continue;
            }

            hasNewExtension = true;
            switch (key)
            {
                case "FileSize":
                    (minFileSize, maxFileSize) = ParseLongRange(value, requireRange: true);
                    break;
                case "EntryPoint":
                    (minEp, maxEp) = ParseLongRange(value, requireRange: true);
                    break;
                case "NumberOfSections":
                    (minSections, maxSections) = ParseIntRange(value, int.MaxValue, allowWildcard: false, requireRange: true);
                    break;
                case "IconGroup1":
                    if (value.Length == 0) throw new FormatException("IconGroup1 cannot be empty.");
                    iconGroup1 = value;
                    break;
                case "IconGroup2":
                    if (value.Length == 0) throw new FormatException("IconGroup2 cannot be empty.");
                    iconGroup2 = value;
                    break;
                case "Container":
                    container = NormalizeFileType(value);
                    break;
                case "HandlerType":
                    handlerType = NormalizeFileType(value);
                    break;
                case "Intermediates":
                    var layers = value.Split('>', StringSplitOptions.RemoveEmptyEntries);
                    if (layers.Length == 0 || layers.Length > 16)
                        throw new FormatException("LDB Intermediates supports 1..16 layers.");
                    intermediates = layers.Select(NormalizeFileType).ToArray();
                    break;
                default:
                    // ClamAV treats an unknown TDB attribute as an unsupported signature
                    // and skips that signature instead of failing the whole database file.
                    return null;
            }
        }

        if (!targetSpecified)
            throw new FormatException("LDB target description requires Target.");

        if (hasNewExtension && (!engineSpecified || minEngine < 51))
            throw new FormatException("LDB attributes other than Target require Engine min level >= 51.");

        if (iconGroup1 is not null || iconGroup2 is not null)
        {
            if (targetValue != 1)
                throw new FormatException("IconGroup is only supported with Target:1 (PE).");
        }

        if ((minEp is not null || maxEp is not null || minSections is not null || maxSections is not null) &&
            targetValue is not (1 or 6 or 9))
        {
            throw new FormatException("EntryPoint/NumberOfSections are only supported with PE/ELF/Mach-O targets.");
        }

        return new LdbTargetDescription(
            targetValue, minFileSize, maxFileSize, minEp, maxEp, minSections, maxSections,
            container, intermediates, handlerType, iconGroup1, iconGroup2, minEngine, maxEngine, targetSpecified);
    }

    private static (int Min, int Max) ParseIntRange(string value, int defaultMax, bool allowWildcard, bool requireRange)
    {
        if (allowWildcard && value == "*") return (0, defaultMax);
        var parts = value.Split('-', 2);
        if (requireRange && parts.Length != 2)
            throw new FormatException($"Invalid numeric range: {value}");
        if (!int.TryParse(parts[0], out var min) || min < 0)
            throw new FormatException($"Invalid numeric range: {value}");
        var max = parts.Length == 1 ? min :
            int.TryParse(parts[1], out var parsedMax) ? parsedMax : throw new FormatException($"Invalid numeric range: {value}");
        if (max < min) throw new FormatException($"Invalid numeric range: {value}");
        return (min, max);
    }

    private static (long Min, long Max) ParseLongRange(string value, bool requireRange)
    {
        var parts = value.Split('-', 2);
        if (requireRange && parts.Length != 2)
            throw new FormatException($"Invalid numeric range: {value}");
        if (!long.TryParse(parts[0], out var min) || min < 0)
            throw new FormatException($"Invalid numeric range: {value}");
        var max = parts.Length == 1 ? min :
            long.TryParse(parts[1], out var parsedMax) ? parsedMax : throw new FormatException($"Invalid numeric range: {value}");
        if (max < min) throw new FormatException($"Invalid numeric range: {value}");
        return (min, max);
    }

    private static string NormalizeFileType(string value)
    {
        if (value == "*") return "ANY";
        var key = value.Trim().ToUpperInvariant();
        return key switch
        {
            "CL_TYPE_ANY" => "ANY",
            "CL_TYPE_MSEXE" or "CL_TYPE_PE" or "PE" => "PE",
            "CL_TYPE_MSOLE2" or "CL_TYPE_OLE2" or "OLE2" => "OLE2",
            "CL_TYPE_HTML" or "HTML" => "HTML",
            "CL_TYPE_MAIL" or "MAIL" => "MAIL",
            "CL_TYPE_GRAPHICS" or "GRAPHICS" => "GRAPHICS",
            "CL_TYPE_ELF" or "ELF" => "ELF",
            "CL_TYPE_TEXT_ASCII" or "CL_TYPE_ASCII" or "ASCII" or "TEXT_ASCII" => "ASCII",
            "CL_TYPE_MACHO" or "CL_TYPE_MACH_O" or "CL_TYPE_MACHO_UNIBIN" or "MACH-O" or "MACHO" => "MACH-O",
            "CL_TYPE_PDF" or "PDF" => "PDF",
            "CL_TYPE_FLASH" or "CL_TYPE_SWF" or "FLASH" or "SWF" => "FLASH",
            "CL_TYPE_JAVA" or "JAVA" => "JAVA",
            "CL_TYPE_INTERNAL" or "INTERNAL" => "INTERNAL",
            "CL_TYPE_OTHER" or "OTHER" => "OTHER",
            "CL_TYPE_7Z" or "7Z" => "7Z",
            "CL_TYPE_ZIP" or "ZIP" => "ZIP",
            "CL_TYPE_RAR" or "RAR" => "RAR",
            "CL_TYPE_TAR" or "CL_TYPE_POSIX_TAR" or "TAR" or "POSIX_TAR" => "POSIX_TAR",
            "CL_TYPE_OLD_TAR" or "OLD_TAR" => "OLD_TAR",
            "CL_TYPE_GZ" or "GZIP" or "GZ" => "GZ",
            "CL_TYPE_BZ" or "BZIP2" or "BZ" => "BZ",
            "CL_TYPE_XZ" or "XZ" => "XZ",
            "CL_TYPE_CPIO_CRC" or "CPIO_CRC" => "CPIO_CRC",
            "CL_TYPE_CPIO_NEWC" or "CPIO_NEWC" => "CPIO_NEWC",
            "CL_TYPE_CPIO_ODC" or "CPIO_ODC" => "CPIO_ODC",
            "CL_TYPE_CPIO_OLD" or "CPIO_OLD" => "CPIO_OLD",
            "CL_TYPE_OOXML_WORD" or "OOXML_WORD" => "OOXML_WORD",
            "CL_TYPE_OOXML_XL" or "OOXML_XL" => "OOXML_XL",
            "CL_TYPE_OOXML_PPT" or "OOXML_PPT" => "OOXML_PPT",
            "CL_TYPE_CAB" or "CAB" => "CAB",
            "CL_TYPE_RIFF" or "RIFF" => "RIFF",
            _ => key.StartsWith("CL_TYPE_", StringComparison.Ordinal) ? key[8..] : key
        };
    }

    private static string[] SplitLdbFields(string line)
    {
        var fields = new List<string>();
        var start = 0;
        var escaped = false;
        var inRegex = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (c == '/')
            {
                inRegex = !inRegex;
                continue;
            }
            if (c == ';' && !inRegex)
            {
                fields.Add(line[start..i]);
                start = i + 1;
            }
        }
        fields.Add(line[start..]);
        return fields.ToArray();
    }

    public static IconDatabase ParseIdbFile(string path)
    {
        var database = new IconDatabase();
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var parts = line.Split(':');
            if (parts.Length != 4)
                throw new FormatException($"Invalid IDB signature in {path}: {line}");
            if (parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
                throw new FormatException($"IDB name/group fields cannot be empty in {path}: {line}");
            if (!Core.HexCodec.TryDecode(parts[3], out var rawHash) || rawHash.Length != 62)
                throw new FormatException($"Invalid IDB metric in {path}: {line}");

            var hex = parts[3];
            var side = Convert.ToInt32(hex[..2], 16);
            if (side is not (16 or 24 or 32))
                throw new FormatException($"Unsupported IDB side {side} in {path}: {line}");

            var cursor = 2;
            uint[] colorAvg = new uint[3]; byte[] colorX = new byte[3]; byte[] colorY = new byte[3];
            uint[] grayAvg = new uint[3]; byte[] grayX = new byte[3]; byte[] grayY = new byte[3];
            byte[] brightAvg = new byte[3]; byte[] brightX = new byte[3]; byte[] brightY = new byte[3];
            byte[] darkAvg = new byte[3]; byte[] darkX = new byte[3]; byte[] darkY = new byte[3];
            byte[] edgeAvg = new byte[3]; byte[] edgeX = new byte[3]; byte[] edgeY = new byte[3];
            byte[] noEdgeAvg = new byte[3]; byte[] noEdgeX = new byte[3]; byte[] noEdgeY = new byte[3];

            for (var i = 0; i < 3; i++) { colorAvg[i] = ReadHex(hex, ref cursor, 3); colorX[i] = ReadByteHex(hex, ref cursor, 2); colorY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { grayAvg[i] = ReadHex(hex, ref cursor, 3); grayX[i] = ReadByteHex(hex, ref cursor, 2); grayY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { brightAvg[i] = ReadByteHex(hex, ref cursor, 2); brightX[i] = ReadByteHex(hex, ref cursor, 2); brightY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { darkAvg[i] = ReadByteHex(hex, ref cursor, 2); darkX[i] = ReadByteHex(hex, ref cursor, 2); darkY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { edgeAvg[i] = ReadByteHex(hex, ref cursor, 2); edgeX[i] = ReadByteHex(hex, ref cursor, 2); edgeY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { noEdgeAvg[i] = ReadByteHex(hex, ref cursor, 2); noEdgeX[i] = ReadByteHex(hex, ref cursor, 2); noEdgeY[i] = ReadByteHex(hex, ref cursor, 2); }
            var rsum = ReadByteHex(hex, ref cursor, 2);
            var gsum = ReadByteHex(hex, ref cursor, 2);
            var bsum = ReadByteHex(hex, ref cursor, 2);
            var ccount = ReadByteHex(hex, ref cursor, 2);
            if (rsum + gsum + bsum > 103 || ccount > 100)
                throw new FormatException($"Invalid IDB color spread data in {path}: {line}");

            var limit = side - side / 8;
            if (colorX.Any(x => x > limit) || colorY.Any(x => x > limit) || grayX.Any(x => x > limit) || grayY.Any(x => x > limit) ||
                brightX.Any(x => x > limit) || brightY.Any(x => x > limit) || darkX.Any(x => x > limit) || darkY.Any(x => x > limit) ||
                edgeX.Any(x => x > limit) || edgeY.Any(x => x > limit) || noEdgeX.Any(x => x > limit) || noEdgeY.Any(x => x > limit) ||
                colorAvg.Any(x => x > 4072) || grayAvg.Any(x => x > 4072))
                throw new FormatException($"Invalid IDB coordinate/average data in {path}: {line}");

            var metric = new IconMetric(side, colorAvg, colorX, colorY, grayAvg, grayX, grayY,
                brightAvg, brightX, brightY, darkAvg, darkX, darkY, edgeAvg, edgeX, edgeY,
                noEdgeAvg, noEdgeX, noEdgeY, rsum, gsum, bsum, ccount);
            database.Add(new IconDatabaseEntry(parts[0], parts[1], parts[2], metric)
            {
                SourceEntry = raw
            });
        }
        return database;
    }

    private static uint ReadHex(string text, ref int cursor, int digits)
    {
        if (cursor + digits > text.Length || !uint.TryParse(text[cursor..(cursor + digits)], System.Globalization.NumberStyles.HexNumber, null, out var value))
            throw new FormatException("Invalid hexadecimal IDB metric.");
        cursor += digits;
        return value;
    }

    private static byte ReadByteHex(string text, ref int cursor, int digits) => (byte)ReadHex(text, ref cursor, digits);

    public static IEnumerable<ContentSignature> ParseDbFile(string path)
    {
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var equals = line.IndexOf('=');
            if (equals <= 0)
                throw new FormatException($"Invalid DB signature in {path}: {line}");

            var name = line[..equals];
            var pattern = line[(equals + 1)..];
            yield return new ContentSignature(
                name,
                SignatureType.Content,
                path,
                HexPatternParser.Parse(pattern))
            {
                SourceEntry = raw
            };
        }
    }

    private static bool TryGetAlgorithm(string hashText, out HashAlgorithmKind algorithm, out byte[] hash)
    {
        algorithm = default;
        hash = Array.Empty<byte>();
        if (!Core.HexCodec.TryDecode(hashText, out hash))
            return false;

        algorithm = hash.Length switch
        {
            16 => HashAlgorithmKind.Md5,
            20 => HashAlgorithmKind.Sha1,
            32 => HashAlgorithmKind.Sha256,
            _ => throw new FormatException("Only MD5, SHA-1 and SHA-256 hash signatures are supported.")
        };
        return true;
    }

    private static long? ParseSize(string value)
    {
        if (value == "*")
            return null;

        if (!long.TryParse(value, out var size) || size <= 0 || size >= uint.MaxValue)
            throw new FormatException($"Invalid file size: {value}");
        return size;
    }

    private static uint ParseUInt(string value, string field)
        => uint.TryParse(value, out var result)
            ? result
            : throw new FormatException($"Invalid {field}: {value}");

    private static int ParseInt(string value)
        => int.TryParse(value, out var result)
            ? result
            : throw new FormatException($"Invalid integer: {value}");

    private static (int Minimum, int Maximum) ReadEngineRange(string attributes)
    {
        var minimum = 0;
        var maximum = int.MaxValue;

        foreach (var token in attributes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!token.StartsWith("Engine:", StringComparison.OrdinalIgnoreCase))
                continue;

            var range = token[7..];
            var parts = range.Split('-', 2, StringSplitOptions.TrimEntries);
            minimum = ParseInt(parts[0]);
            maximum = parts.Length == 2 ? ParseInt(parts[1]) : int.MaxValue;
            if (maximum < minimum)
                throw new FormatException($"Invalid Engine range: {range}");
            break;
        }

        return (minimum, maximum);
    }
}
