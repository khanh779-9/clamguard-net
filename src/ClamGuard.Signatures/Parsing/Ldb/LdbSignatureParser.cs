using ClamGuard.Signatures;

namespace ClamGuard.Signatures.Parsing;

internal static class LdbSignatureParser
{
    internal static IEnumerable<LogicalSignature> ParseLdbFile(string path, int engineFunctionalityLevel)
        => ParseLdbLines(File.ReadLines(path), path, engineFunctionalityLevel);

    internal static IEnumerable<LogicalSignature> ParseLdbLines(IEnumerable<string> lines, string path, int engineFunctionalityLevel)
    {
        foreach (var raw in lines)
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
            var target = LdbTargetParser.ParseLdbTarget(targetText);
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
                    macros[subsigIndex] = LdbSubsigParser.ParseMacroSubSignature(subsigIndex, token, path);
                    continue;
                }

                if (token.StartsWith("fuzzy_img#", StringComparison.OrdinalIgnoreCase))
                {
                    fuzzySubs[subsigIndex] = LdbSubsigParser.ParseFuzzyImageSubSignature(subsigIndex, token, path, line);
                    continue;
                }

                if (LdbSubsigParser.LooksLikeRegexSubSignature(token))
                {
                    regexSubs[subsigIndex] = LdbSubsigParser.ParseRegexSubSignature(subsigIndex, token, path, line);
                    continue;
                }

                if (LdbSubsigParser.LooksLikeByteCompareSubSignature(token))
                {
                    byteCompareSubs[subsigIndex] = LdbSubsigParser.ParseByteCompareSubSignature(subsigIndex, token, path, line);
                    continue;
                }

                contentSubs.Add(LdbSubsigParser.ParseContentSubSignature(subsigIndex, parts[0], token, path, line));
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

    private static int GetSubsigIndex(ContentSignature signature)
    {
        var hash = signature.Name.LastIndexOf('#');
        return hash >= 0 && int.TryParse(signature.Name[(hash + 1)..], out var index) ? index : 0;
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
}
