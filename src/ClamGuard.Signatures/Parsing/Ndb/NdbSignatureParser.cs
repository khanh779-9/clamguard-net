using ClamGuard.Signatures;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Parsing;

internal static class NdbSignatureParser
{
    internal static IEnumerable<NdbSignature> ParseNdbFile(string path, int engineFunctionalityLevel, bool selfProtection = false)
        => ParseNdbLines(File.ReadLines(path), path, engineFunctionalityLevel, selfProtection);

    internal static IEnumerable<NdbSignature> ParseNdbLines(IEnumerable<string> lines, string path, int engineFunctionalityLevel, bool selfProtection = false)
    {
        foreach (var raw in lines)
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

            var minimum = parts.Length >= 5 && parts[4].Length != 0 ? SignatureParserCommon.ParseInt(parts[4]) : (int?)null;
            var maximum = parts.Length >= 6 && parts[5].Length != 0 ? SignatureParserCommon.ParseInt(parts[5]) : (int?)null;
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
            var target = parts[1] == "*" ? 0 : SignatureParserCommon.ParseInt(parts[1]);
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
}
