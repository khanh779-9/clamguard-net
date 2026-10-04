using System.Diagnostics;
using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Parsing;

public static class HexPatternParser
{
    public static HexPattern Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new FormatException("Hex signature cannot be empty.");

        var atoms = ParseAtoms(text, 0, text.Length, allowTopLevelAlternation: false);
        return new HexPattern(atoms);
    }

    private static List<PatternAtom> ParseAtoms(string text, int start, int end, bool allowTopLevelAlternation)
    {
        var atoms = new List<PatternAtom>();
        var i = start;
        while (i < end)
        {
            if (char.IsWhiteSpace(text[i])) { i++; continue; }

            if (text[i] == '*')
            {
                atoms.Add(new GapAtom(0, int.MaxValue));
                i++;
                continue;
            }

            if (text[i] == '{')
            {
                var close = FindMatching(text, i, end, '{', '}');
                if (close < 0) throw new FormatException("Unclosed range wildcard.");
                atoms.Add(ParseRange(text[(i + 1)..close]));
                i = close + 1;
                continue;
            }

            if (text[i] == '[')
            {
                var close = FindMatching(text, i, end, '[', ']');
                if (close < 0) throw new FormatException("Unclosed byte-range wildcard.");
                atoms.Add(ParseBracketRange(text[(i + 1)..close]));
                i = close + 1;
                continue;
            }

            var negated = text[i] == '!' && i + 1 < end && text[i + 1] == '(';
            if (text[i] == '(' || negated)
            {
                var open = negated ? i + 1 : i;
                var close = FindMatching(text, open, end, '(', ')');
                if (close < 0) throw new FormatException("Unclosed alternate/class block.");
                var inner = text[(open + 1)..close].Trim();

                if (!negated && inner.Length == 1 && inner is "B" or "L" or "W")
                {
                    atoms.Add(inner[0] switch
                    {
                        'B' => new CharacterClassAtom(CharacterClassKind.WordBoundary),
                        'L' => new CharacterClassAtom(CharacterClassKind.LineBoundary),
                        'W' => new CharacterClassAtom(CharacterClassKind.NonAlphanumeric),
                        _ => throw new UnreachableException()
                    });
                }
                else
                {
                    var alternatives = SplitTopLevel(inner, '|');
                    if (alternatives.Count == 0)
                        throw new FormatException("Empty alternate block.");

                    var parsed = alternatives
                        .Select(x => new HexPattern(ParseAtoms(x, 0, x.Length, allowTopLevelAlternation: false)))
                        .ToArray();

                    if (negated)
                    {
                        if (parsed.Any(static x => !x.IsFixed) || parsed.Select(static x => x.MinLength).Distinct().Count() != 1)
                            throw new FormatException("Negated alternates must contain fixed-length alternatives of equal length.");
                    }
                    else if (parsed.Any(ContainsUnboundedGap) || parsed.Any(ContainsTooWideGenericRange))
                    {
                        throw new FormatException("Generic alternates cannot contain unbounded wildcards and ranged wildcards must stay below 128 bytes.");
                    }

                    atoms.Add(new AlternatePatternAtom(parsed, negated));
                }

                i = close + 1;
                continue;
            }

            if (text[i] is '|' && allowTopLevelAlternation)
                throw new FormatException("Unexpected top-level alternate separator.");

            if (i + 1 >= end)
                throw new FormatException("Odd-length hex signature.");

            var hi = text[i];
            var lo = text[i + 1];
            if (hi == '?' && lo == '?')
            {
                atoms.Add(new MaskedByteAtom(0, 0));
            }
            else if (hi == '?')
            {
                atoms.Add(new MaskedByteAtom(ParseNibble(lo), 0x0F));
            }
            else if (lo == '?')
            {
                atoms.Add(new MaskedByteAtom((byte)(ParseNibble(hi) << 4), 0xF0));
            }
            else
            {
                atoms.Add(new ExactByteAtom((byte)((ParseNibble(hi) << 4) | ParseNibble(lo))));
            }
            i += 2;
        }

        return atoms;
    }

    private static int FindMatching(string text, int open, int end, char openChar, char closeChar)
    {
        var depth = 0;
        for (var i = open; i < end; i++)
        {
            if (text[i] == openChar)
                depth++;
            else if (text[i] == closeChar)
            {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }

    private static List<string> SplitTopLevel(string text, char separator)
    {
        var parts = new List<string>();
        var depth = 0;
        var last = 0;
        for (var i = 0; i < text.Length; i++)
        {
            switch (text[i])
            {
                case '(':
                case '[':
                case '{':
                    depth++;
                    break;
                case ')':
                case ']':
                case '}':
                    depth--;
                    if (depth < 0) throw new FormatException("Unbalanced pattern group.");
                    break;
                default:
                    if (text[i] == separator && depth == 0)
                    {
                        parts.Add(text[last..i]);
                        last = i + 1;
                    }
                    break;
            }
        }

        parts.Add(text[last..]);
        parts = parts.Select(static x => x.Trim()).Where(static x => x.Length > 0).ToList();
        return parts;
    }

    private static GapAtom ParseRange(string inner)
    {
        if (string.IsNullOrWhiteSpace(inner)) throw new FormatException("Empty range.");
        if (!inner.Contains('-'))
        {
            var n = ParseInt(inner);
            return new GapAtom(n, n);
        }

        var parts = inner.Split('-', 2);
        var min = parts[0].Length == 0 ? 0 : ParseInt(parts[0]);
        var max = parts[1].Length == 0 ? int.MaxValue : ParseInt(parts[1]);
        if (min < 0 || max < min) throw new FormatException("Invalid range.");
        return new GapAtom(min, max);
    }

    private static GapAtom ParseBracketRange(string inner)
    {
        var parts = inner.Split('-', 2);
        if (parts.Length != 2) throw new FormatException("Bracket range must be x-y.");
        var min = ParseInt(parts[0]);
        var max = ParseInt(parts[1]);
        if (min < 0 || max < min || max > 32)
            throw new FormatException("Invalid bracket range; the maximum gap is 32 bytes.");
        return new GapAtom(min, max);
    }


    private static bool ContainsUnboundedGap(HexPattern pattern) => pattern.Atoms.Any(atom =>
        atom is GapAtom { MaxBytes: int.MaxValue } ||
        atom is AlternatePatternAtom nested && nested.Alternatives.Any(ContainsUnboundedGap));

    private static bool ContainsTooWideGenericRange(HexPattern pattern) => pattern.Atoms.Any(atom =>
        atom is GapAtom { MaxBytes: > 127 } && atom is not GapAtom { MaxBytes: int.MaxValue } ||
        atom is AlternatePatternAtom nested && nested.Alternatives.Any(ContainsTooWideGenericRange));
    private static int ParseInt(string value)
    {
        if (int.TryParse(value, out var dec) && dec >= 0) return dec;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) && hex >= 0)
            return hex;
        throw new FormatException($"Invalid number: {value}");
    }

    private static byte ParseNibble(char c)
    {
        var value = c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => -1
        };
        if (value < 0) throw new FormatException($"Invalid hex nibble: {c}");
        return (byte)value;
    }
}
