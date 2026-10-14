using System.Text;
using System.Text.RegularExpressions;
using ClamGuard.Core;

namespace ClamGuard.Yara;

/// <summary>
/// Custom SUBSET emulator of YARA rules — this is NOT a full YARA engine.
/// Supported: plain text strings with basic modifiers (nocase, wide, ascii, fullword, xor),
/// hex strings without wildcards or jumps, simple regex strings, and simple conditions built
/// from and/or/not, string references, count references, "N of (...)", any/all of them, and
/// filesize compared in plain bytes.
/// Unsupported (the affected part is ignored and a warning is recorded in <see cref="Warnings"/>
/// so a rule can never silently stop matching): modules, for-loops, wildcard string sets
/// ($a*), KB/MB/GB size suffixes, hex string wildcards and jumps, and the 'wide' modifier
/// on regex strings.
/// </summary>
public sealed class YaraEngine
{
    private readonly IReadOnlyList<(YaraRule Rule, string File)> _rules;
    private readonly IReadOnlyList<string> _warnings;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> _warningsByRule;

    private YaraEngine(
        IReadOnlyList<(YaraRule Rule, string File)> rules,
        IReadOnlyList<ParsedRule> parsed,
        IReadOnlyList<string> warnings)
    {
        _rules = rules;
        _warnings = warnings;
        var byRule = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var rule in parsed)
        {
            if (rule.Warnings.Count > 0) byRule.TryAdd(rule.Rule.Name, rule.Warnings);
        }

        _warningsByRule = byRule;
    }

    public int RuleCount => _rules.Count;

    /// <summary>
    /// Warnings collected while loading rules (skipped rules, unsupported constructs, truncation);
    /// empty when every rule is fully supported. Populated during <see cref="LoadText"/> and
    /// <see cref="LoadDirectory"/>.
    /// </summary>
    public IReadOnlyList<string> Warnings => _warnings;

    public static YaraEngine LoadText(string text, string source = "inline.yar", YaraScanOptions? options = null)
    {
        options ??= new YaraScanOptions();
        var parsed = YaraParser.Parse(text, options);
        var rules = parsed.Rules.Select(rule => (Rule: rule.Rule, File: source)).ToArray();
        return new YaraEngine(rules, parsed.Rules, parsed.Warnings);
    }

    public static YaraEngine LoadDirectory(string directory, YaraScanOptions? options = null)
    {
        options ??= new YaraScanOptions();
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);

        var rules = new List<(YaraRule Rule, string File)>();
        var parsed = new List<ParsedRule>();
        var warnings = new List<string>();
        var truncated = false;
        foreach (var file in Directory.EnumerateFiles(directory, "*.*", SearchOption.AllDirectories)
                     .Where(static p => Path.GetExtension(p).Equals(".yar", StringComparison.OrdinalIgnoreCase)
                                       || Path.GetExtension(p).Equals(".yara", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (rules.Count >= options.MaxRules)
            {
                truncated = true;
                break;
            }

            foreach (var rule in YaraParser.Parse(File.ReadAllText(file), options).Rules)
            {
                if (rules.Count >= options.MaxRules)
                {
                    truncated = true;
                    break;
                }

                rules.Add((rule.Rule, file));
                parsed.Add(rule);
            }
        }

        if (truncated)
            warnings.Add($"YARA rule limit reached (MaxRules = {options.MaxRules}); additional rules were ignored");
        return new YaraEngine(rules, parsed, warnings);
    }

    public IReadOnlyList<YaraMatch> Scan(ReadOnlySpan<byte> data, YaraScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new YaraScanOptions();
        var results = new List<YaraMatch>();
        foreach (var (rule, file) in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var matches = new Dictionary<string, List<int>>(StringComparer.Ordinal);
            foreach (var s in rule.Strings)
            {
                cancellationToken.ThrowIfCancellationRequested();
                matches[s.Identifier] = MatchString(s, data, options, cancellationToken);
            }

            if (new YaraConditionEvaluator(rule.Condition, matches, data.Length).Evaluate())
            {
                var ruleWarnings = _warningsByRule.TryGetValue(rule.Name, out var found)
                    ? found
                    : Array.Empty<string>();
                foreach (var hit in matches)
                {
                    foreach (var offset in hit.Value)
                        results.Add(new YaraMatch(rule.Name, offset, hit.Key, file) { Warnings = ruleWarnings });
                }
            }
        }
        return results;
    }

    private static List<int> MatchString(YaraStringDefinition definition, ReadOnlySpan<byte> data, YaraScanOptions options, CancellationToken cancellationToken)
    {
        var results = new List<int>();
        if (definition.Kind == YaraStringKind.Hex && definition.Bytes is not null)
        {
            FindBytes(data, definition.Bytes, definition.Nocase, results, options.MaxMatchesPerString, definition.Fullword, cancellationToken);
            return results;
        }

        if (definition.Kind == YaraStringKind.Regex && definition.Regex is not null)
        {
            var text = Encoding.Latin1.GetString(data);
            MatchCollection matches;
            try
            {
                matches = definition.Regex.Matches(text);
            }
            catch (RegexMatchTimeoutException)
            {
                return results;
            }
            foreach (Match match in matches)
            {
                cancellationToken.ThrowIfCancellationRequested();
                results.Add(match.Index);
                if (results.Count >= options.MaxMatchesPerString) break;
            }
            return results;
        }

        var textValue = definition.Text ?? string.Empty;
        var variants = new List<byte[]>();
        if (definition.Ascii) variants.Add(Encoding.Latin1.GetBytes(definition.Nocase ? textValue.ToUpperInvariant() : textValue));
        if (definition.Wide)
        {
            variants.Add(Encoding.Unicode.GetBytes(definition.Nocase ? textValue.ToUpperInvariant() : textValue));
            variants.Add(Encoding.BigEndianUnicode.GetBytes(definition.Nocase ? textValue.ToUpperInvariant() : textValue));
        }
        if (variants.Count == 0) variants.Add(Encoding.Latin1.GetBytes(textValue));

        foreach (var needle in variants)
        {
            if (results.Count >= options.MaxMatchesPerString) break;
            if (definition.Nocase)
            {
                var lower = data.ToArray();
                for (var i = 0; i < lower.Length; i++) lower[i] = ToAsciiUpper(lower[i]);
                FindBytes(lower, needle, false, results, options.MaxMatchesPerString, definition.Fullword, cancellationToken, originalDataForWordBoundary: data);
            }
            else
            {
                FindBytes(data, needle, false, results, options.MaxMatchesPerString, definition.Fullword, cancellationToken);
            }
        }

        if (definition.Kind == YaraStringKind.Text && definition.XorMin is not null && definition.XorMax is not null)
        {
            // Xor the original (never case-folded) bytes; with nocase the comparison folds case
            // on both the xored needle and the data.
            var raw = Encoding.Latin1.GetBytes(textValue);
            byte[]? foldedData = null;
            if (definition.Nocase)
            {
                foldedData = data.ToArray();
                for (var i = 0; i < foldedData.Length; i++) foldedData[i] = ToAsciiUpper(foldedData[i]);
            }

            for (var key = definition.XorMin.Value; key <= definition.XorMax.Value; key++)
            {
                if (results.Count >= options.MaxMatchesPerString) break;
                var xored = new byte[raw.Length];
                for (var j = 0; j < raw.Length; j++)
                {
                    var b = (byte)(raw[j] ^ key);
                    xored[j] = definition.Nocase ? ToAsciiUpper(b) : b;
                }

                if (foldedData is not null)
                    FindBytes(foldedData, xored, false, results, options.MaxMatchesPerString, definition.Fullword, cancellationToken, originalDataForWordBoundary: data);
                else
                    FindBytes(data, xored, false, results, options.MaxMatchesPerString, definition.Fullword, cancellationToken);
            }
        }

        return results;
    }

    private static void FindBytes(
        ReadOnlySpan<byte> haystack,
        ReadOnlySpan<byte> needle,
        bool ignored,
        List<int> results,
        int maxMatches,
        bool fullword,
        CancellationToken cancellationToken,
        ReadOnlySpan<byte> originalDataForWordBoundary = default)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length) return;
        var boundaryData = originalDataForWordBoundary.IsEmpty ? haystack : originalDataForWordBoundary;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (results.Count >= maxMatches) return;
            if ((i & 0x3fff) == 0) cancellationToken.ThrowIfCancellationRequested();
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                var a = haystack[i + j];
                var b = needle[j];
                if (ignored)
                {
                    if (ToAsciiUpper(a) != ToAsciiUpper(b)) { match = false; break; }
                }
                else if (a != b) { match = false; break; }
            }
            if (match)
            {
                if (!fullword || IsFullWordBoundary(boundaryData, i, needle.Length))
                {
                    results.Add(i);
                }
            }
        }
    }

    private static byte ToAsciiUpper(byte value) => value is >= (byte)'a' and <= (byte)'z' ? (byte)(value - 32) : value;

    private static bool IsFullWordBoundary(ReadOnlySpan<byte> data, int start, int length)
    {
        static bool Word(byte b) => b is >= (byte)'0' and <= (byte)'9' || b is >= (byte)'A' and <= (byte)'Z' || b is >= (byte)'a' and <= (byte)'z' || b == (byte)'_';
        var left = start > 0 && Word(data[start - 1]);
        var right = start + length < data.Length && Word(data[start + length]);
        return !left && !right;
    }
}

internal sealed record ParsedRule(YaraRule Rule, IReadOnlyList<string> Warnings);

internal sealed record YaraParseResult(IReadOnlyList<ParsedRule> Rules, IReadOnlyList<string> Warnings);

internal static class YaraParser
{
    public static YaraParseResult Parse(string text, YaraScanOptions options)
    {
        var rules = new List<ParsedRule>();
        var warnings = new List<string>();
        var source = StripComments(text);
        var headerRegex = new Regex(@"\brule\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*(?<tags>[^\{]+))?\s*\{", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (Match header in headerRegex.Matches(source))
        {
            var open = header.Index + header.Length - 1;
            var close = FindMatchingBrace(source, open);
            var name = header.Groups["name"].Value;
            if (close < 0)
            {
                warnings.Add($"rule '{name}': malformed rule (unmatched '{{'); rule skipped");
                continue;
            }
            var tags = header.Groups["tags"].Success
                ? header.Groups["tags"].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : Array.Empty<string>();
            var body = source[(open + 1)..close];
            var stringsSection = Section(body, "strings", "condition");
            var condition = ExtractCondition(body);
            if (condition.Length == 0)
            {
                warnings.Add($"rule '{name}': missing condition; rule skipped");
                continue;
            }
            var ruleWarnings = new List<string>();
            var strings = ParseStrings(stringsSection, options, name, ruleWarnings).ToArray();
            if (strings.Length > options.MaxStringsPerRule)
            {
                ruleWarnings.Add($"rule '{name}': string definitions truncated to {options.MaxStringsPerRule} (MaxStringsPerRule); additional strings ignored");
                strings = strings.Take(options.MaxStringsPerRule).ToArray();
            }
            YaraConditionEvaluator.ValidateCondition(name, condition, strings, ruleWarnings);
            rules.Add(new ParsedRule(new YaraRule(name, tags, strings, condition), ruleWarnings.Distinct(StringComparer.Ordinal).ToArray()));
        }
        warnings.AddRange(rules.SelectMany(static r => r.Warnings));
        return new YaraParseResult(rules, warnings);
    }

    private static int FindMatchingBrace(string text, int open)
    {
        var depth = 0;
        var inQuote = false;
        var inRegex = false;
        var escape = false;
        for (var i = open; i < text.Length; i++)
        {
            var c = text[i];
            if (escape) { escape = false; continue; }
            if ((inQuote || inRegex) && c == '\\') { escape = true; continue; }
            if (c == '"' && !inRegex) { inQuote = !inQuote; continue; }
            if (c == '/' && !inQuote)
            {
                if (inRegex) inRegex = false;
                else inRegex = OpensRegexLiteral(text, i);
                continue;
            }
            if (inQuote || inRegex) continue;
            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i;
        }
        return -1;
    }

    private static string Section(string body, string start, string end)
    {
        var startIndex = body.IndexOf(start + ":", StringComparison.OrdinalIgnoreCase);
        if (startIndex < 0) return string.Empty;
        startIndex += start.Length + 1;
        var endIndex = body.IndexOf(end + ":", startIndex, StringComparison.OrdinalIgnoreCase);
        return (endIndex >= 0 ? body[startIndex..endIndex] : body[startIndex..]).Trim();
    }

    private static string ExtractCondition(string body)
    {
        var idx = body.IndexOf("condition:", StringComparison.OrdinalIgnoreCase);
        return idx < 0 ? string.Empty : body[(idx + "condition:".Length)..].Trim();
    }

    private static IEnumerable<YaraStringDefinition> ParseStrings(string section, YaraScanOptions options, string ruleName, List<string> warnings)
    {
        // YARA string definitions are conventionally indented inside the strings
        // section, so allow leading whitespace before the identifier. The trailing
        // separator must not cross line endings, otherwise it swallows the next
        // definition's line-start anchor. Regex literals honor escaped slashes so
        // /http:\/\/evil/ is captured whole instead of being cut at the escape.
        foreach (Match m in Regex.Matches(section, "(?m)^\\s*(?<id>\\$[A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?<value>\"(?:\\\\.|[^\"])*\"|\\{.*?\\}|/(?:\\\\.|[^/\\\\])*/)(?<mods>[^\\r\\n;]*)[^\\S\\r\\n]*;?"))
        {
            var id = m.Groups["id"].Value;
            var value = m.Groups["value"].Value.Trim();
            var mods = m.Groups["mods"].Value.Trim();
            var nocase = ContainsWord(mods, "nocase");
            var wide = ContainsWord(mods, "wide");
            var ascii = !wide || ContainsWord(mods, "ascii");
            var fullword = ContainsWord(mods, "fullword");
            int? xorMin = null, xorMax = null;
            var xor = Regex.Match(mods, @"xor(?:\s+(?<min>\d+)(?:\s*-\s*(?<max>\d+))?)?", RegexOptions.IgnoreCase);
            if (xor.Success)
            {
                xorMin = xor.Groups["min"].Success ? int.Parse(xor.Groups["min"].Value) : 0;
                xorMax = xor.Groups["max"].Success ? int.Parse(xor.Groups["max"].Value) : 255;
            }

            if (value.StartsWith("\"", StringComparison.Ordinal))
            {
                var decoded = Regex.Unescape(value[1..^1]);
                yield return new YaraStringDefinition(id, YaraStringKind.Text, null, decoded, null, wide, ascii, nocase, fullword, xorMin, xorMax);
            }
            else if (value.StartsWith("/", StringComparison.Ordinal))
            {
                var pattern = value.Length >= 2 ? value[1..^1] : string.Empty;
                var flags = nocase ? RegexOptions.IgnoreCase : RegexOptions.None;
                Regex regex;
                try { regex = new Regex(UnescapeRegexSlashes(pattern), flags | RegexOptions.CultureInvariant, options.RegexTimeout); }
                catch (ArgumentException)
                {
                    warnings.Add($"rule '{ruleName}': regex string '{id}': pattern failed to compile; string ignored");
                    continue;
                }
                if (wide)
                    warnings.Add($"rule '{ruleName}': regex string '{id}': 'wide' modifier unsupported; ignored");
                yield return new YaraStringDefinition(id, YaraStringKind.Regex, null, null, regex, false, true, nocase, fullword, null, null);
            }
            else
            {
                var (bytes, reason) = ParseHex(value);
                if (bytes is not null)
                    yield return new YaraStringDefinition(id, YaraStringKind.Hex, bytes, null, null, false, true, nocase, false, xorMin, xorMax);
                else
                    warnings.Add($"rule '{ruleName}': hex string '{id}': {reason}; string ignored");
            }
        }
    }

    private static (byte[]? Bytes, string Reason) ParseHex(string value)
    {
        if (!value.StartsWith('{') || !value.EndsWith('}')) return (null, "unrecognized hex string");
        var tokens = value[1..^1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) return (null, "empty hex string");
        var result = new List<byte>(tokens.Length);
        foreach (var token in tokens)
        {
            if (token.Contains('?', StringComparison.Ordinal)) return (null, "wildcards ('?') unsupported");
            if (token.Contains('[') || token.Contains(']') || token.Contains('-')) return (null, "jumps ('[..]') unsupported");
            if (token.Length != 2 || !byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out var b)) return (null, $"invalid hex token '{token}'");
            result.Add(b);
        }
        return (result.ToArray(), string.Empty);
    }

    private static string UnescapeRegexSlashes(string pattern)
    {
        if (!pattern.Contains("\\/", StringComparison.Ordinal)) return pattern;
        var sb = new StringBuilder(pattern.Length);
        for (var i = 0; i < pattern.Length; i++)
        {
            if (pattern[i] == '\\' && i + 1 < pattern.Length && pattern[i + 1] == '/')
            {
                sb.Append('/');
                i++;
                continue;
            }
            sb.Append(pattern[i]);
        }
        return sb.ToString();
    }

    private static bool ContainsWord(string text, string word)
        => Regex.IsMatch(text, $@"(?<![A-Za-z0-9_]){Regex.Escape(word)}(?![A-Za-z0-9_])", RegexOptions.IgnoreCase);

    private static string StripComments(string text)
    {
        // Character state machine: // and /* */ are comments only outside string,
        // char and regex literals, so rules like $a = "http://evil.com" survive.
        var sb = new StringBuilder(text.Length);
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == '"' || c == '\'')
            {
                CopyStringLiteral(text, sb, ref i, c);
                continue;
            }
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '/')
            {
                while (i < text.Length && text[i] != '\n') i++;
                continue;
            }
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
            {
                var end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end < 0)
                {
                    sb.Append(c);
                    i++;
                    continue;
                }
                i = end + 2;
                continue;
            }
            if (c == '/' && OpensRegexLiteral(text, i))
            {
                sb.Append(c);
                i++;
                while (i < text.Length)
                {
                    if (text[i] == '\\' && i + 1 < text.Length)
                    {
                        sb.Append(text[i]).Append(text[i + 1]);
                        i += 2;
                        continue;
                    }
                    sb.Append(text[i]);
                    i++;
                    if (text[i - 1] == '/') break;
                }
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    private static void CopyStringLiteral(string text, StringBuilder sb, ref int i, char quote)
    {
        sb.Append(text[i]);
        i++;
        while (i < text.Length)
        {
            var c = text[i];
            sb.Append(c);
            i++;
            if (c == '\\' && i < text.Length)
            {
                sb.Append(text[i]);
                i++;
                continue;
            }
            if (c == quote) break;
        }
    }

    // A '/' opens a regex literal only at a value boundary (after '=', '(', an operator or
    // whitespace); after an identifier, number, ')' or ']' it is a division operator.
    private static bool OpensRegexLiteral(string text, int slashIndex)
        => slashIndex == 0 || !IsValueEnder(text[slashIndex - 1]);

    private static bool IsValueEnder(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or ')' or ']';
}

internal sealed class YaraConditionEvaluator
{
    private static readonly IReadOnlyDictionary<string, List<int>> EmptyMatches = new Dictionary<string, List<int>>();
    private static readonly Regex GlobSetRegex = new(@"\$[A-Za-z_][A-Za-z0-9_]*\s*\*", RegexOptions.CultureInvariant);
    private static readonly Regex StringReferenceRegex = new(@"[$#][A-Za-z_][A-Za-z0-9_]*", RegexOptions.CultureInvariant);

    private readonly IReadOnlyDictionary<string, List<int>> _matches;
    private readonly int _fileSize;
    private readonly string[] _tokens;
    private int _index;
    private string? _unsupportedToken;

    public YaraConditionEvaluator(string condition, IReadOnlyDictionary<string, List<int>> matches, int fileSize)
    {
        _matches = matches;
        _fileSize = fileSize;
        _tokens = Tokenize(condition);
    }

    public bool Evaluate()
    {
        var result = ParseOr();
        return result && _index == _tokens.Length;
    }

    /// <summary>
    /// Runs the evaluator without data and reports which condition tokens the subset grammar
    /// cannot consume. Token consumption is data-independent, so anything left over here is
    /// silently dropped during a real scan and must be turned into a warning.
    /// </summary>
    internal IReadOnlyList<string> ValidateConsume()
    {
        ParseOr();
        if (_unsupportedToken is not null) return new[] { _unsupportedToken };
        var idx = Math.Min(_index, _tokens.Length);
        return _tokens[idx..];
    }

    public static void ValidateCondition(string ruleName, string condition, IReadOnlyCollection<YaraStringDefinition> definedStrings, List<string> warnings)
    {
        var snippet = TruncateSnippet(condition);
        if (GlobSetRegex.IsMatch(condition))
            warnings.Add($"rule '{ruleName}': unsupported condition '{snippet}' ignored");

        var unconsumed = new YaraConditionEvaluator(condition, EmptyMatches, 0).ValidateConsume();
        if (unconsumed.Count > 0)
            warnings.Add($"rule '{ruleName}': unsupported condition '{snippet}' ignored");

        var definedIds = definedStrings.Select(static s => s.Identifier).ToArray();
        foreach (var reference in StringReferenceRegex.Matches(condition)
                     .Select(static m => m.Value[0] == '#' ? "$" + m.Value[1..] : m.Value)
                     .Distinct(StringComparer.Ordinal))
        {
            if (definedIds.Contains(reference, StringComparer.Ordinal)) continue;
            if (definedIds.Contains(reference, StringComparer.OrdinalIgnoreCase))
                warnings.Add($"rule '{ruleName}': string identifier '{reference}' in condition does not match its definition (identifiers are case-sensitive); ignored");
            else
                warnings.Add($"rule '{ruleName}': condition references undefined string '{reference}'; ignored");
        }
    }

    private static string TruncateSnippet(string condition)
    {
        var trimmed = condition.Trim();
        return trimmed.Length <= 80 ? trimmed : trimmed[..77] + "...";
    }

    private bool ParseOr()
    {
        var value = ParseAnd();
        while (Match("or")) value |= ParseAnd();
        return value;
    }

    private bool ParseAnd()
    {
        var value = ParseUnary();
        while (Match("and")) value &= ParseUnary();
        return value;
    }

    private bool ParseUnary()
    {
        if (Match("not")) return !ParseUnary();
        if (Match("(")) { var x = ParseOr(); Match(")"); return x; }
        if (Match("true")) return true;
        if (Match("false")) return false;
        if (Peek().Equals("filesize", StringComparison.OrdinalIgnoreCase))
        {
            _index++;
            var op = Next();
            if (!long.TryParse(Next(), out var rhs)) return false;
            return Compare(_fileSize, op, rhs);
        }
        if (Peek().Equals("any", StringComparison.OrdinalIgnoreCase) || Peek().Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            var any = Match("any");
            if (!any) Match("all");
            if (!Match("of")) return false;
            if (!Match("them")) return false;
            var total = _matches.Count;
            var hit = _matches.Values.Count(static x => x.Count > 0);
            return any ? hit > 0 : hit == total && total > 0;
        }
        if (long.TryParse(Peek(), out var required))
        {
            Next();
            if (!Match("of")) return false;
            var ids = new List<string>();
            if (Match("them"))
                ids.AddRange(_matches.Keys);
            else if (Match("("))
            {
                while (!string.IsNullOrEmpty(Peek()) && !Match(")"))
                {
                    if (Peek().StartsWith("$", StringComparison.Ordinal)) ids.Add(Next());
                    else Next();
                }
            }
            else return false;
            var hits = ids.Count(id => _matches.TryGetValue(id, out var value) && value.Count > 0);
            return hits >= required;
        }
        if (Peek().StartsWith("$", StringComparison.Ordinal))
        {
            var id = Next();
            return _matches.TryGetValue(id, out var hit) && hit.Count > 0;
        }
        if (Peek().StartsWith("#", StringComparison.Ordinal))
        {
            var id = Next()[1..];
            return _matches.TryGetValue("$" + id, out var hit) && hit.Count > 0;
        }
        _unsupportedToken ??= Peek();
        _index++;
        return false;
    }

    private string Peek() => _index < _tokens.Length ? _tokens[_index] : string.Empty;
    private string Next() => _index < _tokens.Length ? _tokens[_index++] : string.Empty;
    private bool Match(string token)
    {
        if (_index < _tokens.Length && _tokens[_index].Equals(token, StringComparison.OrdinalIgnoreCase)) { _index++; return true; }
        return false;
    }

    private static bool Compare(long left, string op, long right) => op switch
    {
        "<" => left < right,
        "<=" => left <= right,
        ">" => left > right,
        ">=" => left >= right,
        "==" or "=" => left == right,
        "!=" => left != right,
        _ => false
    };

    private static string[] Tokenize(string condition)
    {
        return Regex.Matches(condition, @"\$[A-Za-z_][A-Za-z0-9_]*|#[A-Za-z_][A-Za-z0-9_]*|<=|>=|==|!=|[()<>]=?|[A-Za-z_][A-Za-z0-9_]*|\d+")
            .Select(static m => m.Value).ToArray();
    }
}
