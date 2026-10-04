using System.Text;
using System.Text.RegularExpressions;
using ClamGuard.Core;

namespace ClamGuard.Yara;

public sealed class YaraEngine
{
    private readonly IReadOnlyList<(YaraRule Rule, string File)> _rules;

    private YaraEngine(IReadOnlyList<(YaraRule Rule, string File)> rules) => _rules = rules;

    public int RuleCount => _rules.Count;

    public static YaraEngine LoadText(string text, string source = "inline.yar", YaraScanOptions? options = null)
    {
        options ??= new YaraScanOptions();
        return new YaraEngine(YaraParser.Parse(text, options).Select(rule => (rule, source)).ToArray());
    }

    public static YaraEngine LoadDirectory(string directory, YaraScanOptions? options = null)
    {
        options ??= new YaraScanOptions();
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);

        var rules = new List<(YaraRule, string)>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.*", SearchOption.AllDirectories)
                     .Where(static p => Path.GetExtension(p).Equals(".yar", StringComparison.OrdinalIgnoreCase)
                                      || Path.GetExtension(p).Equals(".yara", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (rules.Count >= options.MaxRules) break;
            foreach (var rule in YaraParser.Parse(File.ReadAllText(file), options))
            {
                if (rules.Count >= options.MaxRules) break;
                rules.Add((rule, file));
            }
        }
        return new YaraEngine(rules);
    }

    public IReadOnlyList<YaraMatch> Scan(ReadOnlySpan<byte> data, YaraScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new YaraScanOptions();
        var results = new List<YaraMatch>();
        foreach (var (rule, file) in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var matches = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in rule.Strings)
            {
                cancellationToken.ThrowIfCancellationRequested();
                matches[s.Identifier] = MatchString(s, data, options, cancellationToken);
            }

            if (new YaraConditionEvaluator(rule.Condition, matches, data.Length).Evaluate())
            {
                foreach (var hit in matches)
                {
                    foreach (var offset in hit.Value)
                        results.Add(new YaraMatch(rule.Name, offset, hit.Key, file));
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
            var raw = variants[0];
            for (var key = definition.XorMin.Value; key <= definition.XorMax.Value; key++)
            {
                if (results.Count >= options.MaxMatchesPerString) break;
                var x = raw.Select(b => (byte)(b ^ key)).ToArray();
                FindBytes(data, x, false, results, options.MaxMatchesPerString, definition.Fullword, cancellationToken);
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

internal static class YaraParser
{
    public static IReadOnlyList<YaraRule> Parse(string text, YaraScanOptions options)
    {
        var results = new List<YaraRule>();
        var source = StripComments(text);
        var headerRegex = new Regex(@"\brule\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*(?<tags>[^\{]+))?\s*\{", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (Match header in headerRegex.Matches(source))
        {
            var open = header.Index + header.Length - 1;
            var close = FindMatchingBrace(source, open);
            if (close < 0) continue;
            var name = header.Groups["name"].Value;
            var tags = header.Groups["tags"].Success
                ? header.Groups["tags"].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : Array.Empty<string>();
            var body = source[(open + 1)..close];
            var stringsSection = Section(body, "strings", "condition");
            var condition = ExtractCondition(body);
            if (condition.Length == 0) continue;
            var strings = ParseStrings(stringsSection, options).Take(options.MaxStringsPerRule).ToArray();
            results.Add(new YaraRule(name, tags, strings, condition));
        }
        return results;
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
            if (c == '/' && !inQuote && (i == 0 || text[i - 1] != '/') && (i + 1 >= text.Length || text[i + 1] != '/')) { inRegex = !inRegex; continue; }
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

    private static IEnumerable<YaraStringDefinition> ParseStrings(string section, YaraScanOptions options)
    {
        foreach (Match m in Regex.Matches(section, "(?m)^(?<id>\\$[A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?<value>\"(?:\\\\.|[^\"])*\"|\\{.*?\\}|/.*?/)(?<mods>[^\\r\\n;]*)\\s*;?"))
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
                try { regex = new Regex(pattern, flags | RegexOptions.CultureInvariant, options.RegexTimeout); }
                catch (ArgumentException) { continue; }
                yield return new YaraStringDefinition(id, YaraStringKind.Regex, null, null, regex, false, true, nocase, fullword, null, null);
            }
            else
            {
                var bytes = ParseHex(value);
                if (bytes.Length != 0)
                    yield return new YaraStringDefinition(id, YaraStringKind.Hex, bytes, null, null, false, true, nocase, false, xorMin, xorMax);
            }
        }
    }

    private static byte[] ParseHex(string value)
    {
        if (!value.StartsWith('{') || !value.EndsWith('}')) return [];
        var tokens = value[1..^1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var result = new List<byte>();
        foreach (var token in tokens)
        {
            if (token is "??" or "?") return [];
            if (token.Contains('[') || token.Contains(']') || token.Contains('-')) return [];
            if (token.Length != 2 || !byte.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out var b)) return [];
            result.Add(b);
        }
        return result.ToArray();
    }

    private static bool ContainsWord(string text, string word)
        => Regex.IsMatch(text, $@"(?<![A-Za-z0-9_]){Regex.Escape(word)}(?![A-Za-z0-9_])", RegexOptions.IgnoreCase);

    private static string StripComments(string text)
    {
        text = Regex.Replace(text, @"//.*?$", string.Empty, RegexOptions.Multiline);
        return Regex.Replace(text, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline);
    }
}

internal sealed class YaraConditionEvaluator
{
    private readonly IReadOnlyDictionary<string, List<int>> _matches;
    private readonly int _fileSize;
    private readonly string[] _tokens;
    private int _index;

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
