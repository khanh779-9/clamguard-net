using System.Text;
using System.Text.RegularExpressions;

namespace ClamGuard.Signatures;

/// <summary>
/// POSIX Extended Regular Expression compatibility adapter used by ClamAV
/// metadata signatures. ClamAV 1.5.4 compiles metadata filename patterns with
/// REG_EXTENDED | REG_NOSUB using its bundled OpenBSD-derived regex engine.
/// .NET Regex is used as the execution engine after constraining/translating
/// syntax that would otherwise have different semantics.
/// </summary>
public sealed class PosixEreRegex
{
    private readonly Regex _regex;

    public PosixEreRegex(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        var translated = Translate(pattern);
        _regex = new Regex(
            translated,
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Singleline,
            TimeSpan.FromMilliseconds(250));
    }

    public bool IsMatch(string input) => _regex.IsMatch(input);

    private static string Translate(string pattern)
    {
        if (pattern.Length == 0)
            return pattern;

        var sb = new StringBuilder(pattern.Length + 16);
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];

            // Allow standard case-sensitivity flags like (?i) or (?-i) used in ClamAV signatures.
            if (c == '(' && i + 1 < pattern.Length && pattern[i + 1] == '?')
            {
                if (pattern.AsSpan(i).StartsWith("(?i)") || pattern.AsSpan(i).StartsWith("(?-i)"))
                {
                    sb.Append(pattern[i..(i + 4)]);
                    i += 3;
                    continue;
                }
                throw new ArgumentException("POSIX ERE does not support '(?' constructs.", nameof(pattern));
            }

            // Lazy quantifiers are .NET/Perl syntax, not POSIX ERE.
            if ((c is '*' or '+' or '?') && i + 1 < pattern.Length && pattern[i + 1] == '?')
                throw new ArgumentException("POSIX ERE does not support lazy quantifiers.", nameof(pattern));

            if (c != '\\')
            {
                if (c == '[')
                {
                    var end = FindBracketExpressionEnd(pattern, i);
                    if (end < 0)
                        throw new ArgumentException("Unterminated POSIX ERE bracket expression.", nameof(pattern));

                    sb.Append(TranslateBracketExpression(pattern[i..(end + 1)]));
                    i = end;
                }
                else
                {
                    sb.Append(c);
                }

                continue;
            }

            if (i + 1 >= pattern.Length)
                throw new ArgumentException("Trailing backslash in POSIX ERE.", nameof(pattern));

            var next = pattern[++i];
            switch (next)
            {
                // .NET interprets these as character classes/anchors that are
                // not POSIX ERE syntax. In a POSIX ERE they are not equivalent.
                case 'd': sb.Append('d'); break;
                case 'D': sb.Append('D'); break;
                case 'w': sb.Append('w'); break;
                case 'W': sb.Append('W'); break;
                case 's': sb.Append('s'); break;
                case 'S': sb.Append('S'); break;
                case 'A': sb.Append('A'); break;
                case 'Z': sb.Append('Z'); break;
                case 'z': sb.Append('z'); break;
                case 'G': sb.Append('G'); break;
                case 'B': sb.Append('B'); break;
                case 'p':
                case 'P':
                case 'k':
                case 'K':
                    throw new ArgumentException($"POSIX ERE does not support '\\{next}'.", nameof(pattern));
                case 'b':
                    // OpenBSD-derived regex accepts \b as backspace rather than
                    // the .NET word-boundary assertion.
                    sb.Append("\\x08");
                    break;
                case 'a': sb.Append("\\x07"); break;
                case 'f': sb.Append("\\x0C"); break;
                case 'n': sb.Append("\\n"); break;
                case 'r': sb.Append("\\r"); break;
                case 't': sb.Append("\\t"); break;
                case 'v': sb.Append("\\v"); break;
                default:
                    // POSIX escapes such as \., \+, \?, \\, \( and \) retain
                    // their literal character semantics in .NET as well.
                    sb.Append('\\').Append(next);
                    break;
            }
        }

        return sb.ToString();
    }

    private static int FindBracketExpressionEnd(string pattern, int start)
    {
        var escaped = false;
        for (var i = start + 1; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (c == '\\')
            {
                escaped = true;
                continue;
            }

            // POSIX bracket expressions may contain character-class, collating,
            // or equivalence constructs such as [:digit:], [.ch.], [=a=].
            if (c == '[' && i + 1 < pattern.Length && (pattern[i + 1] == ':' || pattern[i + 1] == '.' || pattern[i + 1] == '='))
            {
                var marker = pattern[i + 1];
                var close = pattern.IndexOf($"{marker}]", i + 2, StringComparison.Ordinal);
                if (close >= 0)
                {
                    i = close + 1;
                    continue;
                }
            }

            if (c == ']')
            {
                // A leading ']' is literal in POSIX bracket expressions.
                if (i == start + 1 || (i == start + 2 && pattern[start + 1] == '^'))
                    continue;
                return i;
            }
        }

        return -1;
    }

    private static string TranslateBracketExpression(string expression)
    {
        var sb = new StringBuilder(expression.Length + 16);
        for (var i = 0; i < expression.Length; i++)
        {
            if (expression[i] != '[' || i + 2 >= expression.Length || expression[i + 1] != ':')
            {
                sb.Append(expression[i]);
                continue;
            }

            var close = expression.IndexOf(":]", i + 2, StringComparison.Ordinal);
            if (close < 0)
            {
                sb.Append(expression[i]);
                continue;
            }

            var name = expression[(i + 2)..close];
            if (!TryGetPosixClass(name, out var replacement))
            {
                // Let the underlying regex engine reject unknown syntax rather
                // than silently broadening its meaning.
                sb.Append(expression[i]);
                continue;
            }

            sb.Append(replacement);
            // ":]" occupies two characters; skip both so the class's own
            // closing bracket is not re-emitted after the replacement.
            i = close + 1;
        }

        return sb.ToString();
    }

    private static bool TryGetPosixClass(string name, out string replacement)
    {
        replacement = name switch
        {
            "alnum" => "A-Za-z0-9",
            "alpha" => "A-Za-z",
            "blank" => " \\t",
            "cntrl" => "\\x00-\\x1F\\x7F",
            "digit" => "0-9",
            "graph" => "\\x21-\\x7E",
            "lower" => "a-z",
            "print" => "\\x20-\\x7E",
            "punct" => "!\\\"#$%&'()*+,\\-./:;<=>?@[\\\\\\]^_`{|}~",
            "space" => " \\t\\r\\n\\v\\f",
            "upper" => "A-Z",
            "xdigit" => "A-Fa-f0-9",
            _ => string.Empty
        };

        return replacement.Length != 0;
    }
}
