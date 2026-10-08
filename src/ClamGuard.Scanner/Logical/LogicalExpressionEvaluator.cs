namespace ClamGuard.Scanner;

/// <summary>
/// Lexer + Parser boolean AST cho biểu thức logic LDB ("0&1&2...", count modifiers).
/// </summary>
internal static class LogicalExpressionEvaluator
{
    private enum TokenKind { Number, And, Or, LParen, RParen, Eq, Gt, Lt, Comma, End }
    private readonly record struct Token(TokenKind Kind, int Value = 0);

    private readonly record struct EvalValue(bool Result, int Count, HashSet<int> Distinct)
    {
        public static EvalValue Empty => new(false, 0, []);

        public EvalValue Merge(EvalValue other, bool result)
        {
            // ClamAV only propagates match counts/IDs from a logical block when
            // the block itself evaluates true. This matters for outer count
            // modifiers such as `(0&1)>0`: a failed `0&1` contributes zero,
            // rather than leaking the count from the successful left operand.
            if (!result)
                return Empty;

            var distinct = new HashSet<int>(Distinct);
            distinct.UnionWith(other.Distinct);
            return new EvalValue(true, Count + other.Count, distinct);
        }
    }

    public static bool ValidateReferencesBefore(string expression, int exclusiveUpperBound)
    {
        if (exclusiveUpperBound < 0) return false;
        try
        {
            var parser = new Parser(expression, Array.Empty<ScannerEngine.SubsigMatches>(), int.MaxValue, exclusiveUpperBound);
            _ = parser.ParseOr(0);
            return parser.Current.Kind == TokenKind.End;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    public static bool Evaluate(string expression, IReadOnlyList<ScannerEngine.SubsigMatches> matches, int maxDepth)
    {
        var parser = new Parser(expression, matches, maxDepth);
        var value = parser.ParseOr(0);
        if (parser.Current.Kind != TokenKind.End)
            throw new FormatException("Unexpected trailing tokens in logical expression.");
        return value.Result;
    }

    private sealed class Parser
    {
        private readonly List<Token> _tokens;
        private readonly IReadOnlyList<ScannerEngine.SubsigMatches> _matches;
        private readonly int _maxDepth;
        private readonly int _referenceUpperBound;
        private int _index;

        public Token Current => _tokens[_index];

        public Parser(string expression, IReadOnlyList<ScannerEngine.SubsigMatches> matches, int maxDepth, int referenceUpperBound = -1)
        {
            _tokens = Tokenize(expression);
            _matches = matches;
            _maxDepth = maxDepth;
            _referenceUpperBound = referenceUpperBound;
        }

        // ClamAV 1.5.4 does not use conventional boolean precedence here.
        // cli_ac_chklsig() splits on the first top-level '&' or '|', then
        // recursively evaluates the remainder. This makes expressions such as
        // 0&1|2 parse as 0&(1|2), so we intentionally mirror that behavior.
        public EvalValue ParseOr(int depth)
        {
            Guard(depth);
            var left = ParsePrimary(depth + 1);
            if (Current.Kind is not (TokenKind.And or TokenKind.Or))
                return left;

            var op = Current.Kind;
            _index++;
            var right = ParseOr(depth + 1);
            var result = op == TokenKind.And
                ? left.Result && right.Result
                : left.Result || right.Result;
            return left.Merge(right, result);
        }

        private EvalValue ParsePrimary(int depth)
        {
            Guard(depth);
            EvalValue value;
            if (Current.Kind == TokenKind.LParen)
            {
                _index++;
                value = ParseOr(depth + 1);
                Expect(TokenKind.RParen);
                _index++;
            }
            else
            {
                Expect(TokenKind.Number);
                var index = Current.Value;
                _index++;
                if (_referenceUpperBound >= 0 && index >= _referenceUpperBound)
                    throw new FormatException("Logical expression references a future or unavailable subsignature.");
                if ((uint)index >= (uint)_matches.Count)
                    value = EvalValue.Empty;
                else
                {
                    var sub = _matches[index];
                    var distinct = sub.Count == 0 ? [] : new HashSet<int> { index };
                    value = new EvalValue(sub.Count > 0, sub.Count, distinct);
                }
            }
            return ParseComparison(value);
        }

        private EvalValue ParseComparison(EvalValue value)
        {
            if (Current.Kind is not (TokenKind.Eq or TokenKind.Gt or TokenKind.Lt))
                return value;

            var kind = Current.Kind;
            _index++;
            Expect(TokenKind.Number);
            var first = Current.Value;
            _index++;
            int? distinctMinimum = null;
            if (Current.Kind == TokenKind.Comma)
            {
                _index++;
                Expect(TokenKind.Number);
                distinctMinimum = Current.Value;
                _index++;
            }

            if (first < 0 || distinctMinimum is < 0)
                throw new FormatException("Logical comparison values must be non-negative.");

            var result = kind switch
            {
                TokenKind.Eq => value.Count == first && (!distinctMinimum.HasValue || value.Distinct.Count >= distinctMinimum.Value),
                TokenKind.Gt => value.Count > first && (!distinctMinimum.HasValue || value.Distinct.Count >= distinctMinimum.Value),
                TokenKind.Lt => value.Count < first && (!distinctMinimum.HasValue || value.Distinct.Count >= distinctMinimum.Value),
                _ => false
            };

            // A failed comparison is a failed logical block in ClamAV and must
            // not carry its pre-comparison count/IDs into an outer modifier.
            return result ? value with { Result = true } : EvalValue.Empty;
        }

        private void Expect(TokenKind kind)
        {
            if (Current.Kind != kind)
                throw new FormatException($"Unexpected logical token: expected {kind}, got {Current.Kind}.");
        }

        private void Guard(int depth)
        {
            if (depth > _maxDepth)
                throw new InvalidDataException("Logical expression nesting limit exceeded.");
        }

        private static List<Token> Tokenize(string expression)
        {
            var result = new List<Token>();
            for (var i = 0; i < expression.Length; i++)
            {
                var c = expression[i];
                if (char.IsWhiteSpace(c)) continue;
                if (char.IsDigit(c))
                {
                    var start = i;
                    while (i + 1 < expression.Length && char.IsDigit(expression[i + 1])) i++;
                    if (!int.TryParse(expression[start..(i + 1)], out var number))
                        throw new FormatException("Invalid logical integer.");
                    result.Add(new Token(TokenKind.Number, number));
                    continue;
                }
                result.Add(c switch
                {
                    '&' => new Token(TokenKind.And),
                    '|' => new Token(TokenKind.Or),
                    '(' => new Token(TokenKind.LParen),
                    ')' => new Token(TokenKind.RParen),
                    '=' => new Token(TokenKind.Eq),
                    '>' => new Token(TokenKind.Gt),
                    '<' => new Token(TokenKind.Lt),
                    ',' => new Token(TokenKind.Comma),
                    _ => throw new FormatException($"Unsupported logical expression character: {c}")
                });
            }
            result.Add(new Token(TokenKind.End));
            return result;
        }
    }
}
