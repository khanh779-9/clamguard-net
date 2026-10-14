namespace ClamGuard.Yara;

public enum YaraStringKind
{
    Text,
    Hex,
    Regex
}

public sealed record YaraStringDefinition(
    string Identifier,
    YaraStringKind Kind,
    byte[]? Bytes,
    string? Text,
    System.Text.RegularExpressions.Regex? Regex,
    bool Wide,
    bool Ascii,
    bool Nocase,
    bool Fullword,
    int? XorMin,
    int? XorMax);

public sealed record YaraRule(
    string Name,
    IReadOnlyList<string> Tags,
    IReadOnlyList<YaraStringDefinition> Strings,
    string Condition);

public sealed record YaraMatch(string RuleName, long? Offset, string? StringIdentifier, string RuleFile)
{
    /// <summary>
    /// Warnings about unsupported constructs in the matched rule; empty when the rule is fully supported.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

public sealed class YaraScanOptions
{
    public int MaxRules { get; init; } = 10000;
    public int MaxStringsPerRule { get; init; } = 4096;
    public int MaxMatchesPerString { get; init; } = 256;
    public TimeSpan RegexTimeout { get; init; } = TimeSpan.FromMilliseconds(250);
}
