using ClamGuard.Core;

namespace ClamGuard.Yara;

public sealed class YaraContentScanner : IContentScanner
{
    private readonly YaraEngine _engine;
    private readonly YaraScanOptions _options;
    public string Directory { get; }

    public YaraContentScanner(string directory, YaraScanOptions? options = null)
    {
        Directory = directory;
        _options = options ?? new YaraScanOptions();
        _engine = YaraEngine.LoadDirectory(directory, _options);
    }

    public IReadOnlyList<Detection> Scan(ReadOnlySpan<byte> data, string path, CancellationToken cancellationToken = default)
        => _engine.Scan(data, _options, cancellationToken)
            .Select(static hit => new Detection(
                hit.RuleName,
                SignatureType.Yara,
                hit.Offset,
                hit.RuleFile,
                hit.StringIdentifier is null ? null : $"matched {hit.StringIdentifier}"))
            .ToArray();
}
