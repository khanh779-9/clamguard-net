using ClamGuard.Core;

namespace ClamGuard.Bytecode;

public sealed class BytecodeContentScanner : IContentScanner
{
    private readonly ClamBcEngine _engine;
    private readonly BytecodeScanOptions _options;
    public string Directory { get; }

    public BytecodeContentScanner(string directory, BytecodeScanOptions? options = null)
    {
        Directory = directory;
        _options = options ?? new BytecodeScanOptions();
        _engine = ClamBcEngine.LoadDirectory(directory, _options);
    }

    public IReadOnlyList<Detection> Scan(ReadOnlySpan<byte> data, string path, CancellationToken cancellationToken = default)
        => _engine.Scan(data, _options, cancellationToken)
            .Select(static hit => new Detection(
                hit.Name,
                SignatureType.Bytecode,
                hit.Offset,
                hit.RuleFile,
                hit.Detail ?? $"return={hit.ReturnValue}"))
            .ToArray();
}
