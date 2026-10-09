

namespace ClamGuard.Bytecode;

internal sealed class ClamBcMapState
{
    public ClamBcMapState(int keySize, int valueSize) { KeySize = keySize; ValueSize = valueSize; }
    public int KeySize { get; }
    public int ValueSize { get; }
    public string? CurrentKey { get; set; }
    public Dictionary<string, ClamBcMapValue> Values { get; } = new(StringComparer.Ordinal);
}
