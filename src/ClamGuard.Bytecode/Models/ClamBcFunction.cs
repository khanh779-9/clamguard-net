

namespace ClamGuard.Bytecode;

internal sealed class ClamBcFunction
{
    public required int ArgumentCount { get; init; }
    public required int[] LocalTypes { get; init; }
    public required List<ClamBcInstruction> Instructions { get; init; }
    public required int BasicBlockCount { get; init; }
    public required List<int> BlockStarts { get; init; }
}
