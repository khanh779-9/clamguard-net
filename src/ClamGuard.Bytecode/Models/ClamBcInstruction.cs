

namespace ClamGuard.Bytecode;

internal sealed record ClamBcInstruction(
    int Opcode,
    int Type,
    int Destination,
    IReadOnlyList<ClamBcOperand> Operands,
    int TargetTrue = -1,
    int TargetFalse = -1,
    int TargetBlock = -1,
    int ApiOrFunctionId = -1,
    int CastSourceWidth = 0,
    int GepScale = 1);
