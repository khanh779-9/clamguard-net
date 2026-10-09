

namespace ClamGuard.Bytecode;

internal sealed record ClamBcOperand(int Index, bool IsConstant = false, ulong Constant = 0, bool IsGlobal = false, int GlobalId = -1);
