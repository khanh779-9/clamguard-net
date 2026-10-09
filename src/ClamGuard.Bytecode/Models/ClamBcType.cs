

namespace ClamGuard.Bytecode;

internal sealed record ClamBcType(int Id, int Kind, int NumElements, int ContainedType, int Size, int Align)
{
    public bool IsPointer => Id is >= 65 and <= 68 || Kind == 5;
}
