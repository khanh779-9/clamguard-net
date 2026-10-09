

namespace ClamGuard.Bytecode;

internal sealed class ClamBcPdfObject
{
    public ClamBcPdfObject(int id,int offset,int size,int flags){Id=id;Offset=offset;Size=size;Flags=flags;}
    public int Id { get; }
    public int Offset { get; }
    public int Size { get; }
    public int Flags { get; set; }
}
