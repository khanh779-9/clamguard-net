

namespace ClamGuard.Bytecode;

internal sealed class ClamBcBufferState
{
    public ClamBcBufferState(byte[]? data, long readCursor, int writeCursor, bool fileBacked)
    { Data = data; ReadCursor = readCursor; WriteCursor = writeCursor; FileBacked = fileBacked; }
    public byte[]? Data { get; }
    public long ReadCursor { get; set; }
    public int WriteCursor { get; set; }
    public bool FileBacked { get; }
}
