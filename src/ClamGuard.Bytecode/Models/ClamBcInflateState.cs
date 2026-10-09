

namespace ClamGuard.Bytecode;

internal sealed class ClamBcInflateState
{
    public ClamBcInflateState(int from, int to, int windowBits, bool done) { From = from; To = to; WindowBits = windowBits; Done = done; }
    public int From { get; }
    public int To { get; }
    public int WindowBits { get; }
    public bool Done { get; set; }
}
