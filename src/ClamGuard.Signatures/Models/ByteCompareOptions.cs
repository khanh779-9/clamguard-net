namespace ClamGuard.Signatures;

[Flags]
public enum ByteCompareOptions
{
    None = 0,
    Hex = 1,
    Decimal = 2,
    Binary = 4,
    Auto = 8,
    LittleEndian = 16,
    BigEndian = 32,
    Exact = 64
}
