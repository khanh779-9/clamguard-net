namespace ClamGuard.Signatures;

[Flags]
public enum ContentMatchOptions
{
    None = 0,
    IgnoreCase = 1,
    Wide = 2,
    FullWord = 4,
    Ascii = 8
}
