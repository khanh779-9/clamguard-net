using ClamGuard.Core;
namespace ClamGuard.Signatures;

public abstract record Signature(string Name, SignatureType Type, string SourceFile)
{
    /// <summary>Exact database entry line used for ClamAV .ign/.ign2 conditional-MD5 suppression.</summary>
    public string? SourceEntry { get; init; }
}
