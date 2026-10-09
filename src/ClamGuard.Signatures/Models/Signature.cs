using ClamGuard.Core;
namespace ClamGuard.Signatures;

public abstract record Signature(string Name, SignatureType Type, string SourceFile)
{
    /// <summary>Original database line, retained only while applying .ign/.ign2 rules during load.</summary>
    public string? SourceEntry { get; set; }
}
