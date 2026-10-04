using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Matching;

namespace ClamGuard.Database.Storage;

public sealed class SignatureDatabase
{
    private readonly List<Signature> _signatures = [];
    public IReadOnlyList<Signature> Signatures => _signatures;
    public long Generation { get; internal set; }
    public IReadOnlyList<DatabaseInfo> Databases { get; internal set; } = [];
    public IconDatabase? IconDatabase { get; internal set; }
    public SpecialDatabaseStore SpecialDatabases { get; } = new();
    public bool HasSelfProtectionSignatures => _signatures.OfType<NdbSignature>().Any(static x => x.IsSelfProtection);

    public void AddRange(IEnumerable<Signature> signatures) => _signatures.AddRange(signatures);

    public CompiledSignatureSet Compile()
    {
        var compiled = new CompiledSignatureSet();
        foreach (var signature in _signatures) compiled.Add(signature);
        compiled.Build();
        return compiled;
    }
}
