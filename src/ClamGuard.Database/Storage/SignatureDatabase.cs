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
    public DynamicConfiguration DynamicConfiguration { get; internal set; } = new();

    private NdbSignature[]? _ndbCache;
    private LogicalSignature[]? _logicalCache;
    private MetadataSignature[]? _metadataCache;
    private CdbSignature[]? _cdbCache;
    private HashSignature[]? _hashCache;
    private bool? _selfProtectionCache;

    public NdbSignature[] NdbSignatures => _ndbCache ??= _signatures.OfType<NdbSignature>().ToArray();
    public LogicalSignature[] LogicalSignatures => _logicalCache ??= _signatures.OfType<LogicalSignature>().ToArray();
    public MetadataSignature[] MetadataSignatures => _metadataCache ??= _signatures.OfType<MetadataSignature>().ToArray();
    public CdbSignature[] CdbSignatures => _cdbCache ??= _signatures.OfType<CdbSignature>().ToArray();
    public HashSignature[] HashSignatures => _hashCache ??= _signatures.OfType<HashSignature>().ToArray();

    public bool HasSelfProtectionSignatures
    {
        get
        {
            if (_selfProtectionCache is null)
                _selfProtectionCache = _signatures.OfType<NdbSignature>().Any(static x => x.IsSelfProtection);
            return _selfProtectionCache.Value;
        }
    }

    public void Add(Signature signature)
    {
        _signatures.Add(signature);
        InvalidateCache();
    }

    public void AddRange(IEnumerable<Signature> signatures)
    {
        _signatures.AddRange(signatures);
        InvalidateCache();
    }

    private void InvalidateCache()
    {
        _ndbCache = null;
        _logicalCache = null;
        _metadataCache = null;
        _cdbCache = null;
        _hashCache = null;
        _selfProtectionCache = null;
    }

    public CompiledSignatureSet Compile()
    {
        // Pre-materialize typed arrays once to prevent repetitive full-database LINQ allocations per scanned file
        _ = NdbSignatures;
        _ = LogicalSignatures;
        _ = MetadataSignatures;
        _ = CdbSignatures;
        _ = HashSignatures;

        var compiled = new CompiledSignatureSet();
        foreach (var signature in _signatures) compiled.Add(signature);
        compiled.Build();
        return compiled;
    }
}
