using ClamGuard.Core;

namespace ClamGuard.Database.Storage;

public sealed record FileTypeMagicRule(
    int Mode,
    string OffsetExpression,
    int? NumericOffset,
    string MagicExpression,
    byte[]? MagicBytes,
    string RealType,
    string Type,
    int? MinimumFunctionalityLevel,
    int? MaximumFunctionalityLevel,
    bool IsPartition);

public sealed record DynamicConfigEntry(
    string Module,
    uint Value,
    int? MinimumFunctionalityLevel,
    int? MaximumFunctionalityLevel,
    string SourceFile,
    string SourceEntry);

public sealed record PhishingDatabaseRule(
    string Pattern,
    bool AllowList,
    string SourceFile,
    string SourceEntry);

public sealed record PasswordDatabaseEntry(
    string Name,
    string Attributes,
    string Container,
    int StorageType,
    byte[] Password,
    string SourceFile,
    string SourceEntry);

public sealed record CertificateDatabaseRule(
    string Name,
    bool IsBlocked,
    byte[] SubjectSha1,
    byte[] SerialSha1,
    string PublicKeyHex,
    bool CodeSign,
    bool TimeSign,
    bool CertSign,
    long? NotBefore,
    int? MinimumFunctionalityLevel,
    int? MaximumFunctionalityLevel,
    string SourceFile,
    string SourceEntry);

public sealed record CatalogDatabaseInfo(
    string Name,
    long Size,
    string Sha256,
    bool LooksLikePkcs7SignedData,
    string SourceFile);

public sealed record AlternativeRuleFile(
    string Name,
    string Kind,
    long Size,
    string Sha256,
    int EntryCount,
    string SourceFile);

public sealed record DatabaseInfoRecord(
    string Name,
    long Size,
    string Sha256,
    string SourceFile);

public sealed class SpecialDatabaseStore
{
    public List<FileTypeMagicRule> FileTypes { get; } = [];
    public List<DynamicConfigEntry> DynamicConfig { get; } = [];
    public List<PhishingDatabaseRule> PhishingRules { get; } = [];
    public List<PasswordDatabaseEntry> Passwords { get; } = [];
    public List<CertificateDatabaseRule> Certificates { get; } = [];
    public List<CatalogDatabaseInfo> Catalogs { get; } = [];
    public List<AlternativeRuleFile> AlternativeRuleFiles { get; } = [];
    public List<DatabaseInfoRecord> InfoRecords { get; } = [];
}
