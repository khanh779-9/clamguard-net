using ClamGuard.Core;
using ClamGuard.Signatures.Patterns;

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

public abstract record Signature(string Name, SignatureType Type, string SourceFile)
{
    /// <summary>Exact database entry line used for ClamAV .ign/.ign2 conditional-MD5 suppression.</summary>
    public string? SourceEntry { get; init; }
}

public sealed record HashSignature(
    string Name,
    SignatureType Type,
    string SourceFile,
    HashAlgorithmKind Algorithm,
    byte[] Hash,
    long? FileSize) : Signature(Name, Type, SourceFile);

public readonly record struct MetadataRange(long Min, long Max);

public sealed record MetadataSignature(
    string Name,
    string SourceFile,
    string ContainerType,
    int? Encrypted,
    PosixEreRegex? FileNameRegex,
    MetadataRange? OriginalSize,
    MetadataRange? CompressedSize,
    int? Res1,
    MetadataRange? FilePosition,
    int? CompressionMethod,
    int? MaxDepth) : Signature(Name, SignatureType.Metadata, SourceFile);

public sealed record CdbSignature(
    string Name,
    string SourceFile,
    string ContainerType,
    PosixEreRegex? FileNameRegex,
    MetadataRange? ContainerSize,
    MetadataRange? FileSizeInContainer,
    MetadataRange? FileSizeReal,
    int Encrypted,
    MetadataRange? FilePosition,
    string? Res2) : Signature(Name, SignatureType.Metadata, SourceFile);

public sealed record ContentSignature(
    string Name,
    SignatureType Type,
    string SourceFile,
    HexPattern Pattern,
    string OffsetExpression = "*",
    ContentMatchOptions MatchOptions = ContentMatchOptions.None) : Signature(Name, Type, SourceFile);

public sealed record NdbSignature(
    string Name,
    string SourceFile,
    int Target,
    string OffsetExpression,
    HexPattern Pattern,
    int? MinimumFunctionalityLevel = null,
    int? MaximumFunctionalityLevel = null,
    int? MacroGroup = null,
    bool IsSelfProtection = false) : Signature(Name, SignatureType.Ndb, SourceFile);

public sealed record LdbTargetDescription(
    int Target = 0,
    long? MinFileSize = null,
    long? MaxFileSize = null,
    long? MinEntryPoint = null,
    long? MaxEntryPoint = null,
    int? MinSections = null,
    int? MaxSections = null,
    string? Container = null,
    IReadOnlyList<string>? Intermediates = null,
    string? HandlerType = null,
    string? IconGroup1 = null,
    string? IconGroup2 = null,
    int? MinimumFunctionalityLevel = null,
    int? MaximumFunctionalityLevel = null,
    bool TargetSpecified = false);

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

public sealed record ByteCompareComparison(char Operator, long Value);

public sealed record LdbRegexSubSignature(
    int Index,
    string Trigger,
    string Pattern,
    string Flags,
    string OffsetExpression);

public sealed record LdbByteCompareSubSignature(
    int Index,
    int ReferenceSubSignature,
    int Shift,
    ByteCompareOptions Options,
    int ByteLength,
    IReadOnlyList<ByteCompareComparison> Comparisons);

public sealed record LdbFuzzyImageSubSignature(
    int Index,
    byte[] Hash,
    uint HammingDistance);

public sealed record LogicalSignature(
    string Name,
    string SourceFile,
    string TargetDescription,
    string Expression,
    IReadOnlyList<ContentSignature> SubSignatures,
    LdbTargetDescription? Target = null,
    IReadOnlyDictionary<int, (int MinDistance, int MaxDistance, int MacroGroup)>? MacroSubSignatures = null,
    IReadOnlyDictionary<int, LdbRegexSubSignature>? RegexSubSignatures = null,
    IReadOnlyDictionary<int, LdbByteCompareSubSignature>? ByteCompareSubSignatures = null,
    IReadOnlyDictionary<int, LdbFuzzyImageSubSignature>? FuzzyImageSubSignatures = null) : Signature(Name, SignatureType.Logical, SourceFile);
