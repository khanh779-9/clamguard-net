using ClamGuard.Core;
namespace ClamGuard.Signatures;

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
