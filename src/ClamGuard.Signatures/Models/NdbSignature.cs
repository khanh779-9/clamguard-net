using ClamGuard.Core;
using ClamGuard.Signatures.Patterns;
namespace ClamGuard.Signatures;

public sealed record NdbSignature(
    string Name,
    string SourceFile,
    SignatureTargetType Target,
    string OffsetExpression,
    HexPattern Pattern,
    int? MinimumFunctionalityLevel = null,
    int? MaximumFunctionalityLevel = null,
    int? MacroGroup = null,
    bool IsSelfProtection = false) : Signature(Name, SignatureType.Ndb, SourceFile)
{
    public SignatureTargetType TargetType => Target;
}
