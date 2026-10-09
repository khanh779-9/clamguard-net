using ClamGuard.Core;
using ClamGuard.Signatures.Patterns;
namespace ClamGuard.Signatures;

public sealed record ContentSignature(
    string Name,
    SignatureType Type,
    string SourceFile,
    HexPattern Pattern,
    string OffsetExpression = "*",
    ContentMatchOptions MatchOptions = ContentMatchOptions.None) : Signature(Name, Type, SourceFile);
