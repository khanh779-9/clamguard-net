using ClamGuard.Core;
namespace ClamGuard.Signatures;

public sealed record HashSignature(
    string Name,
    SignatureType Type,
    string SourceFile,
    HashAlgorithmKind Algorithm,
    byte[] Hash,
    long? FileSize) : Signature(Name, Type, SourceFile);
