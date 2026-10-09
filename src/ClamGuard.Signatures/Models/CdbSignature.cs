using ClamGuard.Core;
namespace ClamGuard.Signatures;

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
