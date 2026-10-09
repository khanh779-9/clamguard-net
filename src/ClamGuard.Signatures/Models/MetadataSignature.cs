using ClamGuard.Core;
namespace ClamGuard.Signatures;

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
