namespace ClamGuard.Bytecode;

public enum ClamBcKind
{
    Generic = 0,
    Startup = 1,
    Logical = 256,
    PeUnpacker = 257,
    Pdf = 258,
    PeAll = 259,
    Preclass = 260,
    ElfUnpacker = 261,
    MachOUnpacker = 262
}

public sealed record BytecodeMetadata(
    int FormatLevel,
    ulong Timestamp,
    string SignatureMaker,
    int TargetExclude,
    ClamBcKind Kind,
    int MinimumFunctionality,
    int MaximumFunctionality,
    int MaximumResource,
    string Compiler,
    string? LogicSignature,
    string DefaultName);

public sealed record BytecodeMatch(
    string Name,
    string RuleFile,
    long? Offset,
    long ReturnValue,
    string? Detail = null);

public sealed class BytecodeScanOptions
{
    public int EngineFunctionalityLevel { get; init; } = 234;
    public int MaxRules { get; init; } = 4096;
    public long MaxInstructions { get; init; } = 1_000_000;
    public int MaxCallDepth { get; init; } = 32;
    public int MaxAllocatedBytesPerRule { get; init; } = 64 * 1024 * 1024;
    public int MaxExtractedBytes { get; init; } = 32 * 1024 * 1024;
    public int MaxBufferBytes { get; init; } = 16 * 1024 * 1024;
    public int MaxPointerViewBytes { get; init; } = 16 * 1024;
    public int MaxApiObjects { get; init; } = 1024;
    public int MaxMapValueBytes { get; init; } = 1024 * 1024;
    public TimeSpan MaxRuntime { get; init; } = TimeSpan.FromSeconds(5);
    public uint EngineScanOptions { get; init; }
    public uint EngineDatabaseOptions { get; init; }
    public uint EngineScanOptionsEx { get; init; }
}
