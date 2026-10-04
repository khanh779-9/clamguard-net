namespace ClamGuard.Core;

public enum SignatureType
{
    Hash,
    Content,
    Ndb,
    Logical,
    Regex,
    ByteComparison,
    Yara,
    Bytecode,
    Metadata,
    Trust,
    Ignore
}

public enum HashAlgorithmKind
{
    Md5,
    Sha1,
    Sha256
}

public enum ScanVerdict
{
    Clean,
    Malicious,
    PotentiallyUnwanted,
    StrongIndicator,
    Trusted,
    Error,
    Timeout
}

public enum DatabaseFormat
{
    Unknown,
    Cvd,
    Cld,
    Cud,
    TextSignature
}

public sealed record DatabaseInfo(
    string Name,
    DatabaseFormat Format,
    uint Version,
    uint SignatureCount,
    uint FunctionalityLevel,
    DateTimeOffset? CreatedAt,
    string? Builder,
    string? Md5,
    bool IsVerified);

public sealed record Detection(
    string Name,
    SignatureType Type,
    long? Offset,
    string DatabaseFile,
    string? Detail = null);

public sealed record ScanResult(
    ScanVerdict Verdict,
    string FilePath,
    string? FileType,
    IReadOnlyList<Detection> Detections,
    long BytesScanned,
    TimeSpan Duration,
    DatabaseInfo? Database);

public sealed class ScanLimits
{
    public long MaxFileSize { get; init; } = 1L << 30;
    /// <summary>Maximum file size allowed when a feature requires full materialization instead of streaming.</summary>
    public long MaxFullBufferSize { get; init; } = 256L << 20;
    public int MaxPatternMatchesPerSignature { get; init; } = 256;
    public int MaxLogicalDepth { get; init; } = 32;

    /// <summary>Read size used by file streaming scans.</summary>
    public int StreamChunkSize { get; init; } = 1024 * 1024;

    /// <summary>Maximum retained suffix for non-fixed patterns during streaming.</summary>
    public int MaxFlexibleLookbehind { get; init; } = 1024 * 1024;

    /// <summary>Maximum number of entries/files expanded from one container tree.</summary>
    public int MaxArchiveEntries { get; init; } = 10000;

    /// <summary>Maximum nested-container depth, including the root container.</summary>
    public int MaxArchiveDepth { get; init; } = 16;

    /// <summary>Maximum aggregate uncompressed bytes materialized from a container tree.</summary>
    public long MaxArchiveExpandedBytes { get; init; } = 1L << 31;

    /// <summary>Reject compressed members whose declared expansion exceeds this ratio when the compressed size is non-zero.</summary>
    public int MaxArchiveCompressionRatio { get; init; } = 1000;

    /// <summary>Maximum bytes materialized from a single embedded PDF stream.</summary>
    public long MaxEmbeddedStreamSize { get; init; } = 256L << 20;

    /// <summary>Maximum HTML input size eligible for ClamAV-style normalization.</summary>
    public long MaxHtmlNormalize { get; init; } = 40L << 20;

    /// <summary>Maximum post-normalization HTML size scanned in no-tags form.</summary>
    public long MaxHtmlNoTags { get; init; } = 8L << 20;

    /// <summary>Maximum script content size eligible for normalization.</summary>
    public long MaxScriptNormalize { get; init; } = 20L << 20;

    /// <summary>Maximum wall-clock time allowed for optional external archive codecs.</summary>
    public TimeSpan MaxArchiveDecodeTime { get; init; } = TimeSpan.FromSeconds(15);

    public void Validate()
    {
        if (MaxFileSize <= 0) throw new ArgumentOutOfRangeException(nameof(MaxFileSize));
        if (MaxFullBufferSize <= 0 || MaxFullBufferSize > MaxFileSize) throw new ArgumentOutOfRangeException(nameof(MaxFullBufferSize));
        if (MaxPatternMatchesPerSignature is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxPatternMatchesPerSignature));
        if (MaxLogicalDepth is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(MaxLogicalDepth));
        if (StreamChunkSize is < 4096 or > 64 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(StreamChunkSize));
        if (MaxFlexibleLookbehind is < 1024 or > 128 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(MaxFlexibleLookbehind));
        if (MaxArchiveEntries is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxArchiveEntries));
        if (MaxArchiveDepth is < 1 or > 128) throw new ArgumentOutOfRangeException(nameof(MaxArchiveDepth));
        if (MaxArchiveExpandedBytes <= 0 || MaxArchiveExpandedBytes > MaxFileSize * 16) throw new ArgumentOutOfRangeException(nameof(MaxArchiveExpandedBytes));
        if (MaxArchiveCompressionRatio is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxArchiveCompressionRatio));
        if (MaxEmbeddedStreamSize <= 0 || MaxEmbeddedStreamSize > MaxFileSize) throw new ArgumentOutOfRangeException(nameof(MaxEmbeddedStreamSize));
        if (MaxHtmlNormalize <= 0 || MaxHtmlNormalize > MaxFileSize) throw new ArgumentOutOfRangeException(nameof(MaxHtmlNormalize));
        if (MaxHtmlNoTags <= 0 || MaxHtmlNoTags > MaxHtmlNormalize) throw new ArgumentOutOfRangeException(nameof(MaxHtmlNoTags));
        if (MaxScriptNormalize <= 0 || MaxScriptNormalize > MaxFileSize) throw new ArgumentOutOfRangeException(nameof(MaxScriptNormalize));
        if (MaxArchiveDecodeTime <= TimeSpan.Zero || MaxArchiveDecodeTime > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(MaxArchiveDecodeTime));
    }
}

public interface IContentScanner
{
    IReadOnlyList<Detection> Scan(ReadOnlySpan<byte> data, string path, CancellationToken cancellationToken = default);
}

public sealed class ScanOptions
{
    public bool CollectAllMatches { get; init; }
    public ScanLimits Limits { get; init; } = new();
    public string? YaraRuleDirectory { get; init; }
    public string? BytecodeDirectory { get; init; }
    public List<IContentScanner> ContentScanners { get; } = [];
}

public sealed class UpdateOptions
{
    public Uri BaseUri { get; init; } = new("https://database.clamav.net/");
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(60);
    public int MaxAttempts { get; init; } = 2;
    /// <summary>Optional ClamAV certificate directory for detached .cvd.sign verification.</summary>
    public string? CertsDirectory { get; init; }
}
