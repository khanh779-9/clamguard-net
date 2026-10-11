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

/// <summary>
/// ClamAV target type specification for NDB and LDB signatures.
/// </summary>
public enum SignatureTargetType
{
    Any = 0,
    Pe = 1,
    Ole2 = 2,
    Html = 3,
    Mail = 4,
    Graphics = 5,
    Elf = 6,
    Ascii = 7,
    Unused8 = 8,
    MachO = 9,
    Pdf = 10,
    Flash = 11,
    Java = 12,
    Internal = 13,
    Other = 14
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
    /// <summary>Maximum size for one input/embedded file, in bytes.</summary>
    public long MaxFileSize { get; set; } = 1L << 30;
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
    public int MaxArchiveDepth { get; init; } = 17;

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
        // Recover invalid/stale per-file limits rather than aborting every scan. The native
        // compatible ceiling is 2 GiB; the regular default remains 1 GiB at this low layer.
        if (MaxFileSize <= 0) MaxFileSize = 1L << 30;
        else if (MaxFileSize > (2L << 30)) MaxFileSize = 2L << 30;
        if (MaxFullBufferSize <= 0 || MaxFullBufferSize > MaxFileSize) throw new ArgumentOutOfRangeException(nameof(MaxFullBufferSize));
        if (MaxPatternMatchesPerSignature is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxPatternMatchesPerSignature));
        if (MaxLogicalDepth is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(MaxLogicalDepth));
        if (StreamChunkSize is < 4096 or > 64 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(StreamChunkSize));
        if (MaxFlexibleLookbehind is < 1024 or > 128 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(MaxFlexibleLookbehind));
        if (MaxArchiveEntries is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxArchiveEntries));
        if (MaxArchiveDepth is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(MaxArchiveDepth));
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
    /// <summary>Return all matching signatures. When false, the engine still checks past PUA/heuristic-only matches.</summary>
    public bool CollectAllMatches { get; init; }
    public ScanLimits Limits { get; init; } = new();
    public string? YaraRuleDirectory { get; init; }
    public string? BytecodeDirectory { get; init; }
    public List<IContentScanner> ContentScanners { get; } = [];

    // Parser capabilities mirror the independent CL_SCAN_PARSE_* bits in
    // libclamav/clamav.h (ClamAV 1.5.4). A disabled parser skips only its
    // format-specific expansion/inspection; raw-byte signature matching remains on.
    public bool ScanArchive { get; set; } = true; // CL_SCAN_PARSE_ARCHIVE
    public bool ScanELF { get; set; } = true;     // CL_SCAN_PARSE_ELF
    public bool ScanPDF { get; set; } = true;     // CL_SCAN_PARSE_PDF
    public bool ScanSWF { get; set; } = true;     // CL_SCAN_PARSE_SWF
    public bool ScanHWP3 { get; set; } = true;    // CL_SCAN_PARSE_HWP3
    public bool ScanXMLDocs { get; set; } = true; // CL_SCAN_PARSE_XMLDOCS
    public bool ScanMail { get; set; } = true;    // CL_SCAN_PARSE_MAIL
    public bool ScanOLE2 { get; set; } = true;    // CL_SCAN_PARSE_OLE2
    public bool ScanHTML { get; set; } = true;    // CL_SCAN_PARSE_HTML
    public bool ScanPE { get; set; } = true;      // CL_SCAN_PARSE_PE
    public bool ScanOneNote { get; set; } = true; // CL_SCAN_PARSE_ONENOTE
    public bool ScanImage { get; set; } = true;   // CL_SCAN_PARSE_IMAGE
    public bool ScanImageFuzzyHash { get; set; } = true; // CL_SCAN_PARSE_IMAGE_FUZZY_HASH

    // Native-style general / heuristic switches. The managed scanner currently
    // implements only the heuristic types listed below; unsupported native
    // heuristics are deliberately not exposed as no-op booleans.
    public bool EnableHeuristics { get; set; } = true; // CL_SCAN_GENERAL_HEURISTICS
    public bool HeuristicPrecedence { get; set; }      // CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE
    public bool HeuristicExceedsMax { get; set; } = true; // CL_SCAN_HEURISTIC_EXCEEDS_MAX
    public bool HeuristicEncryptedArchive { get; set; }   // CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE
    public bool HeuristicEncryptedDoc { get; set; }       // CL_SCAN_HEURISTIC_ENCRYPTED_DOC

    /// <summary>Legacy compatibility alias: enables/disables all managed heuristic alerts.</summary>
    public bool HeuristicScan { get => EnableHeuristics; set => EnableHeuristics = value; }

    /// <summary>Legacy compatibility alias for the two native encrypted-content heuristic flags.</summary>
    public bool BlockEncrypted
    {
        get => HeuristicEncryptedArchive || HeuristicEncryptedDoc;
        set { HeuristicEncryptedArchive = value; HeuristicEncryptedDoc = value; }
    }

    public const long DefaultMaxFileSize = 100L * 1024 * 1024;
    public const long DefaultMaxScanSize = 400L * 1024 * 1024;
    public const long MaximumSupportedFileSize = 2L << 30;

    /// <summary>Maximum individual file size in bytes. Use long to avoid 2 GiB int overflow.</summary>
    public long MaxFileSize { get; set; } = DefaultMaxFileSize;

    /// <summary>Maximum aggregate size in bytes considered for nested/container scanning.</summary>
    public long MaxScanSize { get; set; } = DefaultMaxScanSize;
    public int MaxFiles { get; set; } = 10_000;
    public int MaxRecursion { get; set; } = 17;

    /// <summary>PUA signatures are opt-in, matching ClamAV's default behaviour. This is database configuration, not a cl_scan_options parse bit.</summary>
    public bool DetectPUA { get; set; }

    public bool UseMultithreading { get; set; } = true;
    public int MaxThreads { get; set; } = Math.Max(1, Environment.ProcessorCount);

    public bool Verbose { get; set; }
    public bool ShowProgress { get; set; } = true;
    public bool InfectedOnly { get; set; }

    public bool Recursive { get; set; } = true;
    public bool FollowSymlinks { get; set; }
    public List<string> ExcludeDirectories { get; set; } = [];
    public List<string> ExcludeExtensions { get; set; } = [];

    public static ScanOptions Default => new();

    /// <summary>
    /// Normalize user-facing size limits to safe defaults/bounds, then validate the
    /// lower-level parser settings and all other public scan options.
    /// </summary>
    public void Validate()
    {
        NormalizePublicSizeLimits();
        Limits.Validate();
        if (MaxFiles < 1 || MaxFiles > 1_000_000) throw new ArgumentOutOfRangeException(nameof(MaxFiles));
        if (MaxRecursion < 1 || MaxRecursion > 100) throw new ArgumentOutOfRangeException(nameof(MaxRecursion));
        if (MaxThreads < 1 || MaxThreads > 1024) throw new ArgumentOutOfRangeException(nameof(MaxThreads));
        if (ExcludeDirectories.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Excluded directory entries must not be empty.", nameof(ExcludeDirectories));
        if (ExcludeExtensions.Any(string.IsNullOrWhiteSpace)) throw new ArgumentException("Excluded extensions must not be empty.", nameof(ExcludeExtensions));
    }

    /// <summary>
    /// Recovers from invalid public byte limits before a scan starts. This is intentionally
    /// separate from ScanLimits.Validate(): low-level parser limits remain strict, while the
    /// user-facing limits cannot abort an otherwise valid scan because of an int overflow or
    /// a stale/zero value supplied by a caller.
    /// </summary>
    private void NormalizePublicSizeLimits()
    {
        if (MaxFileSize <= 0)
            MaxFileSize = DefaultMaxFileSize;
        else if (MaxFileSize > MaximumSupportedFileSize)
            MaxFileSize = MaximumSupportedFileSize;

        if (MaxScanSize <= 0)
            MaxScanSize = DefaultMaxScanSize;
    }

    /// <summary>
    /// Merge the public ClamAV-style limits with the safer lower-level limits.
    /// Both sets remain effective: the smaller configured ceiling always wins.
    /// </summary>
    public ScanLimits CreateEffectiveLimits()
    {
        var fileLimit = Math.Min(Limits.MaxFileSize, (long)MaxFileSize);
        var htmlLimit = Math.Min(Limits.MaxHtmlNormalize, fileLimit);
        return new ScanLimits
        {
            MaxFileSize = fileLimit,
            MaxFullBufferSize = Math.Min(Limits.MaxFullBufferSize, fileLimit),
            MaxPatternMatchesPerSignature = Limits.MaxPatternMatchesPerSignature,
            MaxLogicalDepth = Limits.MaxLogicalDepth,
            StreamChunkSize = Limits.StreamChunkSize,
            MaxFlexibleLookbehind = Limits.MaxFlexibleLookbehind,
            MaxArchiveEntries = Math.Min(Limits.MaxArchiveEntries, MaxFiles),
            MaxArchiveDepth = Math.Min(Limits.MaxArchiveDepth, MaxRecursion),
            MaxArchiveExpandedBytes = Math.Min(Limits.MaxArchiveExpandedBytes, Math.Min((long)MaxScanSize, fileLimit * 16)),
            MaxArchiveCompressionRatio = Limits.MaxArchiveCompressionRatio,
            MaxEmbeddedStreamSize = Math.Min(Limits.MaxEmbeddedStreamSize, fileLimit),
            MaxHtmlNormalize = htmlLimit,
            MaxHtmlNoTags = Math.Min(Limits.MaxHtmlNoTags, htmlLimit),
            MaxScriptNormalize = Math.Min(Limits.MaxScriptNormalize, fileLimit),
            MaxArchiveDecodeTime = Limits.MaxArchiveDecodeTime
        };
    }

    public bool IsExcludedExtension(string path)
    {
        var extension = Path.GetExtension(path);
        if (string.IsNullOrEmpty(extension)) return false;
        return ExcludeExtensions.Any(x => string.Equals(
            x.StartsWith('.') ? x : "." + x,
            extension,
            StringComparison.OrdinalIgnoreCase));
    }

    public bool IsExcludedDirectory(string path, string rootDirectory)
    {
        var fullPath = NormalizeDirectoryPath(path);
        var root = NormalizeDirectoryPath(rootDirectory);
        foreach (var excluded in ExcludeDirectories)
        {
            var value = excluded.Trim();
            if (value.Length == 0) continue;

            if (Path.IsPathRooted(value))
            {
                var excludedPath = NormalizeDirectoryPath(value);
                if (IsSameOrChildPath(fullPath, excludedPath)) return true;
            }
            else
            {
                // Relative entries match a directory name at any depth (not a substring).
                var segments = Path.GetRelativePath(root, fullPath)
                    .Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
                if (segments.Any(segment => string.Equals(segment, value, StringComparison.OrdinalIgnoreCase))) return true;
            }
        }
        return false;
    }

    private static string NormalizeDirectoryPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var pathRoot = Path.GetPathRoot(fullPath);
        if (!string.IsNullOrEmpty(pathRoot) && string.Equals(fullPath, pathRoot,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            return pathRoot;
        return fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static bool IsSameOrChildPath(string path, string parent)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(path, parent, comparison)) return true;
        var prefix = parent.EndsWith(Path.DirectorySeparatorChar) || parent.EndsWith(Path.AltDirectorySeparatorChar)
            ? parent
            : parent + Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, comparison);
    }

    public static bool IsPuaName(string? name)
        => name?.StartsWith("PUA.", StringComparison.OrdinalIgnoreCase) == true;

    public bool IsDetectionEnabled(Detection detection)
        => (DetectPUA || !IsPuaName(detection.Name)) &&
           (EnableHeuristics || !IsHeuristicName(detection.Name));

    public static bool IsHeuristicName(string? name)
        => name?.StartsWith("Heuristics.", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// PUA and heuristic-only matches are lower priority than ordinary malware
    /// signatures. This preserves the native scanner's non-heuristic precedence
    /// and prevents a hidden PUA from masking a later malware match.
    /// </summary>
    public bool HasBlockingDetections(IEnumerable<Detection> detections)
        => detections.Any(detection => IsDetectionEnabled(detection) &&
            !IsPuaName(detection.Name) &&
            (!IsHeuristicName(detection.Name) || HeuristicPrecedence));

    public IReadOnlyList<Detection> FilterDetections(IEnumerable<Detection> detections)
    {
        var visible = detections
            .Where(IsDetectionEnabled)
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .ToArray();
        if (CollectAllMatches || visible.Length <= 1) return visible;
        // CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE lets heuristic alerts win; the
        // default managed policy otherwise prioritizes concrete malware matches.
        if (HeuristicPrecedence)
        {
            var primaryHeuristic = visible.FirstOrDefault(x => IsHeuristicName(x.Name));
            if (primaryHeuristic is not null) return [primaryHeuristic];
        }
        var primary = visible.FirstOrDefault(x => !IsPuaName(x.Name) && !IsHeuristicName(x.Name))
                      ?? visible.FirstOrDefault(x => !IsHeuristicName(x.Name))
                      ?? visible[0];
        return [primary];
    }
}

public sealed class UpdateOptions
{
    public Uri BaseUri { get; init; } = new("https://database.clamav.net/");
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(60);
    public int MaxAttempts { get; init; } = 2;
    /// <summary>Optional ClamAV certificate directory for detached .cvd.sign verification.</summary>
    public string? CertsDirectory { get; init; }
}
