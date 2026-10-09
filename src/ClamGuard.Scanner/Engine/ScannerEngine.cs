using System.Diagnostics;
using System.Buffers;
using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Database.Storage;
using ClamGuard.Signatures;
using ClamGuard.Signatures.Matching;
using ClamGuard.Signatures.Patterns;
using ClamGuard.Yara;
using ClamGuard.Bytecode;

namespace ClamGuard.Scanner;

public sealed partial class ScannerEngine
{
    private readonly DatabaseManager _databaseManager;
    private readonly ConcurrentDictionary<string, Lazy<IContentScanner>> _optionalScannerCache = new(StringComparer.OrdinalIgnoreCase);

    public ScannerEngine(DatabaseManager databaseManager) => _databaseManager = databaseManager;

    public ScanResult Scan(string path, ScanOptions? options = null)
        => ScanAsync(path, options).GetAwaiter().GetResult();

    public async Task<ScanResult> ScanAsync(string path, ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new ScanOptions();
        options.Validate();
        options = CreateEffectiveOptions(options);
        options.Limits.Validate();
        var started = Stopwatch.StartNew();
        if (options.Verbose) Trace.WriteLine($"[ClamGuard] Scan started: {path}");
        if (!File.Exists(path))
            return new ScanResult(ScanVerdict.Error, path, null, [], 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());

        var info = new FileInfo(path);
        if (info.Length > options.Limits.MaxFileSize)
        {
            var detections = options.EnableHeuristics && options.HeuristicExceedsMax
                ? new[] { new Detection("Heuristics.Limits.Exceeded", SignatureType.Metadata, null, "scan-options", $"File size {info.Length} exceeds the configured maximum {options.Limits.MaxFileSize} bytes.") }
                : Array.Empty<Detection>();
            return new ScanResult(detections.Length == 0 ? ScanVerdict.Error : ScanVerdict.StrongIndicator, path, DetectType(path), detections, 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());
        }

        try
        {
            var state = _databaseManager.Current;
            if (info.Length == 0)
                return new ScanResult(ScanVerdict.Clean, path, DetectType(path), [], 0, started.Elapsed, state.Database.Databases.FirstOrDefault());

            var ndbSignatures = state.Database.Signatures.OfType<NdbSignature>().ToArray();
            var logicalSignatures = state.Database.Signatures.OfType<LogicalSignature>().ToArray();
            var peSectionRules = state.Database.Signatures.OfType<HashSignature>()
                .Where(x => PeSpecializedMatcher.IsSectionHash(x.SourceFile))
                .ToArray();
            var peImportRules = state.Database.Signatures.OfType<HashSignature>()
                .Where(x => PeSpecializedMatcher.IsImportHash(x.SourceFile))
                .ToArray();

            // Container signatures such as ISO/UDF can be located well beyond the
            // first few KiB. Probe enough of the front of the file to classify them
            // before deciding whether full-buffer/container expansion is required.
            // ClamAV cli_determine_fmap_type() uses MAGIC_BUFFER_SIZE (1028 bytes)
            // for the initial file-type probe. Keep our fast path at the same scale;
            // formats with out-of-band markers are handled by targeted reads below.
            var probeLength = (int)Math.Min(1028L, info.Length);
            var probe = new byte[probeLength];
            await using (var probeStream = File.OpenRead(path))
            {
                var readProbe = 0;
                while (readProbe < probe.Length)
                {
                    var read = await probeStream.ReadAsync(probe.AsMemory(readProbe), cancellationToken);
                    if (read == 0) break;
                    readProbe += read;
                }
                if (readProbe != probe.Length)
                    probe = probe[..readProbe];
            }
            var rootType = DetectType(probe, path, state.Database.SpecialDatabases.FileTypes);

            // .sdb rules are NDB-family rules marked as self-protection. ClamAV's
            // self-protection scan runs against the raw layer before type-specific
            // parsing. Our streaming NDB path now includes stream-safe SDB rules,
            // while non-streamable rules are evaluated in the normal full-data path.
            // This avoids forcing every file into a whole-file RAM buffer merely
            // because an SDB database is loaded.

            // DMG stores the UDIF "koly" marker in a 512-byte trailer. Read that
            // trailer separately so extensionless/non-standardly named disk images
            // still enter the container-expansion path.
            // ISO9660 uses the CD001 descriptor at sector 16 (offset 32769).
            // ClamAV performs this as a targeted type-detection check rather than
            // inflating the initial magic buffer.
            if (rootType == "Unknown" && info.Length >= 32774)
            {
                var isoProbe = new byte[5];
                await using var isoStream = File.OpenRead(path);
                isoStream.Position = 32769;
                var readIso = 0;
                while (readIso < isoProbe.Length)
                {
                    var read = await isoStream.ReadAsync(isoProbe.AsMemory(readIso), cancellationToken);
                    if (read == 0) break;
                    readIso += read;
                }
                if (readIso == isoProbe.Length && isoProbe.AsSpan().SequenceEqual("CD001"u8))
                    rootType = "ISO";
            }

            if (rootType == "Unknown" && info.Length >= 32773)
            {
                // UDF's primary implementation descriptor can be outside the
                // 1028-byte magic window. ClamAV uses the file map for this, so
                // keep the managed fast path targeted rather than reading the file.
                var udfProbe = new byte[5];
                await using var udfStream = File.OpenRead(path);
                udfStream.Position = 32768;
                var readUdf = 0;
                while (readUdf < udfProbe.Length)
                {
                    var read = await udfStream.ReadAsync(udfProbe.AsMemory(readUdf), cancellationToken);
                    if (read == 0) break;
                    readUdf += read;
                }
                if (readUdf == udfProbe.Length && udfProbe.AsSpan().SequenceEqual("BEA01"u8))
                    rootType = "UDF";
            }

            if (rootType == "Unknown" && info.Length >= 512)
            {
                var tail = new byte[512];
                await using var tailStream = File.OpenRead(path);
                tailStream.Position = info.Length - tail.Length;
                var readTail = 0;
                while (readTail < tail.Length)
                {
                    var read = await tailStream.ReadAsync(tail.AsMemory(readTail), cancellationToken);
                    if (read == 0) break;
                    readTail += read;
                }
                if (readTail == tail.Length && ArchiveScanner.LooksLikeDmg(tail))
                    rootType = "DMG";
            }

            var signatureFileType = rootType.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ? "OTHER" : rootType;
            var applicableRawNdb = ndbSignatures
                .Where(x => x.MacroGroup is null && LdbRuntime.TargetMatchesFileType(x.Target, signatureFileType))
                .ToArray();
            var streamableNdb = applicableRawNdb.Where(x => ScanTypePolicy.CanStreamRawNdb(x, signatureFileType)).ToHashSet();
            var fixedNdbCandidateRules = applicableRawNdb
                .Where(x => !streamableNdb.Contains(x) &&
                            x.Pattern.IsFixed &&
                            !ScanTypePolicy.IsNormalizedTarget(x.Target))
                .ToHashSet();
            var matchedFixedNdbCandidates = new HashSet<NdbSignature>();
            // Only an applicable, non-streamable NDB rule can require the expensive
            // second pass. Macro NDB entries are logical-signature ingredients and are
            // already covered when logical signatures are evaluated.
            var requiresFullNdbEvaluation = applicableRawNdb.Any(x => !streamableNdb.Contains(x));
            var requiresContainerExpansion = ScanTypePolicy.IsArchiveContainer(rootType) &&
                                             ScanTypePolicy.ShouldParseContainer(rootType, options);
            var requiresMachOFat = ScanTypePolicy.IsMachO(rootType) && ScanTypePolicy.LooksLikeMachOFat(probe);
            var requiresSpecializedPreRaw = ScanTypePolicy.ShouldRunSpecializedPreRaw(rootType, options) &&
                                            (!(rootType.Equals("HTML", StringComparison.OrdinalIgnoreCase) ||
                                               rootType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase)) ||
                                             info.Length <= options.Limits.MaxHtmlNormalize);

            // ClamAV runs container/document parsers before the ordinary raw scan for
            // these types. Because our managed archive layer needs a materialized span,
            // load it once, scan the container first, and reuse the same bytes for the
            // raw matcher and later target-specific passes. PE/ELF/Mach-O keep the raw-
            // first path, matching cli_magic_scan()'s executable ordering.
            var requiresPeFullBuffer = options.ScanPE && peImportRules.Length != 0 && ScanTypePolicy.IsPe(rootType);
            var requiresLogicalFullBuffer = HasApplicableLogicalSignatures(
                logicalSignatures,
                signatureFileType,
                info.Length);
            var needsFullBuffer = requiresLogicalFullBuffer || requiresFullNdbEvaluation ||
                                  requiresPeFullBuffer || requiresContainerExpansion ||
                                  requiresMachOFat || requiresSpecializedPreRaw ||
                                  options.ContentScanners.Count != 0;
            // A feature requiring materialization must not stop the raw signature pass
            // merely because its buffer budget is exhausted. Continue streaming the
            // original object and report that secondary inspection was incomplete.
            var fullBufferLimitExceeded = needsFullBuffer && info.Length > options.Limits.MaxFullBufferSize;
            if (fullBufferLimitExceeded) needsFullBuffer = false;

            byte[]? fullData = null;
            var containerPreScanned = false;
            var detections = new List<Detection>();
            if (fullBufferLimitExceeded && options.EnableHeuristics && options.HeuristicExceedsMax)
            {
                detections.Add(new Detection(
                    "Heuristics.Limits.Exceeded",
                    SignatureType.Metadata,
                    null,
                    "scan-options",
                    $"File size {info.Length} exceeds the materialization limit {options.Limits.MaxFullBufferSize}; raw signature scanning continues, but one or more secondary scan stages were skipped."));
            }

            // If a whole-file buffer is already needed for subsequent operations, read it once upfront
            // to avoid reading the file twice from disk.
            if (needsFullBuffer)
            {
                fullData = await ReadFullFileAsync(path, info.Length, cancellationToken);
            }

            if (requiresContainerExpansion && fullData is not null)
            {
                var fullRootType = DetectType(fullData!, path, state.Database.SpecialDatabases.FileTypes);
                if (!string.Equals(rootType, fullRootType, StringComparison.OrdinalIgnoreCase))
                {
                    rootType = fullRootType;
                    signatureFileType = rootType.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ? "OTHER" : rootType;
                }
                requiresMachOFat = ScanTypePolicy.IsMachO(rootType) && ScanTypePolicy.LooksLikeMachOFat(fullData!);

                if (state.Compiled.MatchesFalsePositive(fullData!))
                    return new ScanResult(ScanVerdict.Trusted, path, rootType, [], info.Length, started.Elapsed, state.Database.Databases.FirstOrDefault());

                detections.AddRange(ArchiveScanner.Scan(fullData!, path, state, options, [], 0, cancellationToken, rootType));
                containerPreScanned = true;
                if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                    return CreateDetectionResult(path, rootType, detections, info.Length, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
            }

            if (requiresSpecializedPreRaw && fullData is not null)
            {
                detections.AddRange(SpecializedFileHandlers.ScanPreRaw(
                    fullData!, rootType, state, options, path, cancellationToken));
                if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                    return CreateDetectionResult(path, rootType, detections, info.Length, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
            }

            (IReadOnlyList<Detection> Detections, bool Trusted, long BytesRead) rawMatch;
            if (fullData is not null)
            {
                // The bytes are already in RAM. Re-reading them through a second disk stream / memory map
                // adds 100% duplicate I/O. Use fast in-memory compiled match directly.
                var useCombinedNdbIndex = !containerPreScanned &&
                    (streamableNdb.Count != 0 || fixedNdbCandidateRules.Count != 0);
                rawMatch = (state.Compiled.Match(
                    fullData,
                    "compiled-database",
                    includeNdb: useCombinedNdbIndex,
                    collectAllMatches: (options.CollectAllMatches || !options.DetectPUA),
                    ndbFilter: useCombinedNdbIndex ? streamableNdb.Contains : null,
                    ndbPatternCandidates: containerPreScanned ? null : matchedFixedNdbCandidates,
                    ndbCandidateFilter: containerPreScanned ? null : fixedNdbCandidateRules.Contains),
                    state.Compiled.MatchesFalsePositive(fullData),
                    info.Length);
            }
            else
            {
                using var mapped = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
                await using var input = mapped.CreateViewStream(0, info.Length, MemoryMappedFileAccess.Read);
                rawMatch = await state.Compiled.MatchStreamAsync(
                    input,
                    options.Limits.StreamChunkSize,
                    options.Limits.MaxFlexibleLookbehind,
                    "compiled-database",
                    cancellationToken,
                    includeNdb: streamableNdb.Count != 0,
                    collectAllMatches: (options.CollectAllMatches || !options.DetectPUA),
                    ndbFilter: streamableNdb.Count == 0 ? null : streamableNdb.Contains);
            }

            if (rawMatch.Trusted)
            {
                // .fp/.sfp matched the root layer. ClamAV converts this to CL_VERIFIED,
                // clears prior evidence, and skips child/container scanning.
                return new ScanResult(ScanVerdict.Trusted, path, rootType, [], rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
            }

            detections.AddRange(rawMatch.Detections);
            if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);

            var specializedRules = options.ScanPE && (peSectionRules.Length != 0 || peImportRules.Length != 0);
            // PE section hashes are streamed section-by-section. Import hashes still
            // require a structurally complete PE image, so only .imp forces a whole
            // file materialization here.
            if (needsFullBuffer)
            {
                if (fullData is null)
                    fullData = await ReadFullFileAsync(path, info.Length, cancellationToken);

                var logicalType = DetectType(fullData, path, state.Database.SpecialDatabases.FileTypes);
                signatureFileType = logicalType.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
                    ? "OTHER"
                    : logicalType;

                if (logicalSignatures.Length != 0 || ndbSignatures.Length != 0)
                {
                    IEnumerable<NdbSignature> materializedNdb = ndbSignatures
                        .Where(x => x.MacroGroup is null &&
                                    LdbRuntime.TargetMatchesFileType(x.Target, signatureFileType));
                    if (!containerPreScanned)
                    {
                        materializedNdb = materializedNdb.Where(x =>
                            !streamableNdb.Contains(x) &&
                            (!x.Pattern.IsFixed ||
                             ScanTypePolicy.IsNormalizedTarget(x.Target) ||
                             matchedFixedNdbCandidates.Contains(x)));
                    }

                    detections.AddRange(EvaluateNdb(
                        materializedNdb,
                        fullData,
                        options.Limits,
                        signatureFileType,
                        cancellationToken,
                        scanOptions: options));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                    var applicableLogical = logicalSignatures
                        .Where(x => LdbRuntime.TargetMatchesFileType(x.Target?.Target ?? 0, signatureFileType) &&
                                    (x.Target?.MinFileSize is null || fullData.Length >= x.Target.MinFileSize.Value) &&
                                    (x.Target?.MaxFileSize is null || fullData.Length <= x.Target.MaxFileSize.Value))
                        .ToArray();

                    detections.AddRange(EvaluateLogical(applicableLogical, ndbSignatures, fullData, options.Limits, signatureFileType, state.Database.IconDatabase, [], cancellationToken, scanState: state, scanOptions: options));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                }
                if (specializedRules)
                {
                    if (options.ScanPE && ScanTypePolicy.IsPe(rootType))
                        detections.AddRange(PeSpecializedMatcher.Match(fullData, state, options.Limits, cancellationToken));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                }
                foreach (var contentScanner in options.ContentScanners)
                {
                    detections.AddRange(contentScanner.Scan(fullData, path, cancellationToken));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                }
                if (options.ScanPE && ScanTypePolicy.IsPe(rootType))
                {
                    detections.AddRange(PeOverlayScanner.ScanPeOverlay(fullData, state, options, cancellationToken));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                }
                if (requiresMachOFat || (ScanTypePolicy.IsMachO(rootType) && ScanTypePolicy.LooksLikeMachOFat(fullData)))
                {
                    detections.AddRange(ScanMachOFatSlices(fullData, state, options, cancellationToken));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                }
                if (requiresContainerExpansion && !containerPreScanned)
                {
                    detections.AddRange(ArchiveScanner.Scan(fullData, path, state, options, [], 0, cancellationToken));
                    if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                        return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
                }
            }

            if (fullData is null && options.ScanPE && ScanTypePolicy.IsPe(rootType) && peSectionRules.Length != 0 &&
                (state.Database.DynamicConfiguration.Pe & DynamicConfigFlags.PeMd5Sect) != 0)
            {
                var sectionHits = await PeSpecializedMatcher.MatchSectionsFromFileAsync(path, info.Length, peSectionRules, options.Limits.MaxPatternMatchesPerSignature, cancellationToken);
                detections.AddRange(sectionHits);
                if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                    return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
            }

            if (fullData is null && options.ScanPE && ScanTypePolicy.IsPe(rootType))
            {
                var overlayHits = await PeOverlayScanner.ScanPeOverlayFromFileAsync(path, info.Length, state, options, cancellationToken);
                detections.AddRange(overlayHits);
                if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                    return CreateDetectionResult(path, rootType, detections, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault(), options);
            }

            var finalResult = CreateDetectionResult(
                path,
                rootType,
                detections,
                rawMatch.BytesRead,
                started.Elapsed,
                state.Database.Databases.FirstOrDefault(),
                options,
                trusted: rawMatch.Trusted);
            if (fullBufferLimitExceeded && !(options.EnableHeuristics && options.HeuristicExceedsMax) && finalResult.Verdict == ScanVerdict.Clean)
                return finalResult with { Verdict = ScanVerdict.Error };
            return finalResult;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new ScanResult(ScanVerdict.Timeout, path, DetectType(path), [], 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());
        }
        catch (IOException)
        {
            return new ScanResult(ScanVerdict.Error, path, DetectType(path), [], 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());
        }
        catch (UnauthorizedAccessException)
        {
            return new ScanResult(ScanVerdict.Error, path, DetectType(path), [], 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());
        }
    }

    internal static ScanResult CreateDetectionResult(
        string path,
        string? fileType,
        IEnumerable<Detection> detections,
        long bytesScanned,
        TimeSpan duration,
        DatabaseInfo? database,
        ScanOptions options,
        bool trusted = false)
    {
        var visible = options.FilterDetections(detections);
        if (trusted && visible.Count == 0)
            return new ScanResult(ScanVerdict.Trusted, path, fileType, [], bytesScanned, duration, database);

        var verdict = visible.Count == 0
            ? ScanVerdict.Clean
            : visible.Any(x => !ScanOptions.IsPuaName(x.Name) && !ScanTypePolicy.IsHeuristic(x))
                ? ScanVerdict.Malicious
                : visible.Any(x => ScanOptions.IsPuaName(x.Name))
                    ? ScanVerdict.PotentiallyUnwanted
                    : ScanVerdict.StrongIndicator;
        return new ScanResult(verdict, path, fileType, visible, bytesScanned, duration, database);
    }

    private static bool HasApplicableLogicalSignatures(
        IReadOnlyList<LogicalSignature> signatures,
        string fileType,
        long fileSize)
    {
        foreach (var signature in signatures)
        {
            var target = signature.Target;
            if (target is null)
                return true;
            if (target.Target != 0 && !LdbRuntime.TargetMatchesFileType(target.Target, fileType))
                continue;
            if (target.MinFileSize is not null && fileSize < target.MinFileSize.Value)
                continue;
            if (target.MaxFileSize is not null && fileSize > target.MaxFileSize.Value)
                continue;

            // A concrete container/intermediate constraint cannot match the root
            // layer, which has no parent chain. Avoid materializing the root merely
            // because such a nested-only rule exists. Nested layers are already
            // materialized by their archive/container handlers.
            if (target.Container is not null &&
                !target.Container.Equals("ANY", StringComparison.OrdinalIgnoreCase))
                continue;
            if (target.Intermediates is not null && target.Intermediates.Count != 0)
                continue;

            return true;
        }
        return false;
    }

    private static async Task<byte[]> ReadFullFileAsync(string path, long length, CancellationToken cancellationToken)
    {
        if (length < 0 || length > int.MaxValue)
            throw new InvalidDataException("File is too large to materialize in the managed scan path.");

        await using var input = File.OpenRead(path);
        using var buffer = new MemoryStream((int)length);
        await input.CopyToAsync(buffer, cancellationToken);
        return buffer.ToArray();
    }

    private ScanOptions CreateEffectiveOptions(ScanOptions options)
    {
        var effective = new ScanOptions
        {
            CollectAllMatches = options.CollectAllMatches,
            Limits = options.CreateEffectiveLimits(),
            YaraRuleDirectory = options.YaraRuleDirectory,
            BytecodeDirectory = options.BytecodeDirectory,
            ScanArchive = options.ScanArchive,
            ScanELF = options.ScanELF,
            ScanPDF = options.ScanPDF,
            ScanSWF = options.ScanSWF,
            ScanHWP3 = options.ScanHWP3,
            ScanXMLDocs = options.ScanXMLDocs,
            ScanMail = options.ScanMail,
            ScanOLE2 = options.ScanOLE2,
            ScanHTML = options.ScanHTML,
            ScanPE = options.ScanPE,
            ScanOneNote = options.ScanOneNote,
            ScanImage = options.ScanImage,
            ScanImageFuzzyHash = options.ScanImageFuzzyHash,
            EnableHeuristics = options.EnableHeuristics,
            HeuristicPrecedence = options.HeuristicPrecedence,
            HeuristicExceedsMax = options.HeuristicExceedsMax,
            HeuristicEncryptedArchive = options.HeuristicEncryptedArchive,
            HeuristicEncryptedDoc = options.HeuristicEncryptedDoc,
            DetectPUA = options.DetectPUA,
            MaxFileSize = options.MaxFileSize,
            MaxScanSize = options.MaxScanSize,
            MaxFiles = options.MaxFiles,
            MaxRecursion = options.MaxRecursion,
            UseMultithreading = options.UseMultithreading,
            MaxThreads = options.MaxThreads,
            Verbose = options.Verbose,
            ShowProgress = options.ShowProgress,
            InfectedOnly = options.InfectedOnly,
            Recursive = options.Recursive,
            FollowSymlinks = options.FollowSymlinks,
            ExcludeDirectories = [.. options.ExcludeDirectories],
            ExcludeExtensions = [.. options.ExcludeExtensions]
        };
        foreach (var scanner in options.ContentScanners) effective.ContentScanners.Add(scanner);
        if (!string.IsNullOrWhiteSpace(options.YaraRuleDirectory)
            && !effective.ContentScanners.OfType<YaraContentScanner>().Any(x => string.Equals(x.Directory, options.YaraRuleDirectory, StringComparison.OrdinalIgnoreCase)))
        {
            var directory = Path.GetFullPath(options.YaraRuleDirectory);
            var key = "yara:" + directory;
            var scanner = _optionalScannerCache.GetOrAdd(key, _ => new Lazy<IContentScanner>(() => new YaraContentScanner(directory), LazyThreadSafetyMode.ExecutionAndPublication)).Value;
            effective.ContentScanners.Add(scanner);
        }
        if (!string.IsNullOrWhiteSpace(options.BytecodeDirectory)
            && !effective.ContentScanners.OfType<BytecodeContentScanner>().Any(x => string.Equals(x.Directory, options.BytecodeDirectory, StringComparison.OrdinalIgnoreCase)))
        {
            var directory = Path.GetFullPath(options.BytecodeDirectory);
            var key = "bytecode:" + directory;
            var scanner = _optionalScannerCache.GetOrAdd(key, _ => new Lazy<IContentScanner>(() => new BytecodeContentScanner(directory), LazyThreadSafetyMode.ExecutionAndPublication)).Value;
            effective.ContentScanners.Add(scanner);
        }
        return effective;
    }

}
