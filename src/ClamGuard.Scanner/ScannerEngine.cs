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

public sealed class ScannerEngine
{
    private readonly DatabaseManager _databaseManager;
    private readonly ConcurrentDictionary<string, Lazy<IContentScanner>> _optionalScannerCache = new(StringComparer.OrdinalIgnoreCase);

    public ScannerEngine(DatabaseManager databaseManager) => _databaseManager = databaseManager;

    public ScanResult Scan(string path, ScanOptions? options = null)
        => ScanAsync(path, options).GetAwaiter().GetResult();

    public async Task<ScanResult> ScanAsync(string path, ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new ScanOptions();
        options.Limits.Validate();
        options = CreateEffectiveOptions(options);
        var started = Stopwatch.StartNew();
        if (!File.Exists(path))
            return new ScanResult(ScanVerdict.Error, path, null, [], 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());

        var info = new FileInfo(path);
        if (info.Length > options.Limits.MaxFileSize)
            return new ScanResult(ScanVerdict.Error, path, DetectType(path), [], 0, started.Elapsed, _databaseManager.Current.Database.Databases.FirstOrDefault());

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
            // Only an applicable, non-streamable NDB rule can require the expensive
            // second pass. Macro NDB entries are logical-signature ingredients and are
            // already covered when logical signatures are evaluated.
            var requiresFullNdbEvaluation = applicableRawNdb.Any(x => !streamableNdb.Contains(x));
            var requiresContainerExpansion = ScanTypePolicy.IsArchiveContainer(rootType);
            var requiresMachOFat = ScanTypePolicy.IsMachO(rootType) && ScanTypePolicy.LooksLikeMachOFat(probe);
            var requiresSpecializedPreRaw = ScanTypePolicy.RequiresSpecializedPreRaw(rootType) &&
                                            (!(rootType.Equals("HTML", StringComparison.OrdinalIgnoreCase) ||
                                               rootType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase)) ||
                                             info.Length <= options.Limits.MaxHtmlNormalize);

            // ClamAV runs container/document parsers before the ordinary raw scan for
            // these types. Because our managed archive layer needs a materialized span,
            // load it once, scan the container first, and reuse the same bytes for the
            // raw matcher and later target-specific passes. PE/ELF/Mach-O keep the raw-
            // first path, matching cli_magic_scan()'s executable ordering.
            var requiresPeFullBuffer = peImportRules.Length != 0 && ScanTypePolicy.IsPe(rootType);
            var requiresLogicalFullBuffer = HasApplicableLogicalSignatures(
                logicalSignatures,
                signatureFileType,
                info.Length);
            var needsFullBuffer = requiresLogicalFullBuffer || requiresFullNdbEvaluation ||
                                  requiresPeFullBuffer || requiresContainerExpansion ||
                                  requiresMachOFat || requiresSpecializedPreRaw ||
                                  options.ContentScanners.Count != 0;
            byte[]? fullData = null;
            var containerPreScanned = false;
            var detections = new List<Detection>();

            if (needsFullBuffer && info.Length > options.Limits.MaxFullBufferSize)
                return new ScanResult(ScanVerdict.Error, path, rootType, [], 0, started.Elapsed, state.Database.Databases.FirstOrDefault());

            // If a whole-file buffer is already needed for subsequent operations, read it once upfront
            // to avoid reading the file twice from disk.
            if (needsFullBuffer)
            {
                fullData = await ReadFullFileAsync(path, info.Length, cancellationToken);
            }

            if (requiresContainerExpansion)
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
                if (!options.CollectAllMatches && detections.Count != 0)
                    return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), info.Length, started.Elapsed, state.Database.Databases.FirstOrDefault());
            }

            if (requiresSpecializedPreRaw)
            {
                detections.AddRange(SpecializedFileHandlers.ScanPreRaw(
                    fullData!, rootType, state, options, path, cancellationToken));
                if (!options.CollectAllMatches && detections.Count != 0)
                    return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), info.Length, started.Elapsed, state.Database.Databases.FirstOrDefault());
            }

            (IReadOnlyList<Detection> Detections, bool Trusted, long BytesRead) rawMatch;
            if (fullData is not null)
            {
                // The bytes are already in RAM. Re-reading them through a second disk stream / memory map
                // adds 100% duplicate I/O. Use fast in-memory compiled match directly.
                rawMatch = (state.Compiled.Match(
                    fullData,
                    "compiled-database",
                    includeNdb: false,
                    collectAllMatches: options.CollectAllMatches),
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
                    collectAllMatches: options.CollectAllMatches,
                    ndbFilter: streamableNdb.Count == 0 ? null : streamableNdb.Contains);
            }

            if (rawMatch.Trusted)
            {
                // .fp/.sfp matched the root layer. ClamAV converts this to CL_VERIFIED,
                // clears prior evidence, and skips child/container scanning.
                return new ScanResult(ScanVerdict.Trusted, path, rootType, [], rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
            }

            detections.AddRange(rawMatch.Detections);
            if (!options.CollectAllMatches && detections.Count != 0)
                return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());

            var specializedRules = peSectionRules.Length != 0 || peImportRules.Length != 0;
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
                        materializedNdb = materializedNdb.Where(x => !streamableNdb.Contains(x));

                    detections.AddRange(EvaluateNdb(
                        materializedNdb,
                        fullData,
                        options.Limits,
                        signatureFileType,
                        cancellationToken));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                    var applicableLogical = logicalSignatures
                        .Where(x => LdbRuntime.TargetMatchesFileType(x.Target?.Target ?? 0, signatureFileType) &&
                                    (x.Target?.MinFileSize is null || fullData.Length >= x.Target.MinFileSize.Value) &&
                                    (x.Target?.MaxFileSize is null || fullData.Length <= x.Target.MaxFileSize.Value))
                        .ToArray();

                    detections.AddRange(EvaluateLogical(applicableLogical, ndbSignatures, fullData, options.Limits, signatureFileType, state.Database.IconDatabase, [], cancellationToken, scanState: state, scanOptions: options));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                }
                if (specializedRules)
                {
                    if (ScanTypePolicy.IsPe(rootType))
                        detections.AddRange(PeSpecializedMatcher.Match(fullData, state, options.Limits, cancellationToken));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                }
                foreach (var contentScanner in options.ContentScanners)
                {
                    detections.AddRange(contentScanner.Scan(fullData, path, cancellationToken));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                }
                if (ScanTypePolicy.IsPe(rootType))
                {
                    detections.AddRange(PeOverlayScanner.ScanPeOverlay(fullData, state, options, cancellationToken));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                }
                if (requiresMachOFat || (ScanTypePolicy.IsMachO(rootType) && ScanTypePolicy.LooksLikeMachOFat(fullData)))
                {
                    detections.AddRange(ScanMachOFatSlices(fullData, state, options, cancellationToken));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                }
                if (requiresContainerExpansion && !containerPreScanned)
                {
                    detections.AddRange(ArchiveScanner.Scan(fullData, path, state, options, [], 0, cancellationToken));
                    if (!options.CollectAllMatches && detections.Count != 0)
                        return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
                }
            }

            if (fullData is null && ScanTypePolicy.IsPe(rootType) && peSectionRules.Length != 0 &&
                (state.Database.DynamicConfiguration.Pe & DynamicConfigFlags.PeMd5Sect) != 0)
            {
                var sectionHits = await PeSpecializedMatcher.MatchSectionsFromFileAsync(path, info.Length, peSectionRules, options.Limits.MaxPatternMatchesPerSignature, cancellationToken);
                detections.AddRange(sectionHits);
                if (!options.CollectAllMatches && detections.Count != 0)
                    return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
            }

            if (fullData is null && ScanTypePolicy.IsPe(rootType))
            {
                var overlayHits = await PeOverlayScanner.ScanPeOverlayFromFileAsync(path, info.Length, state, options, cancellationToken);
                detections.AddRange(overlayHits);
                if (!options.CollectAllMatches && detections.Count != 0)
                    return new ScanResult(ScanVerdict.Malicious, path, rootType, detections.Take(1).ToArray(), rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
            }

            var distinct = detections
                .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .Select(x => x.First())
                .ToArray();

            var verdict = rawMatch.Trusted && distinct.Length == 0
                ? ScanVerdict.Trusted
                : distinct.Length == 0 ? ScanVerdict.Clean : ScanVerdict.Malicious;

            return new ScanResult(verdict, path, rootType, distinct, rawMatch.BytesRead, started.Elapsed, state.Database.Databases.FirstOrDefault());
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
            Limits = options.Limits,
            YaraRuleDirectory = options.YaraRuleDirectory,
            BytecodeDirectory = options.BytecodeDirectory
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

    internal static ScanResult ScanBuffer(byte[] buffer, int length, CompiledState state, ScanOptions options, string path, CancellationToken cancellationToken)
    {
        var data = buffer.AsSpan(0, length);
        var fileType = DetectType(data, path, state.Database.SpecialDatabases.FileTypes);
        var detections = new List<Detection>();
        if (ScanTypePolicy.RequiresSpecializedPreRaw(fileType))
        {
            detections.AddRange(SpecializedFileHandlers.ScanPreRaw(data, fileType, state, options, path, cancellationToken));
            if (!options.CollectAllMatches && detections.Count != 0)
                return new ScanResult(ScanVerdict.Malicious, path, fileType, [detections[0]], length, TimeSpan.Zero, state.Database.Databases.FirstOrDefault());
        }
        detections.AddRange(state.Compiled.Match(data, "compiled-database", includeNdb: false, collectAllMatches: options.CollectAllMatches));
        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        detections.AddRange(EvaluateNdb(ndb, data, options.Limits, fileType, cancellationToken));
        detections.AddRange(EvaluateLogical(state.Database.Signatures.OfType<LogicalSignature>(), ndb, data, options.Limits, fileType, state.Database.IconDatabase, [], cancellationToken, scanState: state, scanOptions: options));
        if (ScanTypePolicy.IsPe(fileType))
            detections.AddRange(PeSpecializedMatcher.Match(data, state, options.Limits, cancellationToken));
        foreach (var contentScanner in options.ContentScanners)
            detections.AddRange(contentScanner.Scan(data, path, cancellationToken));
        if (ScanTypePolicy.IsPe(fileType))
            detections.AddRange(PeOverlayScanner.ScanPeOverlay(data.ToArray(), state, options, cancellationToken));
        if (ScanTypePolicy.IsMachO(fileType) && ScanTypePolicy.LooksLikeMachOFat(data))
            detections.AddRange(ScanMachOFatSlices(buffer, length, state, options, cancellationToken));
        if (ScanTypePolicy.IsArchiveContainer(fileType))
            detections.AddRange(ArchiveScanner.Scan(data, path, state, options, [], 0, cancellationToken));
        var distinct = detections.GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToArray();
        var trusted = state.Compiled.MatchesFalsePositive(data);
        if (trusted && distinct.Length == 0)
            return new ScanResult(ScanVerdict.Trusted, path, fileType, distinct, length, TimeSpan.Zero, state.Database.Databases.FirstOrDefault());
        var verdict = distinct.Length == 0 ? ScanVerdict.Clean : ScanVerdict.Malicious;
        return new ScanResult(verdict, path, fileType, distinct, length, TimeSpan.Zero, state.Database.Databases.FirstOrDefault());
    }

    private static IReadOnlyList<Detection> ScanMachOFatSlices(
        byte[] data,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
        => ScanMachOFatSlices(data, data.Length, state, options, cancellationToken);

    private static IReadOnlyList<Detection> ScanMachOFatSlices(
        byte[] data,
        int length,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (length <= 0) return [];
        var whole = data.AsSpan(0, length);
        var slices = LdbRuntime.GetMachOFatSlices(whole);
        if (slices.Count == 0) return [];

        var results = new List<Detection>();
        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        var logical = state.Database.Signatures.OfType<LogicalSignature>().ToArray();

        foreach (var (offset, sliceLength) in slices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var slice = data.AsSpan(offset, sliceLength);
            if (state.Compiled.MatchesFalsePositive(slice))
                continue;
            var type = DetectType(slice, "embedded.macho", state.Database.SpecialDatabases.FileTypes);

            foreach (var hit in state.Compiled.Match(slice, $"mach-o-slice@{offset}", includeNdb: false))
                results.Add(hit.Offset is null
                    ? hit
                    : hit with { Offset = hit.Offset.Value + offset });

            foreach (var hit in EvaluateNdb(ndb, slice, options.Limits, type, cancellationToken))
                results.Add(hit.Offset is null
                    ? hit
                    : hit with { Offset = hit.Offset.Value + offset });

            foreach (var hit in EvaluateLogical(logical, ndb, slice, options.Limits, type, state.Database.IconDatabase, ["MACHO_UNIBIN"], cancellationToken, scanState: state, scanOptions: options))
                results.Add(hit.Offset is null
                    ? hit
                    : hit with { Offset = hit.Offset.Value + offset });

            if (ScanTypePolicy.IsPe(type))
            {
                foreach (var hit in PeSpecializedMatcher.Match(slice, state, options.Limits, cancellationToken))
                    results.Add(hit.Offset is null
                        ? hit
                        : hit with { Offset = hit.Offset.Value + offset });
            }

            foreach (var contentScanner in options.ContentScanners)
            {
                foreach (var hit in contentScanner.Scan(slice, $"mach-o-slice@{offset}", cancellationToken))
                    results.Add(hit.Offset is null
                        ? hit
                        : hit with { Offset = hit.Offset.Value + offset });
            }
        }

        return results;
    }

    internal static IReadOnlyList<Detection> EvaluateNdb(
        IEnumerable<NdbSignature> signatures,
        ReadOnlySpan<byte> data,
        ScanLimits limits,
        string fileType,
        CancellationToken cancellationToken)
    {
        var results = new List<Detection>();
        if (data.IsEmpty) return results;

        foreach (var signature in signatures)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (signature.MacroGroup is not null)
                continue; // Macro members are consumed by LDB macro subsignatures, not alerts.

            var normalized = NormalizeTargetData(data, fileType, signature.Target);
            ReadOnlySpan<byte> scanData = data;
            if (normalized is not null) scanData = normalized;
            var context = LdbRuntime.CreateContext(scanData, fileType);
            if (!LdbRuntime.TargetMatchesFileType(signature.Target, context))
                continue;

            var content = new ContentSignature(
                signature.Name,
                SignatureType.Ndb,
                signature.SourceFile,
                signature.Pattern,
                signature.OffsetExpression);
            var matches = LogicalContentMatcher.FindContentMatches(content, scanData, context, limits.MaxPatternMatchesPerSignature);
            if (matches.Count == 0)
                continue;

            results.Add(new Detection(
                signature.Name,
                SignatureType.Ndb,
                matches[0],
                signature.SourceFile,
                $"NDB target {signature.Target} content pattern matched."));
        }
        return results;
    }

    internal static IReadOnlyList<Detection> EvaluateLogical(
        IEnumerable<LogicalSignature> signatures,
        IEnumerable<NdbSignature> ndbSignatures,
        ReadOnlySpan<byte> data,
        ScanLimits limits,
        string fileType,
        IconDatabase? iconDatabase,
        IReadOnlyList<string> parentTypes,
        CancellationToken cancellationToken,
        bool retyped = false,
        CompiledState? scanState = null,
        ScanOptions? scanOptions = null)
    {
        var results = new List<Detection>();
        var baseContext = LdbRuntime.CreateContext(data, fileType, parentTypes, retyped);
        // ClamAV gates PCRE signature support behind PCRE_CONF_SUPPORT and the
        // PE icon check behind PE_CONF_MATCHICON; a missing engine state keeps
        // both enabled (matching the all-on dconf defaults).
        var dconf = scanState?.Database.DynamicConfiguration;
        var pcreSupported = dconf is null || (dconf.Pcre & DynamicConfigFlags.PcreSupport) != 0;
        var matchIconEnabled = dconf is null || (dconf.Pe & DynamicConfigFlags.PeMatchIcon) != 0;
        var macroPositions = new Dictionary<int, List<int>>();
        var macroMembers = ndbSignatures
            .Where(static x => x.MacroGroup is not null)
            .GroupBy(x => x.MacroGroup!.Value)
            .ToDictionary(x => x.Key, x => x.ToArray());

        // ClamAV stores the most recent match for each macro group. Pre-compute
        // those positions so LDB content subsignatures using $N$ can resolve
        // the same absolute anchor before the logical expression is evaluated.
        // Only run this if any active signature actually contains macro subsignatures.
        var hasAnyMacroSubSignatures = signatures.Any(static s => s.MacroSubSignatures is not null && s.MacroSubSignatures.Count != 0);
        if (hasAnyMacroSubSignatures && macroMembers.Count != 0)
        {
            foreach (var pair in macroMembers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var positions = new List<int>();
                foreach (var member in pair.Value)
                {
                    var normalized = NormalizeTargetData(data, fileType, member.Target);
                    ReadOnlySpan<byte> memberData = data;
                    if (normalized is not null) memberData = normalized;
                    var memberContext = normalized is null ? baseContext : LdbRuntime.CreateContext(memberData, fileType, parentTypes, retyped);
                    if (!LdbRuntime.TargetMatchesFileType(member.Target, memberContext))
                        continue;
                    // In an NDB macro member the $N$ offset is a group marker, not a file offset.
                    var memberMatches = LogicalContentMatcher.FindContentMatches(
                        new ContentSignature(member.Name, SignatureType.Ndb, member.SourceFile, member.Pattern, "*"),
                        memberData, memberContext, limits.MaxPatternMatchesPerSignature);
                    positions.AddRange(memberMatches);
                }
                if (positions.Count != 0)
                    macroPositions[pair.Key] = positions.Distinct().OrderBy(static x => x).ToList();
            }
        }

        foreach (var signature in signatures)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = signature.Target;
            var normalized = NormalizeTargetData(data, fileType, target?.Target ?? 0);
            ReadOnlySpan<byte> matchData = data;
            if (normalized is not null) matchData = normalized;
            var context = normalized is null ? baseContext : LdbRuntime.CreateContext(matchData, fileType, parentTypes, retyped);
            if (!LdbRuntime.MatchesTarget(target, context))
                continue;

            var indexMap = new Dictionary<int, ContentSignature>();
            foreach (var sub in signature.SubSignatures)
                indexMap[GetSubsigIndex(sub)] = sub;

            var maxIndex = signature.SubSignatures.Select(GetSubsigIndex).DefaultIfEmpty(-1).Max();
            if (signature.MacroSubSignatures is not null && signature.MacroSubSignatures.Count != 0)
                maxIndex = Math.Max(maxIndex, signature.MacroSubSignatures.Keys.Max());
            if (signature.RegexSubSignatures is not null && signature.RegexSubSignatures.Count != 0)
                maxIndex = Math.Max(maxIndex, signature.RegexSubSignatures.Keys.Max());
            if (signature.ByteCompareSubSignatures is not null && signature.ByteCompareSubSignatures.Count != 0)
                maxIndex = Math.Max(maxIndex, signature.ByteCompareSubSignatures.Keys.Max());
            if (signature.FuzzyImageSubSignatures is not null && signature.FuzzyImageSubSignatures.Count != 0)
                maxIndex = Math.Max(maxIndex, signature.FuzzyImageSubSignatures.Keys.Max());
            if (maxIndex < 0 || maxIndex >= 64)
                continue;

            var matches = Enumerable.Range(0, maxIndex + 1).Select(static i => new SubsigMatches(i)).ToArray();
            var isPureAnd = IsPureAndExpression(signature.Expression);
            var andSatisfied = true;
            // For pure AND expressions ("0&1&2..."), test fixed & longer patterns first to fail fast.
            IEnumerable<KeyValuePair<int, ContentSignature>> orderedSubs = indexMap;
            if (isPureAnd && indexMap.Count > 1)
            {
                orderedSubs = indexMap.OrderByDescending(static kv => kv.Value.Pattern.IsFixed)
                                      .ThenByDescending(static kv => kv.Value.Pattern.MinLength);
            }

            foreach (var kv in orderedSubs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var index = kv.Key;
                var sub = kv.Value;
                var hits = LogicalContentMatcher.FindContentMatches(sub, matchData, context, limits.MaxPatternMatchesPerSignature, macroPositions);
                matches[index].Positions.AddRange(hits);
                if (isPureAnd && hits.Count == 0)
                {
                    andSatisfied = false;
                    break;
                }
            }

            if (isPureAnd && !andSatisfied)
                continue;

            if (signature.MacroSubSignatures is not null)
            {
                foreach (var pair in signature.MacroSubSignatures)
                {
                    var index = pair.Key;
                    var spec = pair.Value;
                    if (index <= 0 || index >= matches.Length || !macroMembers.TryGetValue(spec.MacroGroup, out var members))
                        continue;
                    var preceding = matches[index - 1].Positions;
                    var seen = new SortedSet<int>();
                    foreach (var previousStart in preceding)
                    foreach (var member in members)
                    {
                        if (!LdbRuntime.TargetMatchesFileType(member.Target, context))
                            continue;
                        var memberMatches = LogicalContentMatcher.FindContentMatches(
                            new ContentSignature(member.Name, SignatureType.Ndb, member.SourceFile, member.Pattern, "*"),
                            matchData, context, limits.MaxPatternMatchesPerSignature, macroPositions);
                        foreach (var memberStart in memberMatches)
                        {
                            var delta = memberStart - previousStart;
                            if (delta >= spec.MinDistance && delta <= spec.MaxDistance)
                                seen.Add(memberStart);
                        }
                    }
                    var macroMatches = seen.Take(limits.MaxPatternMatchesPerSignature).ToArray();
                    matches[index].Positions.AddRange(macroMatches);
                    if (spec.MacroGroup >= 0 && macroMatches.Length != 0)
                        macroPositions[spec.MacroGroup] = macroMatches.ToList();
                }
            }

            if (signature.RegexSubSignatures is not null && pcreSupported)
            {
                foreach (var pair in signature.RegexSubSignatures.OrderBy(static x => x.Key))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var index = pair.Key;
                    var regexSub = pair.Value;
                    if (index >= matches.Length || !LogicalExpressionEvaluator.ValidateReferencesBefore(regexSub.Trigger, index) ||
                        !TryEvaluateTrigger(regexSub.Trigger, matches, limits.MaxLogicalDepth))
                        continue;
                    matches[index].Positions.AddRange(RegexContentMatcher.FindRegexMatches(regexSub, matchData, context, limits.MaxPatternMatchesPerSignature));
                }
            }

            if (signature.ByteCompareSubSignatures is not null)
            {
                foreach (var pair in signature.ByteCompareSubSignatures.OrderBy(static x => x.Key))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var index = pair.Key;
                    var spec = pair.Value;
                    if (index >= matches.Length || spec.ReferenceSubSignature < 0 || spec.ReferenceSubSignature >= matches.Length ||
                        spec.ReferenceSubSignature >= index ||
                        (signature.RegexSubSignatures?.ContainsKey(spec.ReferenceSubSignature) ?? false) ||
                        (signature.ByteCompareSubSignatures?.ContainsKey(spec.ReferenceSubSignature) ?? false) ||
                        matches[spec.ReferenceSubSignature].Positions.Count == 0)
                        continue;
                    foreach (var referenceStart in matches[spec.ReferenceSubSignature].Positions.Take(limits.MaxPatternMatchesPerSignature))
                    {
                        var valueOffset = referenceStart + spec.Shift;
                        // ClamAV's byte-compare matcher requires the effective offset
                        // to be strictly greater than zero.
                        if (valueOffset <= 0 || !TryReadByteCompareValue(matchData, valueOffset, spec, out var value))
                            continue;
                        if (spec.Comparisons.All(c => CompareByteValue(value, c)))
                            matches[index].Positions.Add(valueOffset);
                    }
                    if (matches[index].Positions.Count > limits.MaxPatternMatchesPerSignature)
                        matches[index].Positions.RemoveRange(limits.MaxPatternMatchesPerSignature, matches[index].Positions.Count - limits.MaxPatternMatchesPerSignature);
                }
            }

            if (signature.FuzzyImageSubSignatures is not null)
            {
                foreach (var pair in signature.FuzzyImageSubSignatures)
                {
                    if (pair.Key < matches.Length && LdbRuntime.FuzzyImageMatches(matchData, pair.Value.Hash))
                        matches[pair.Key].Positions.Add(0);
                }
            }

            bool expressionMatched;
            try
            {
                if (!LogicalExpressionEvaluator.ValidateReferencesBefore(signature.Expression, matches.Length))
                    continue;
                expressionMatched = LogicalExpressionEvaluator.Evaluate(signature.Expression, matches, limits.MaxLogicalDepth);
            }
            catch (FormatException) { continue; }
            catch (InvalidDataException) { continue; }

            if (!expressionMatched)
                continue;

            // HandlerType is a re-typing rule, not a direct detection rule. ClamAV only
            // invokes the requested handler after the logical expression for this rule
            // has matched. The retyped pass is protected from recursively retyping itself.
            if (target?.HandlerType is not null)
            {
                // HandlerType is a re-typing rule, not an alert. On the first
                // layer ClamAV starts a child-style scan using the requested type.
                // On the retyped layer the RETYPED guard prevents the same rule
                // from firing again, so the handler rule itself does not become a
                // detection.
                if (!context.Retyped && scanState is not null && scanOptions is not null)
                {
                    results.AddRange(RescanAsHandlerType(
                        data,
                        scanState,
                        scanOptions,
                        target.HandlerType,
                        parentTypes,
                        cancellationToken));
                }
                continue;
            }

            if ((target?.IconGroup1 is not null || target?.IconGroup2 is not null) &&
                matchIconEnabled &&
                !LdbRuntime.HasIconGroup(data, context, target!.IconGroup1, target.IconGroup2, iconDatabase))
                continue;

            results.Add(new Detection(
                signature.Name,
                SignatureType.Logical,
                null,
                signature.SourceFile,
                $"Logical expression evaluated true: {signature.Expression}"));
        }
        return results;
    }

    private static bool IsPureAndExpression(string expr)
    {
        if (string.IsNullOrWhiteSpace(expr)) return false;
        // Pure AND consists solely of digits and '&' characters (e.g. "0&1&2&3&4")
        foreach (var c in expr)
        {
            if (c != '&' && !char.IsAsciiDigit(c))
                return false;
        }
        return expr.Contains('&');
    }

    private static IReadOnlyList<Detection> RescanAsHandlerType(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        string handlerType,
        IReadOnlyList<string> parentTypes,
        CancellationToken cancellationToken)
    {
        // HandlerType creates a retyped scan layer. Apply FP trust before running the
        // handler matchers/scanners so a trusted layer produces no evidence.
        if (state.Compiled.MatchesFalsePositive(data))
            return [];

        var results = new List<Detection>();
        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        var logical = state.Database.Signatures.OfType<LogicalSignature>().ToArray();

        // cli_magic_scan() performs the ordinary compiled/raw matcher again on
        // the retyped fmap before/alongside its type-specific scanners.
        results.AddRange(state.Compiled.Match(
            data,
            $"handler-type:{handlerType}",
            includeNdb: false));

        results.AddRange(EvaluateNdb(
            ndb,
            data,
            options.Limits,
            handlerType,
            cancellationToken));

        results.AddRange(EvaluateLogical(
            logical,
            ndb,
            data,
            options.Limits,
            handlerType,
            state.Database.IconDatabase,
            parentTypes,
            cancellationToken,
            retyped: true,
            scanState: state,
            scanOptions: options));

        // Dispatch only the handler requested by the retyping layer. ClamAV's
        // cli_magic_scan() switches on the active layer type; it does not run the
        // PE parser on an ELF/ZIP/etc merely because HandlerType exists.
        if (ScanTypePolicy.IsPe(handlerType))
            results.AddRange(PeSpecializedMatcher.Match(data, state, options.Limits, cancellationToken));

        foreach (var contentScanner in options.ContentScanners)
            results.AddRange(contentScanner.Scan(data, $"handler-type:{handlerType}", cancellationToken));

        if (handlerType.Equals("PE", StringComparison.OrdinalIgnoreCase) ||
            handlerType.Equals("MSEXE", StringComparison.OrdinalIgnoreCase))
        {
            results.AddRange(PeOverlayScanner.ScanPeOverlay(data.ToArray(), state, options, cancellationToken));
        }

        if (handlerType.Equals("MACH-O", StringComparison.OrdinalIgnoreCase) ||
            handlerType.Equals("MACHO_UNIBIN", StringComparison.OrdinalIgnoreCase))
        {
            results.AddRange(ScanMachOFatSlices(data.ToArray(), state, options, cancellationToken));
        }

        // Archive/document handlers are dispatched only for the active handler
        // type. ArchiveScanner still performs the concrete byte-level subtype
        // detection before extraction.
        if (ScanTypePolicy.IsArchiveContainer(handlerType))
        {
            results.AddRange(ArchiveScanner.Scan(
                data,
                $"handler-type.{handlerType}",
                state,
                options,
                parentTypes,
                parentTypes.Count + 1,
                cancellationToken));
        }

        return results;
    }

    private static byte[]? NormalizeTargetData(ReadOnlySpan<byte> data, string fileType, int target)
    {
        if (target == 3 && fileType.Equals("HTML", StringComparison.OrdinalIgnoreCase))
            return NormalizeHtml(data);
        if (target == 3 && fileType.Equals("HTML_UTF16", StringComparison.OrdinalIgnoreCase))
        {
            var text = DecodeUtf16Text(data);
            return text is null ? null : NormalizeHtml(Encoding.Latin1.GetBytes(text));
        }
        if (target == 7 && fileType.Equals("ASCII", StringComparison.OrdinalIgnoreCase))
            return NormalizeAscii(data);
        return null;
    }

    private static string? DecodeUtf16Text(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        try
        {
            if (data[0] == 0xff && data[1] == 0xfe)
                return Encoding.Unicode.GetString(data[2..]);
            if (data[0] == 0xfe && data[1] == 0xff)
                return Encoding.BigEndianUnicode.GetString(data[2..]);
            return null;
        }
        catch (DecoderFallbackException) { return null; }
    }

    private static byte[] NormalizeAscii(ReadOnlySpan<byte> data)
    {
        var text = Encoding.Latin1.GetString(data);
        var normalized = new StringBuilder(text.Length);
        var pendingSpace = false;
        foreach (var ch in text)
        {
            if (ch is >= '\x21' and <= '\x7e')
            {
                if (pendingSpace && normalized.Length != 0) normalized.Append(' ');
                normalized.Append(char.ToLowerInvariant(ch));
                pendingSpace = false;
                continue;
            }
            if (ch is ' ' or '\t' or '\r' or '\n' or '\f' or '\v')
                pendingSpace = normalized.Length != 0;
            // Other ASCII controls are dropped, matching the same compatibility
            // objective as ASCII-normalise rather than preserving binary noise.
        }
        return Encoding.Latin1.GetBytes(normalized.ToString());
    }

    private static byte[] NormalizeHtml(ReadOnlySpan<byte> data)
    {
        var input = Encoding.Latin1.GetString(data);
        var withoutComments = new StringBuilder(input.Length);
        var i = 0;
        while (i < input.Length)
        {
            if (i + 3 < input.Length && input[i] == '<' && input[i + 1] == '!' && input[i + 2] == '-' && input[i + 3] == '-')
            {
                var end = input.IndexOf("-->", i + 4, StringComparison.Ordinal);
                if (end < 0) break;
                i = end + 3;
                continue;
            }
            withoutComments.Append(input[i++]);
        }

        var decoded = WebUtility.HtmlDecode(withoutComments.ToString()) ?? string.Empty;
        var normalized = new StringBuilder(decoded.Length);
        var pendingSpace = false;
        foreach (var ch in decoded)
        {
            if (ch is >= '\x21' and <= '\x7e')
            {
                if (pendingSpace && normalized.Length != 0) normalized.Append(' ');
                normalized.Append(char.ToLowerInvariant(ch));
                pendingSpace = false;
            }
            else if (char.IsWhiteSpace(ch))
            {
                pendingSpace = normalized.Length != 0;
            }
        }
        return Encoding.Latin1.GetBytes(normalized.ToString());
    }

    private static bool TryEvaluateTrigger(string expression, IReadOnlyList<SubsigMatches> matches, int maxDepth)
    {
        try
        {
            return LogicalExpressionEvaluator.Evaluate(expression, matches, maxDepth);
        }
        catch (FormatException)
        {
            return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static bool TryReadByteCompareValue(
        ReadOnlySpan<byte> data,
        int offset,
        LdbByteCompareSubSignature spec,
        out long value)
    {
        value = 0;
        if (offset < 0 || offset >= data.Length || spec.ByteLength <= 0)
            return false;

        var available = data.Length - offset;
        var requested = spec.ByteLength;
        var take = Math.Min(available, requested);
        if (spec.Options.HasFlag(ByteCompareOptions.Exact) && take != requested)
            return false;

        var bytes = data.Slice(offset, take);
        if (spec.Options.HasFlag(ByteCompareOptions.Binary))
        {
            if (take != requested || take is not (1 or 2 or 4 or 8))
                return false;
            ulong raw = spec.Options.HasFlag(ByteCompareOptions.LittleEndian) ? take switch
            {
                1 => bytes[0],
                2 => BinaryPrimitives.ReadUInt16LittleEndian(bytes),
                4 => BinaryPrimitives.ReadUInt32LittleEndian(bytes),
                8 => BinaryPrimitives.ReadUInt64LittleEndian(bytes),
                _ => 0UL
            } : take switch
            {
                1 => bytes[0],
                2 => BinaryPrimitives.ReadUInt16BigEndian(bytes),
                4 => BinaryPrimitives.ReadUInt32BigEndian(bytes),
                8 => BinaryPrimitives.ReadUInt64BigEndian(bytes),
                _ => 0UL
            };
            value = unchecked((long)raw);
            return true;
        }

        var text = Encoding.ASCII.GetString(bytes).TrimStart();
        if (text.Length == 0)
            return false;
        var isHex = spec.Options.HasFlag(ByteCompareOptions.Hex) ||
                    (spec.Options.HasFlag(ByteCompareOptions.Auto) && text.StartsWith("0x", StringComparison.OrdinalIgnoreCase));
        if (isHex)
        {
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
            var digits = text.TakeWhile(Uri.IsHexDigit).ToArray();
            if (digits.Length == 0 || digits.Length > 16)
                return false;
            var hex = new string(digits);
            if (spec.Options.HasFlag(ByteCompareOptions.Exact) && digits.Length != text.Length)
                return false;
            if ((hex.Length & 1) != 0) hex = "0" + hex;
            if (spec.Options.HasFlag(ByteCompareOptions.LittleEndian))
            {
                var pairs = Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)).Reverse();
                hex = string.Concat(pairs);
            }
            return long.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out value);
        }

        var digitsDec = text.TakeWhile(c => char.IsDigit(c) || (c is '+' or '-') && c == text[0]).ToArray();
        if (digitsDec.Length == 0)
            return false;
        var decimalText = new string(digitsDec);
        if (spec.Options.HasFlag(ByteCompareOptions.Exact) && digitsDec.Length != text.Length)
            return false;
        return long.TryParse(decimalText, out value);
    }

    private static bool CompareByteValue(long value, ByteCompareComparison comparison) => comparison.Operator switch
    {
        '>' => value > comparison.Value,
        '<' => value < comparison.Value,
        '=' => value == comparison.Value,
        _ => false
    };

    private static int GetSubsigIndex(ContentSignature signature)
    {
        var hash = signature.Name.LastIndexOf('#');
        return hash >= 0 && int.TryParse(signature.Name[(hash + 1)..], out var index) ? index : 0;
    }

    private static bool OffsetAllows(string value, int position, int length)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "*") return true;
        if (value.Equals("EOF", StringComparison.OrdinalIgnoreCase)) return position == length;
        if (value.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value[4..], out var eofShift))
            return position == length - eofShift;
        if (int.TryParse(value, out var exact)) return position == exact;
        var parts = value.Split(',', 2, StringSplitOptions.TrimEntries);
        return parts.Length == 2 && int.TryParse(parts[0], out var min) && int.TryParse(parts[1], out var max)
            ? position >= min && position <= max
            : false;
    }

    internal sealed class SubsigMatches
    {
        public int Index { get; }
        public List<int> Positions { get; } = [];
        public int Count => Positions.Count;

        public SubsigMatches(int index) => Index = index;
    }

    internal static string DetectType(ReadOnlySpan<byte> data, string path)
        => DetectType(data, path, null);

    internal static string DetectType(
        ReadOnlySpan<byte> data,
        string path,
        IReadOnlyList<ClamGuard.Database.Storage.FileTypeMagicRule>? fileTypeRules)
    {
        // ClamAV's primary file-typing mechanism is File Type Magic (FTM).
        // Mode 0 direct-magic rules are tried before the built-in fallbacks.
        if (data.Length != 0 && FileTypeMagicDetector.TryDetectDirect(data, fileTypeRules, out var magicType))
        {
            // CL_TYPE_BINARY_DATA is the fallback type in libclamav, not an
            // instruction to stop file-type refinement. Keep specialized built-in
            // checks active when an FTM rule only confirms generic binary data.
            if (!magicType.Equals("OTHER", StringComparison.OrdinalIgnoreCase))
            {
                if (magicType.Equals("ZIP", StringComparison.OrdinalIgnoreCase) && TryRefineZipType(data) is { } refinedZip)
                    return refinedZip;
                return magicType;
            }
        }

        if (data.Length >= 8 && data[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return "OLE2";
        if (data.Length >= 4 && data[..4].SequenceEqual(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' })) return "ELF";
        if (data.Length >= 3 && (data[..3].SequenceEqual("FWS"u8) || data[..3].SequenceEqual("CWS"u8) || data[..3].SequenceEqual("ZWS"u8))) return "FLASH";
        if (data.Length >= 2 && data[0] == 'M' && data[1] == 'Z')
        {
            // Keep MZ as a useful type hint for truncated files, but prefer a
            // validated PE header whenever the DOS header gives us enough data.
            if (data.Length >= 0x40)
            {
                var pe = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c, 4));
                if (pe >= 0 && pe <= data.Length - 4 && BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(pe, 4)) == 0x00004550)
                    return "PE";
            }
            return "PE";
        }
        if (data.Length >= 4)
        {
            var magic = BinaryPrimitives.ReadUInt32BigEndian(data[..4]);
            if (magic is 0xFEEDFACE or 0xCEFAEDFE or 0xFEEDFACF or 0xCFFAEDFE or
                        0xCAFEBABE or 0xBEBAFECA or 0xCAFEBABF or 0xBFBAFECA) return "MACH-O";
        }
        if (LooksLikeAutoIt(data)) return "AUTOIT";
        if (LooksLikeInstallShield(data)) return "ISHIELD_MSI";
        var udfMarker = data.IndexOf("BEA01"u8);
        if (udfMarker >= 0 && udfMarker <= 32768) return "UDF";
        var utf16Html = DecodeUtf16Text(data);
        if (utf16Html is not null)
        {
            var prefix = utf16Html[..Math.Min(4096, utf16Html.Length)];
            if (prefix.IndexOf("<html", StringComparison.OrdinalIgnoreCase) >= 0 ||
                prefix.IndexOf("<!doctype", StringComparison.OrdinalIgnoreCase) >= 0)
                return "HTML_UTF16";
        }
        var mimeType = DetectMimeType(data);
        if (mimeType is not null) return mimeType;
        if (data.Length >= 5 && data[..5].SequenceEqual("%PDF-"u8)) return "PDF";
        if (data.Length >= 5 && data[..5].SequenceEqual("{\\rtf"u8)) return "RTF";
        if (data.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) == 0x223E9F78u) return "TNEF";
        if (data.Length >= 6 && data[..6].SequenceEqual("begin "u8)) return "UUENCODED";
        if (data.IndexOf("(This file must be converted with BinHex 4.0)"u8) >= 0) return "BINHEX";
        if (data.Length >= 4 && (data[..4].SequenceEqual(new byte[] { 0x50, 0x4b, 0x03, 0x04 }) ||
                                  data[..4].SequenceEqual(new byte[] { 0x50, 0x4b, 0x05, 0x06 }) ||
                                  data[..4].SequenceEqual(new byte[] { 0x50, 0x4b, 0x07, 0x08 })))
            return TryRefineZipType(data) ?? "ZIP";
        if (data.Length >= 2 && data[0] == 0x1f && data[1] == 0x8b) return "GZ";
        if (data.Length >= 3 && data[..3].SequenceEqual("BZh"u8)) return "BZ";
        if (data.Length >= 6 && data[..4].SequenceEqual("EGGA"u8) && data[4] == 0x00 && data[5] == 0x01) return "EGG";
        if (data.Length >= 4 && data[..4].SequenceEqual("ALZ\x01"u8)) return "ALZ";
        if (data.Length >= 16 && ArchiveScanner.IsSymbianSisHeader(data)) return "SIS";
        if (data.Length >= 10 &&
            BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) == 0x44445A53 &&
            BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4)) == 0x3327F088 &&
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2)) == 0x0041) return "SZDD";
        if (data.Length >= 6 && (data[..6].SequenceEqual("070701"u8) || data[..6].SequenceEqual("070702"u8))) return "CPIO_NEWC";
        if (data.Length >= 6 && data[..6].SequenceEqual("070707"u8)) return "CPIO_ODC";
        if (data.Length >= 2 && ((data[0] == 0xC7 && data[1] == 0x71) || (data[0] == 0x71 && data[1] == 0xC7))) return "CPIO_OLD";
        if (data.Length >= 8 && data[..8].SequenceEqual(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) return "7Z";
        if (data.Length >= 7 && data[..7].SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 })) return "RAR";
        if (data.Length >= 2 && data[0] == 0x60 && data[1] == 0xEA) return "ARJ";
        if (data.Length >= 4 && data[..4].SequenceEqual("MSCF"u8)) return "CAB";
        if (data.Length >= 4 && data[..4].SequenceEqual("ITSF"u8)) return "CHM";
        if (data.Length >= 4 && data[..4].SequenceEqual("xar!"u8)) return "XAR";
        if (data.Length >= 32774 && data.Slice(32769, 5).SequenceEqual("CD001"u8)) return "ISO";
        if (data.Length >= 512 && (data[^512..^508].SequenceEqual("koly"u8) || data[^512..].Slice(0, 4).SequenceEqual("koly"u8))) return "DMG";
        if (data.Length >= 6 && data[..6].SequenceEqual(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 })) return "XZ";
        if (data.Length >= 512 && data.Slice(257, 5).SequenceEqual("ustar"u8)) return "POSIX_TAR";
        if (data.Length >= 512 && LooksLikeTarHeader(data[..512])) return "OLD_TAR";
        if (data.Length >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4e && data[3] == 0x47) return "PNG";
        if (data.Length >= 3 && data[..3].SequenceEqual(new byte[] { 0xff, 0xd8, 0xff })) return "JPEG";
        if (data.Length >= 3 && data[..3].SequenceEqual("GIF"u8)) return "GIF";
        if (data.Length >= 2 && data[0] == 'B' && data[1] == 'M') return "GRAPHICS";

        // Mode 1 FTM rules are loaded into ClamAV's content matcher and are used
        // for retyping text/binary layers after the direct magic pass.
        if (fileTypeRules is not null && fileTypeRules.Count != 0)
        {
            var baseType = LooksLikeAsciiText(data) ? "ASCII" : "OTHER";
            if (FileTypeMagicDetector.TryDetectContent(data, fileTypeRules, baseType, out var contentType))
                return contentType;
        }

        var ext = Path.GetExtension(path).ToLowerInvariant();
        var extensionType = ext switch
        {
            ".exe" or ".dll" or ".sys" => "PE",
            ".pdf" => "PDF",
            ".rtf" => "RTF",
            ".hqx" => "BINHEX",
            ".tnef" => "TNEF",
            ".uue" or ".uu" => "UUENCODED",
            ".zip" or ".jar" or ".apk" or ".docx" or ".xlsx" or ".pptx" => "ZIP",
            ".rar" => "RAR",
            ".7z" => "7Z",
            ".egg" => "EGG",
            ".alz" => "ALZ",
            ".sis" => "SIS",
            ".szdd" => "SZDD",
            ".nsis" => "NULSFT",
            ".a3x" or ".a3x64" or ".au3" => "AUTOIT",
            ".ism" or ".ish" => "ISHIELD_MSI",
            ".arj" => "ARJ",
            ".cab" => "CAB",
            ".chm" => "CHM",
            ".iso" => "ISO",
            ".xar" or ".pkg" => "XAR",
            ".dmg" => "DMG",
            ".swf" => "FLASH",
            ".lha" or ".lzh" => "LHA",
            ".gz" or ".tgz" => "GZ",
            ".bz2" => "BZ",
            ".xz" => "XZ",
            ".tar" => "POSIX_TAR",
            ".cpio" => "CPIO_NEWC",
            ".doc" or ".xls" or ".ppt" => "OLE2",
            ".htm" or ".html" => "HTML",
            ".eml" or ".msg" => "MAIL",
            ".mht" or ".mhtml" => "MHTML",
            ".class" => "JAVA",
            ".txt" or ".log" or ".csv" or ".xml" or ".json" or ".js" or ".css" => "ASCII",
            _ => "Unknown"
        };
        if (!extensionType.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) return extensionType;
        return LooksLikeAsciiText(data) ? "ASCII" : "Unknown";
    }

    private static string? TryRefineZipType(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        ReadOnlySpan<byte> localHeader = new byte[] { 0x50, 0x4b, 0x03, 0x04 };
        var searchOffset = 0;
        var checkedHeaders = 0;
        while (checkedHeaders < 3 && searchOffset < data.Length)
        {
            var relative = data[searchOffset..].IndexOf(localHeader);
            if (relative < 0) break;
            var header = searchOffset + relative;
            if (header > data.Length - 30) break;

            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(header + 26, 2));
            var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(header + 28, 2));
            var nameStart = header + 30;
            if (nameLength > data.Length - nameStart) break;
            var name = Encoding.UTF8.GetString(data.Slice(nameStart, nameLength)).Replace('\\', '/');

            if (name.StartsWith("word/", StringComparison.OrdinalIgnoreCase)) return "OOXML_WORD";
            if (name.StartsWith("xl/", StringComparison.OrdinalIgnoreCase)) return "OOXML_XL";
            if (name.StartsWith("ppt/", StringComparison.OrdinalIgnoreCase)) return "OOXML_PPT";
            if (name.Equals("Contents/content.hpf", StringComparison.OrdinalIgnoreCase)) return "OOXML_HWP";

            checkedHeaders++;
            var next = nameStart + nameLength + extraLength;
            searchOffset = next > header ? Math.Min(next, data.Length) : header + 4;
        }
        return null;
    }

    private static string? DetectMimeType(ReadOnlySpan<byte> data)
    {
        var sample = Encoding.Latin1.GetString(data[..Math.Min(data.Length, 64 * 1024)]);
        var headersEnd = sample.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headersEnd < 0) headersEnd = sample.IndexOf("\n\n", StringComparison.Ordinal);
        if (headersEnd < 0) headersEnd = Math.Min(sample.Length, 16 * 1024);
        var headers = sample[..headersEnd];
        var hasMime = Regex.IsMatch(headers, @"(?im)^\s*MIME-Version\s*:");
        var hasContentType = Regex.IsMatch(headers, @"(?im)^\s*Content-Type\s*:");
        var hasMailHeader = Regex.IsMatch(headers, @"(?im)^\s*(From|Received|Message-Id)\s*:");
        if (!hasContentType || (!hasMime && !hasMailHeader)) return null;
        return headers.IndexOf("multipart/related", StringComparison.OrdinalIgnoreCase) >= 0 ? "MHTML" : "MAIL";
    }

    private static bool LooksLikeAutoIt(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> magic = new byte[] { 0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D, 0x41, 0x55, 0x53, 0x21, 0x45, 0x41, 0x30 };
        for (var i = 0; i + magic.Length + 1 < data.Length; i++)
        {
            if (!data.Slice(i, magic.Length).SequenceEqual(magic)) continue;
            var version = data[i + magic.Length];
            if (version is 0x35 or 0x36) return true;
        }
        return false;
    }

    private static bool LooksLikeInstallShield(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> prefix = "InstallShield\0"u8;
        for (var i = 0; i + prefix.Length + 0x120 < data.Length; i++)
        {
            if (!data.Slice(i, prefix.Length).SequenceEqual(prefix)) continue;
            var p = i + prefix.Length + 292;
            if (p + 8 + 16 + 4 > data.Length) return false;
            if (data[p] != 0x06 || !data.Slice(p + 1, 7).SequenceEqual(new byte[7])) continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(p + 24, 4)) == 1) return true;
        }
        return false;
    }

    private static bool LooksLikeTarHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < 512) return false;
        var nameEnd = header[..100].IndexOf((byte)0);
        if (nameEnd == 0) return false;
        var storedText = Encoding.ASCII.GetString(header.Slice(148, 8)).TrimEnd('\0').Trim();
        if (!long.TryParse(storedText, System.Globalization.NumberStyles.Integer, null, out var stored)) return false;
        var sum = 0L;
        for (var i = 0; i < 512; i++) sum += i is >= 148 and < 156 ? 32 : header[i];
        return stored > 0 && sum == stored;
    }

    private static bool LooksLikeAsciiText(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data.Length > 4 * 1024 * 1024) return false;
        var printable = 0;
        var suspicious = 0;
        foreach (var b in data)
        {
            if (b == 0) return false;
            if (b is >= 0x20 and <= 0x7e || b is 0x09 or 0x0a or 0x0d or 0x0c) printable++;
            else if (b < 0x20) suspicious++;
            else suspicious++;
        }
        return printable >= data.Length * 0.90 && suspicious <= data.Length * 0.10;
    }

    private static string DetectType(string path) => DetectType(ReadOnlySpan<byte>.Empty, path);
}
