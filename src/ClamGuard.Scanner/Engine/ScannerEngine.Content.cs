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
    internal static ScanResult ScanBuffer(byte[] buffer, int length, CompiledState state, ScanOptions options, string path, CancellationToken cancellationToken)
    {
        var data = buffer.AsSpan(0, length);
        var fileType = DetectType(data, path, state.Database.SpecialDatabases.FileTypes);
        var detections = new List<Detection>();
        if (ScanTypePolicy.ShouldRunSpecializedPreRaw(fileType, options))
        {
            detections.AddRange(SpecializedFileHandlers.ScanPreRaw(data, fileType, state, options, path, cancellationToken));
            if (!options.CollectAllMatches && options.HasBlockingDetections(detections))
                return CreateDetectionResult(path, fileType, detections, length, TimeSpan.Zero, state.Database.Databases.FirstOrDefault(), options);
        }
        var ndb = state.Database.NdbSignatures;
        var applicableRawNdb = ndb
            .Where(x => x.MacroGroup is null && LdbRuntime.TargetMatchesFileType(x.Target, fileType))
            .ToArray();
        var streamableNdb = applicableRawNdb
            .Where(x => ScanTypePolicy.CanStreamRawNdb(x, fileType))
            .ToHashSet();
        var fixedNdbCandidateRules = applicableRawNdb
            .Where(x => !streamableNdb.Contains(x) &&
                        x.Pattern.IsFixed &&
                        !ScanTypePolicy.IsNormalizedTarget(x.Target))
            .ToHashSet();
        var matchedFixedNdbCandidates = new HashSet<NdbSignature>();
        var useCombinedNdbIndex = streamableNdb.Count != 0 || fixedNdbCandidateRules.Count != 0;

        detections.AddRange(state.Compiled.Match(
            data,
            "compiled-database",
            includeNdb: useCombinedNdbIndex,
            collectAllMatches: (options.CollectAllMatches || !options.DetectPUA),
            ndbFilter: useCombinedNdbIndex ? streamableNdb.Contains : null,
            ndbPatternCandidates: matchedFixedNdbCandidates,
            ndbCandidateFilter: fixedNdbCandidateRules.Contains,
            targetGroup: SignatureTargetGroups.FromFileType(fileType)));
        detections.AddRange(EvaluateNdb(
            applicableRawNdb.Where(x =>
                !streamableNdb.Contains(x) &&
                (!x.Pattern.IsFixed ||
                 ScanTypePolicy.IsNormalizedTarget(x.Target) ||
                 matchedFixedNdbCandidates.Contains(x))),
            data,
            options.Limits,
            fileType,
            cancellationToken,
            scanOptions: options));
        detections.AddRange(EvaluateLogical(state.Database.LogicalSignatures, ndb, data, options.Limits, fileType, state.Database.IconDatabase, [], cancellationToken, scanState: state, scanOptions: options));
        if (options.ScanPE && ScanTypePolicy.IsPe(fileType))
            detections.AddRange(PeSpecializedMatcher.Match(data, state, options.Limits, cancellationToken));
        foreach (var contentScanner in options.ContentScanners)
            detections.AddRange(contentScanner.Scan(data, path, cancellationToken));
        if (options.ScanPE && ScanTypePolicy.IsPe(fileType))
            detections.AddRange(PeOverlayScanner.ScanPeOverlay(data, state, options, cancellationToken));
        if (ScanTypePolicy.IsMachO(fileType) && ScanTypePolicy.LooksLikeMachOFat(data))
            detections.AddRange(ScanMachOFatSlices(data, state, options, cancellationToken));
        if (ScanTypePolicy.IsArchiveContainer(fileType) && ScanTypePolicy.ShouldParseContainer(fileType, options))
            detections.AddRange(ArchiveScanner.Scan(data, path, state, options, [], 0, cancellationToken));
        var trusted = state.Compiled.MatchesFalsePositive(data);
        return CreateDetectionResult(path, fileType, detections, length, TimeSpan.Zero, state.Database.Databases.FirstOrDefault(), options, trusted);
    }

    private static IReadOnlyList<Detection> ScanMachOFatSlices(
        ReadOnlySpan<byte> whole,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (whole.Length <= 0) return [];
        var slices = LdbRuntime.GetMachOFatSlices(whole);
        if (slices.Count == 0) return [];

        var results = new List<Detection>();
        var ndb = state.Database.NdbSignatures;
        var logical = state.Database.LogicalSignatures;

        foreach (var (offset, sliceLength) in slices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var slice = whole.Slice(offset, sliceLength);
            if (state.Compiled.MatchesFalsePositive(slice))
                continue;
            var type = DetectType(slice, "embedded.macho", state.Database.SpecialDatabases.FileTypes);

            foreach (var hit in state.Compiled.Match(slice, $"mach-o-slice@{offset}", includeNdb: false,
                         collectAllMatches: (options.CollectAllMatches || !options.DetectPUA)))
                results.Add(hit.Offset is null
                    ? hit
                    : hit with { Offset = hit.Offset.Value + offset });

            foreach (var hit in EvaluateNdb(ndb, slice, options.Limits, type, cancellationToken, options))
                results.Add(hit.Offset is null
                    ? hit
                    : hit with { Offset = hit.Offset.Value + offset });

            foreach (var hit in EvaluateLogical(logical, ndb, slice, options.Limits, type, state.Database.IconDatabase, ["MACHO_UNIBIN"], cancellationToken, scanState: state, scanOptions: options))
                results.Add(hit.Offset is null
                    ? hit
                    : hit with { Offset = hit.Offset.Value + offset });

            if (options.ScanPE && ScanTypePolicy.IsPe(type))
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
        CancellationToken cancellationToken,
        ScanOptions? scanOptions = null)
    {
        var results = new List<Detection>();
        if (data.IsEmpty) return results;

        foreach (var signature in signatures)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (signature.MacroGroup is not null)
                continue; // Macro members are consumed by LDB macro subsignatures, not alerts.

            var normalized = NormalizeTargetData(data, fileType, signature.Target, scanOptions);
            ReadOnlySpan<byte> scanData = data;
            if (normalized is not null) scanData = normalized;
            var context = LdbRuntime.CreateContext(scanData, fileType, scanOptions: scanOptions);
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

    // Group-evaluation wrappers used by the concurrent signature-group pass in
    // ScanAsync: ReadOnlySpan parameters cannot be captured by Task.Run closures,
    // so the buffered entry points receive byte[] and re-slice internally.
    internal static IReadOnlyList<Detection> EvaluateNdbBuffered(
        NdbSignature[] signatures,
        byte[] data,
        ScanLimits limits,
        string fileType,
        CancellationToken cancellationToken,
        ScanOptions? scanOptions)
        => EvaluateNdb(signatures, data, limits, fileType, cancellationToken, scanOptions);

    internal static IReadOnlyList<Detection> EvaluateLogicalBuffered(
        LogicalSignature[] signatures,
        NdbSignature[] ndbSignatures,
        byte[] data,
        ScanLimits limits,
        string fileType,
        IconDatabase? iconDatabase,
        CancellationToken cancellationToken,
        CompiledState scanState,
        ScanOptions? scanOptions)
        => EvaluateLogical(signatures, ndbSignatures, data, limits, fileType, iconDatabase, [], cancellationToken, scanState: scanState, scanOptions: scanOptions);

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
        var baseContext = LdbRuntime.CreateContext(data, fileType, parentTypes, retyped, scanOptions);
        // ClamAV gates PCRE signature support behind PCRE_CONF_SUPPORT and the
        // PE icon check behind PE_CONF_MATCHICON; a missing engine state keeps
        // both enabled (matching the all-on dconf defaults).
        var dconf = scanState?.Database.DynamicConfiguration;
        var pcreSupported = dconf is null || (dconf.Pcre & DynamicConfigFlags.PcreSupport) != 0;
        var matchIconEnabled = dconf is null || (dconf.Pe & DynamicConfigFlags.PeMatchIcon) != 0;
        // A shared compact fragment index rejects pure-AND logical signatures
        // whose required fixed-byte anchor cannot be present. Full LDB matching
        // below still checks every subsignature, offset, modifier, and expression.
        var canPreFilterByFileType = parentTypes.Count == 0 && !retyped;

        var dataLength = data.Length;

        var signatureArray = (signatures as LogicalSignature[] ?? signatures.ToArray())
            .Where(signature =>
                (!canPreFilterByFileType || LdbRuntime.TargetMatchesFileType(signature.Target?.Target ?? 0, fileType)) &&
                (signature.Target?.MinFileSize is null || dataLength >= signature.Target.MinFileSize.Value) &&
                (signature.Target?.MaxFileSize is null || dataLength <= signature.Target.MaxFileSize.Value))
            .ToArray();
        var logicalCandidates = scanState?.Compiled.FindLogicalCandidates(data);
        bool CanStillMatch(LogicalSignature signature)
            => logicalCandidates is null || scanState is null ||
               !scanState.Compiled.IsLogicalSignaturePrefiltered(signature) ||
               logicalCandidates.Contains(signature);

        var activeSignatures = new List<LogicalSignature>(signatureArray.Length);
        foreach (var signature in signatureArray)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (CanStillMatch(signature))
                activeSignatures.Add(signature);
        }

        if (activeSignatures.Count == 0)
            return results;

        // Only compute macro groups required by LDB rules that survived the
        // mandatory-anchor prefilter (or are not safely indexable). Scanning every
        // NDB macro group against the whole file first caused repeated full-file
        // searches unrelated to any LDB rule that could still match.
        var requiredMacroGroups = new HashSet<int>();
        foreach (var signature in activeSignatures)
        {
            if (signature.MacroSubSignatures is null)
                continue;
            foreach (var macro in signature.MacroSubSignatures.Values)
                requiredMacroGroups.Add(macro.MacroGroup);
        }

        var macroPositions = new Dictionary<int, List<int>>();
        var macroMembers = requiredMacroGroups.Count == 0
            ? new Dictionary<int, NdbSignature[]>()
            : ndbSignatures
                .Where(x => x.MacroGroup.HasValue && requiredMacroGroups.Contains(x.MacroGroup.Value))
                .GroupBy(x => x.MacroGroup!.Value)
                .ToDictionary(x => x.Key, x => x.ToArray());
        if (macroMembers.Count != 0)
        {
            foreach (var pair in macroMembers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var positions = new List<int>();
                foreach (var member in pair.Value)
                {
                    var normalized = NormalizeTargetData(data, fileType, member.Target, scanOptions);
                    ReadOnlySpan<byte> memberData = data;
                    if (normalized is not null) memberData = normalized;
                    var memberContext = normalized is null ? baseContext : LdbRuntime.CreateContext(memberData, fileType, parentTypes, retyped, scanOptions);
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

        foreach (var signature in activeSignatures)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var target = signature.Target;
            var normalized = NormalizeTargetData(data, fileType, target?.Target ?? 0, scanOptions);
            ReadOnlySpan<byte> matchData = data;
            if (normalized is not null) matchData = normalized;
            var context = normalized is null ? baseContext : LdbRuntime.CreateContext(matchData, fileType, parentTypes, retyped, scanOptions);
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

            if (signature.FuzzyImageSubSignatures is not null &&
                (scanOptions is null || (scanOptions.ScanImage && scanOptions.ScanImageFuzzyHash)))
            {
                foreach (var pair in signature.FuzzyImageSubSignatures)
                {
                    cancellationToken.ThrowIfCancellationRequested();
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
                    if (scanOptions is not null && !scanOptions.CollectAllMatches && results.Count != 0)
                        return results;
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
            if (scanOptions is not null && !scanOptions.CollectAllMatches)
                return results;
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

}
