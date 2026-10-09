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
        // A shared compact fragment index rejects pure-AND logical signatures
        // whose required fixed-byte anchor cannot be present. Full LDB matching
        // below still checks every subsignature, offset, modifier, and expression.
        var logicalCandidates = scanState?.Compiled.FindLogicalCandidates(data);
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
            if (logicalCandidates is not null &&
                scanState is not null &&
                scanState.Compiled.IsLogicalSignaturePrefiltered(signature) &&
                !logicalCandidates.Contains(signature))
                continue;

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

}
