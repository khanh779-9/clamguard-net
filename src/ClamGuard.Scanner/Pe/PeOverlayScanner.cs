using ClamGuard.Core;
using ClamGuard.Database;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

/// <summary>
/// Quét vùng Overlay của PE file (full-buffer và streaming từ file).
/// </summary>
internal static class PeOverlayScanner
{
    internal static async Task<IReadOnlyList<Detection>> ScanPeOverlayFromFileAsync(
        string path,
        long fileLength,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (fileLength <= 0) return [];

        var prefixLength = (int)Math.Min(fileLength, 4L * 1024 * 1024);
        var prefix = new byte[prefixLength];
        await using (var input = File.OpenRead(path))
        {
            var read = 0;
            while (read < prefix.Length)
            {
                var n = await input.ReadAsync(prefix.AsMemory(read), cancellationToken);
                if (n == 0) break;
                read += n;
            }
            if (read != prefix.Length) prefix = prefix[..read];
        }

        if (!PeSpecializedMatcher.TryGetOverlayRange(prefix, fileLength, out var overlayOffset, out var overlaySize) ||
            overlaySize <= 0 || overlaySize > options.Limits.MaxEmbeddedStreamSize ||
            overlaySize > int.MaxValue)
            return [];

        var overlay = new byte[(int)overlaySize];
        await using (var input = File.OpenRead(path))
        {
            input.Position = overlayOffset;
            var read = 0;
            while (read < overlay.Length)
            {
                var n = await input.ReadAsync(overlay.AsMemory(read), cancellationToken);
                if (n == 0) return [];
                read += n;
            }
        }

        return ScanPeOverlayData(overlay, overlayOffset, state, options, cancellationToken);
    }

    internal static IReadOnlyList<Detection> ScanPeOverlayData(
        ReadOnlySpan<byte> overlay,
        long overlayOffset,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (overlay.Length == 0 || overlay.Length > options.Limits.MaxEmbeddedStreamSize)
            return [];
        if (state.Compiled.MatchesFalsePositive(overlay))
            return [];

        var parentTypes = new[] { "PE" };
        var path = $"overlay@{overlayOffset}";
        var fileType = ScannerEngine.DetectType(overlay, path, state.Database.SpecialDatabases.FileTypes);
        var results = new List<Detection>();

        foreach (var hit in state.Compiled.Match(overlay, path, includeNdb: false))
            results.Add(hit.Offset is null ? hit : hit with { Offset = hit.Offset.Value + overlayOffset });

        var ndb = state.Database.Signatures.OfType<NdbSignature>().ToArray();
        foreach (var hit in ScannerEngine.EvaluateNdb(ndb, overlay, options.Limits, fileType, cancellationToken))
            results.Add(hit.Offset is null ? hit : hit with { Offset = hit.Offset.Value + overlayOffset });

        foreach (var hit in ScannerEngine.EvaluateLogical(state.Database.Signatures.OfType<LogicalSignature>(), ndb, overlay, options.Limits, fileType, state.Database.IconDatabase, parentTypes, cancellationToken, scanState: state, scanOptions: options))
            results.Add(hit.Offset is null ? hit : hit with { Offset = hit.Offset.Value + overlayOffset });

        if (ScanTypePolicy.IsPe(fileType))
        {
            foreach (var hit in PeSpecializedMatcher.Match(overlay, state, options.Limits, cancellationToken))
                results.Add(hit.Offset is null ? hit : hit with { Offset = hit.Offset.Value + overlayOffset });
        }

        foreach (var contentScanner in options.ContentScanners)
        {
            foreach (var hit in contentScanner.Scan(overlay, path, cancellationToken))
                results.Add(hit.Offset is null ? hit : hit with { Offset = hit.Offset.Value + overlayOffset });
        }

        if (ScanTypePolicy.IsArchiveContainer(fileType))
            results.AddRange(ArchiveScanner.Scan(overlay, path, state, options, parentTypes, 1, cancellationToken));

        return results;
    }

    internal static IReadOnlyList<Detection> ScanPeOverlay(
        ReadOnlySpan<byte> data,
        CompiledState state,
        ScanOptions options,
        CancellationToken cancellationToken)
    {
        if (!PeSpecializedMatcher.TryGetOverlay(data, out var overlay, out var overlayOffset))
            return [];
        return ScanPeOverlayData(overlay, overlayOffset, state, options, cancellationToken);
    }
}
