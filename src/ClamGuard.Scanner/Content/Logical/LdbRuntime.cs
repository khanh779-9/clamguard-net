using System.Buffers.Binary;
using System.Collections.Frozen;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal static class LdbRuntime
{
    public static LdbScanContext CreateContext(
        ReadOnlySpan<byte> data,
        string fileType,
        IReadOnlyList<string>? parentTypes = null,
        bool retyped = false,
        ScanOptions? scanOptions = null)
    {
        var parserDisabled = scanOptions is not null &&
            ((ScanTypePolicy.IsPe(fileType) && !scanOptions.ScanPE) ||
             (ScanTypePolicy.IsElf(fileType) && !scanOptions.ScanELF));
        var executable = parserDisabled ? null : ExecutableInspector.TryInspect(data, fileType);
        return new LdbScanContext(fileType, data.Length, executable, parentTypes ?? [], retyped);
    }

    public static bool MatchesTarget(LdbTargetDescription? target, LdbScanContext ctx)
    {
        if (target is null)
            return true;
        if (target.Target != SignatureTargetType.Any && !TargetMatchesFileType(target.Target, ctx.FileType))
            return false;
        if (target.MinFileSize is not null && ctx.FileSize < target.MinFileSize.Value)
            return false;
        if (target.MaxFileSize is not null && ctx.FileSize > target.MaxFileSize.Value)
            return false;

        if ((target.MinEntryPoint is not null || target.MaxEntryPoint is not null ||
             target.MinSections is not null || target.MaxSections is not null) && ctx.Executable is null)
            return false;

        if (target.MinEntryPoint is not null && ctx.Executable!.EntryPoint < target.MinEntryPoint.Value)
            return false;
        if (target.MaxEntryPoint is not null && ctx.Executable!.EntryPoint > target.MaxEntryPoint.Value)
            return false;
        if (target.MinSections is not null && ctx.Executable!.NumberOfSections < target.MinSections.Value)
            return false;
        if (target.MaxSections is not null && ctx.Executable!.NumberOfSections > target.MaxSections.Value)
            return false;

        if (target.Container is not null)
        {
            // CL_TYPE_ANY is a root-only constraint. A concrete container type
            // must be the immediate parent of the scanned object.
            if (target.Container.Equals("ANY", StringComparison.OrdinalIgnoreCase))
            {
                if (ctx.ParentTypes.Count != 0)
                    return false;
            }
            else if (ctx.ParentTypes.Count == 0 || !FileTypeMatches(target.Container, ctx.ParentTypes[^1]))
            {
                return false;
            }
        }

        if (target.Intermediates is not null)
        {
            if (target.Intermediates.Count > 16 || ctx.ParentTypes.Count < target.Intermediates.Count)
                return false;

            // The database stores intermediates top-down; the last entry is the
            // immediate container. Match the requested suffix of the actual
            // parent chain so additional outer containers are permitted.
            var actualStart = ctx.ParentTypes.Count - target.Intermediates.Count;
            for (var i = 0; i < target.Intermediates.Count; i++)
            {
                var expected = target.Intermediates[i];
                if (!FileTypeMatches(expected, ctx.ParentTypes[actualStart + i]))
                    return false;
            }
        }

        if ((target.IconGroup1 is not null || target.IconGroup2 is not null) && ctx.Executable is null)
            return false;

        return true;
    }

    // Precomputed bitmask table mapping uppercase file type to bitwise target mask.
    // Each target T (0..14) corresponds to bit (1 << T). Target 0 (Any) matches every type.
    private static readonly Dictionary<string, uint> FileTypeToTargetMask = new(StringComparer.OrdinalIgnoreCase)
    {
        ["PE"] = (1u << 0) | (1u << 1),
        ["OLE2"] = (1u << 0) | (1u << 2),
        ["HTML"] = (1u << 0) | (1u << 3),
        ["MAIL"] = (1u << 0) | (1u << 4),
        ["GRAPHICS"] = (1u << 0) | (1u << 5),
        ["GIF"] = (1u << 0) | (1u << 5),
        ["PNG"] = (1u << 0) | (1u << 5),
        ["JPEG"] = (1u << 0) | (1u << 5),
        ["TIFF"] = (1u << 0) | (1u << 5),
        ["ELF"] = (1u << 0) | (1u << 6),
        ["ASCII"] = (1u << 0) | (1u << 7),
        ["MACH-O"] = (1u << 0) | (1u << 9),
        ["MACHO"] = (1u << 0) | (1u << 9),
        ["MACHO_UNIBIN"] = (1u << 0) | (1u << 9),
        ["PDF"] = (1u << 0) | (1u << 10),
        ["FLASH"] = (1u << 0) | (1u << 11),
        ["JAVA"] = (1u << 0) | (1u << 12),
        ["INTERNAL"] = (1u << 0) | (1u << 13),
        ["OTHER"] = (1u << 0) | (1u << 14)
    };

    // Precomputed O(1) table of compatible container aliases (expected -> actuals)
    private static readonly Dictionary<string, System.Collections.Frozen.FrozenSet<string>> ContainerAliasMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ZIP"] = new[] { "ZIP" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["OLE2"] = new[] { "OLE2" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["TAR"] = new[] { "TAR", "POSIX_TAR", "OLD_TAR" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MSSZDD"] = new[] { "MSSZDD", "SZDD" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MSCAB"] = new[] { "MSCAB", "CAB" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MSCHM"] = new[] { "MSCHM", "CHM" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MSOLE2"] = new[] { "MSOLE2", "OLE2" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["ISO9660"] = new[] { "ISO9660", "ISO" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MSEXE"] = new[] { "MSEXE", "PE" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MACHO_UNIBIN"] = new[] { "MACHO_UNIBIN", "MACH-O" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["ZIPSFX"] = new[] { "ZIPSFX", "ZIP" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["RARSFX"] = new[] { "RARSFX", "RAR" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["ARJSFX"] = new[] { "ARJSFX", "ARJ" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["CABSFX"] = new[] { "CABSFX", "CAB" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["7ZSFX"] = new[] { "7ZSFX", "7Z" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["EGGSFX"] = new[] { "EGGSFX", "EGG" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["SWF"] = new[] { "SWF", "FLASH" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        ["MHTML"] = new[] { "MHTML" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase)
    };

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static bool TargetMatchesFileType(SignatureTargetType target, LdbScanContext ctx) => TargetMatchesFileType((int)target, ctx.FileType);

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static bool TargetMatchesFileType(SignatureTargetType target, string fileType) => TargetMatchesFileType((int)target, fileType);

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static bool TargetMatchesFileType(int target, LdbScanContext ctx) => TargetMatchesFileType(target, ctx.FileType);

    /// <summary>
    /// O(1) bitmask test: target index (0..14) tested against precomputed mask for fileType.
    /// Target 0 (Any) always returns true. Target 8 (Unused8) always returns false.
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    public static bool TargetMatchesFileType(int target, string fileType)
    {
        if (target == 0) return true;
        if ((uint)target > 14 || target == 8) return false;
        return FileTypeToTargetMask.TryGetValue(fileType, out var mask) && (mask & (1u << target)) != 0;
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static bool FileTypeMatches(string expected, string actual)
    {
        if (expected.Equals("ANY", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals(actual, StringComparison.OrdinalIgnoreCase)) return true;

        // ClamAV may assign a specialized type to a ZIP-backed document while
        // container signatures still refer to the underlying ZIP/OLE container.
        if (expected.Equals("ZIP", StringComparison.OrdinalIgnoreCase) &&
            actual.StartsWith("OOXML_", StringComparison.OrdinalIgnoreCase)) return true;
        if (expected.Equals("OLE2", StringComparison.OrdinalIgnoreCase) &&
            actual.StartsWith("HWP", StringComparison.OrdinalIgnoreCase)) return true;

        if (ContainerAliasMap.TryGetValue(expected, out var set))
            return set.Contains(actual);

        return false;
    }

    public static List<LdbOffsetRange> ResolveOffset(string expression, LdbScanContext ctx, int macroIndex = -1, IReadOnlyDictionary<int, List<int>>? macroPositions = null)
    {
        expression = string.IsNullOrWhiteSpace(expression) ? "*" : expression.Trim();

        // NDB/LDB floating offsets use `base,maxshift`. Parse the shift first so
        // absolute offsets such as `123,8` work as intended instead of falling
        // through to the executable-only relative-offset branch.
        var maxShift = 0;
        var comma = expression.IndexOf(',');
        if (comma >= 0)
        {
            if (expression.IndexOf(',', comma + 1) >= 0 ||
                !int.TryParse(expression[(comma + 1)..].Trim(), out maxShift) || maxShift < 0)
                return [];
            expression = expression[..comma].Trim();
        }

        if (expression == "*")
            return [new(0, checked((int)Math.Min(int.MaxValue, Math.Max(0, ctx.FileSize - 1))))];

        if (expression.Equals("VI", StringComparison.OrdinalIgnoreCase))
            return ctx.Executable?.VersionInfoRegions.Select(x => new LdbOffsetRange(x.Start, x.End)).ToList() ?? [];

        if (expression.Equals("EOF", StringComparison.OrdinalIgnoreCase))
        {
            var p = ctx.FileSize;
            return p >= 0 && p <= int.MaxValue ? [new((int)p, (int)p)] : [];
        }

        if (expression.StartsWith("EOF-", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[4..], out var eofShift))
        {
            if (eofShift < 0) return [];
            var p = ctx.FileSize - eofShift;
            return p >= 0 && p <= int.MaxValue ? [new((int)p, (int)Math.Min(int.MaxValue, p + (long)maxShift))] : [];
        }

        if (expression.StartsWith("$", StringComparison.Ordinal) && expression.EndsWith("$") && int.TryParse(expression[1..^1], out var group) && group is >= 0 and < 32)
        {
            var last = macroPositions is not null && macroPositions.TryGetValue(group, out var positions) && positions.Count != 0
                ? positions.Max()
                : -1;
            return last >= 0 ? [new(last, (int)Math.Min(int.MaxValue, (long)last + maxShift))] : [];
        }

        if (int.TryParse(expression, out var absolute))
            return absolute >= 0 ? [new(absolute, (int)Math.Min(int.MaxValue, (long)absolute + maxShift))] : [];

        if (ctx.Executable is null)
            return [];

        if (expression.StartsWith("EP+", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var epPlus))
            return ExactWithShift(ctx.Executable.EntryPoint, epPlus, maxShift);
        if (expression.StartsWith("EP-", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var epMinus))
            return ExactWithShift(ctx.Executable.EntryPoint, -epMinus, maxShift);
        if (expression.StartsWith("SL+", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[3..], out var slPlus))
        {
            var last = ctx.Executable.Sections.LastOrDefault();
            return last is null ? [] : ExactWithShift(last.RawOffset, slPlus, maxShift);
        }
        if (expression.StartsWith("SE", StringComparison.OrdinalIgnoreCase) && int.TryParse(expression[2..], out var seIndex))
        {
            if ((uint)seIndex >= (uint)ctx.Executable.Sections.Count) return [];
            var section = ctx.Executable.Sections[seIndex];
            if (section.RawSize <= 0) return [];
            var start = section.RawOffset;
            var end = section.RawOffset + section.RawSize - 1L + maxShift;
            var maxBound = section.RawOffset + section.RawSize;
            if (start < 0 || start > int.MaxValue || end < start) return [];
            return [new((int)start, (int)Math.Min(int.MaxValue, end), (int)Math.Min(int.MaxValue, maxBound))];
        }
        if (expression.StartsWith("S", StringComparison.OrdinalIgnoreCase))
        {
            var plus = expression.IndexOf('+');
            if (plus > 1 && int.TryParse(expression[1..plus], out var sIndex) && int.TryParse(expression[(plus + 1)..], out var sShift))
            {
                if ((uint)sIndex >= (uint)ctx.Executable.Sections.Count) return [];
                return ExactWithShift(ctx.Executable.Sections[sIndex].RawOffset, sShift, maxShift);
            }
        }
        return [];
    }

    private static List<LdbOffsetRange> ExactWithShift(long baseOffset, int relative, int maxShift)
    {
        var start = baseOffset + relative;
        if (start < 0 || start > int.MaxValue) return [];
        var endLong = start + (long)Math.Max(0, maxShift);
        if (endLong < start) return [];
        return [new((int)start, (int)Math.Min(int.MaxValue, endLong))];
    }

    public static bool HasIconGroup(ReadOnlySpan<byte> data, LdbScanContext ctx, string? group1, string? group2, IconDatabase? database)
    {
        if (database is null || ctx.Executable is null || ctx.FileType != "PE") return false;
        var groups = ctx.Executable.IconGroups;
        if (groups.Count == 0) return false;

        var wanted1 = string.IsNullOrEmpty(group1) ? "*" : group1;
        var wanted2 = string.IsNullOrEmpty(group2) ? "*" : group2;
        foreach (var iconGroup in groups)
        {
            foreach (var icon in iconGroup.Icons)
            {
                if (!IconDecoder.TryDecode(icon, out var image)) continue;
                var prepared = IconMetrics.PrepareForClam(image);
                var side = prepared.Width;
                foreach (var dbEntry in database.Entries.Where(e => GroupMatches(wanted1, e.Group1) && GroupMatches(wanted2, e.Group2) && e.Metric.Side == side))
                    if (IconMetrics.Matches(prepared, dbEntry.Metric, alreadyPrepared: true)) return true;
            }
        }
        return false;
    }

    private static bool GroupMatches(string wanted, string actual)
        => wanted == "*" || wanted.Equals(actual, StringComparison.Ordinal);


    public static bool FuzzyImageMatches(ReadOnlySpan<byte> data, byte[] expectedHash)
    {
        if (expectedHash.Length != 8) return false;
        if (!ImageDecoder.TryDecode(data, out var image)) return false;
        var hash = ImageFuzzyHasher.Compute(image);
        return hash.AsSpan().SequenceEqual(expectedHash);
    }

    internal static IReadOnlyList<(int Offset, int Length)> GetMachOFatSlices(ReadOnlySpan<byte> data)
        => ExecutableInspector.GetMachOFatSlices(data);
}
