using System.Collections.Concurrent;
using ClamGuard.Database;
using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

/// <summary>
/// Immutable, per-database-generation view of the signature set with the
/// type-classified NDB rule sets that ScannerEngine needs for every file.
/// Built once per database generation instead of once per scanned file, so
/// folder scans do not re-enumerate the full signature list for each target.
/// </summary>
internal sealed class PreparedScanRules
{
    private readonly ConcurrentDictionary<string, FileTypeNdbRules> _ndbByFileType = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, LogicalSignature[]> _logicalByFileType = new(StringComparer.OrdinalIgnoreCase);

    private PreparedScanRules(
        NdbSignature[] ndbSignatures,
        LogicalSignature[] logicalSignatures,
        HashSignature[] peSectionRules,
        HashSignature[] peImportRules)
    {
        NdbSignatures = ndbSignatures;
        LogicalSignatures = logicalSignatures;
        PeSectionRules = peSectionRules;
        PeImportRules = peImportRules;
    }

    public NdbSignature[] NdbSignatures { get; }
    public LogicalSignature[] LogicalSignatures { get; }
    public HashSignature[] PeSectionRules { get; }
    public HashSignature[] PeImportRules { get; }

    public static PreparedScanRules Build(CompiledState state)
    {
        var ndb = new List<NdbSignature>();
        var logical = new List<LogicalSignature>();
        var sections = new List<HashSignature>();
        var imports = new List<HashSignature>();
        foreach (var signature in state.Database.Signatures)
        {
            switch (signature)
            {
                case NdbSignature n:
                    ndb.Add(n);
                    break;
                case LogicalSignature l:
                    logical.Add(l);
                    break;
                case HashSignature h:
                    if (PeSpecializedMatcher.IsSectionHash(h.SourceFile)) sections.Add(h);
                    else if (PeSpecializedMatcher.IsImportHash(h.SourceFile)) imports.Add(h);
                    break;
            }
        }

        return new PreparedScanRules([.. ndb], [.. logical], [.. sections], [.. imports]);
    }

    public FileTypeNdbRules GetNdbRules(string fileType)
        => _ndbByFileType.GetOrAdd(fileType, static (type, self) => FileTypeNdbRules.Build(self.NdbSignatures, type), this);

    /// <summary>Logical signatures whose target flags match the file type.</summary>
    public LogicalSignature[] GetLogicalSignatures(string fileType)
        => _logicalByFileType.GetOrAdd(fileType, static (type, self) =>
            [.. self.LogicalSignatures.Where(x => LdbRuntime.TargetMatchesFileType(x.Target?.Target ?? 0, type))], this);
}

/// <summary>NDB rules classified once per file type instead of once per scanned file.</summary>
internal sealed class FileTypeNdbRules
{
    private FileTypeNdbRules(
        NdbSignature[] applicableRaw,
        HashSet<NdbSignature> streamable,
        HashSet<NdbSignature> fixedCandidates,
        bool requiresFullNdbEvaluation)
    {
        ApplicableRaw = applicableRaw;
        Streamable = streamable;
        FixedCandidates = fixedCandidates;
        RequiresFullNdbEvaluation = requiresFullNdbEvaluation;
    }

    /// <summary>Non-macro NDB rules whose target flags match the file type.</summary>
    public NdbSignature[] ApplicableRaw { get; }
    public HashSet<NdbSignature> Streamable { get; }
    public HashSet<NdbSignature> FixedCandidates { get; }
    public bool RequiresFullNdbEvaluation { get; }

    public static FileTypeNdbRules Build(NdbSignature[] ndbSignatures, string fileType)
    {
        var applicable = ndbSignatures
            .Where(x => x.MacroGroup is null && LdbRuntime.TargetMatchesFileType(x.Target, fileType))
            .ToArray();
        var streamable = applicable
            .Where(x => ScanTypePolicy.CanStreamRawNdb(x, fileType))
            .ToHashSet();
        var fixedCandidates = applicable
            .Where(x => !streamable.Contains(x) &&
                        x.Pattern.IsFixed &&
                        !ScanTypePolicy.IsNormalizedTarget(x.Target))
            .ToHashSet();
        return new FileTypeNdbRules(
            applicable,
            streamable,
            fixedCandidates,
            applicable.Any(x => !streamable.Contains(x)));
    }
}
