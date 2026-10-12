using ClamGuard.Signatures.Patterns;

namespace ClamGuard.Signatures.Matching;

public sealed record SubsigAnchorRef(
    int SubsigIndex,
    int AnchorId,
    int AnchorOffset,
    int SecondAnchorId,
    int SecondAnchorDelta);

/// <summary>
/// ClamAV-style subsignature anchor index: content subsignature fixed-byte runs
/// are registered in shared Aho-Corasick automata. A single scan over the byte
/// layer reports where each subsignature could possibly match. Subsignatures
/// with two runs require BOTH runs at the recorded relative distance, which
/// collapses false candidates on common byte sequences.
/// </summary>
public sealed class SubsigAnchorIndex
{
    private const int MinAnchorLength = 6;
    private const int MaxPositionsPerAnchor = 1024;

    private readonly Dictionary<LogicalSignature, List<SubsigAnchorRef>> _anchorsBySignature = new(ReferenceEqualityComparer.Instance);
    private readonly List<byte[]> _exactAnchorBytes = [];
    private readonly List<byte[]> _foldedAnchorBytes = [];
    private AhoCorasickMatcher? _exactMatcher;
    private AhoCorasickMatcher? _foldedMatcher;
    private bool _built;

    public bool IsEmpty
    {
        get
        {
            Build();
            return _exactAnchorBytes.Count == 0 && _foldedAnchorBytes.Count == 0;
        }
    }

    public void Add(LogicalSignature signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        if (_built)
            throw new InvalidOperationException("Cannot add signatures after Build().");

        List<SubsigAnchorRef>? refs = null;
        foreach (var sub in signature.SubSignatures)
        {
            var subsigIndex = GetSubsigIndex(sub);
            var variants = CollectVariants(sub);
            foreach (var pattern in variants)
            {
                if (!pattern.TryGetSearchRuns(out var runs, MinAnchorLength))
                    continue;

                var ignoreCase = sub.MatchOptions.HasFlag(ContentMatchOptions.IgnoreCase);
                var bytes = ignoreCase ? _foldedAnchorBytes : _exactAnchorBytes;
                var baseId = ignoreCase ? _foldedAnchorBytes.Count : _exactAnchorBytes.Count;

                var first = runs[0];
                if (ignoreCase)
                    first = (first.Offset, first.Bytes.Select(FoldByte).ToArray());
                var firstId = bytes.Count;
                bytes.Add(first.Bytes);

                int secondId = -1;
                var secondDelta = 0;
                if (runs.Count >= 2)
                {
                    var second = runs[1];
                    if (ignoreCase)
                        second = (second.Offset, second.Bytes.Select(FoldByte).ToArray());
                    secondId = bytes.Count;
                    secondDelta = second.Offset - first.Offset;
                    bytes.Add(second.Bytes);
                }

                refs ??= [];
                refs.Add(new SubsigAnchorRef(subsigIndex, firstId, first.Offset, secondId, secondDelta));
            }
        }

        if (refs is not null)
            _anchorsBySignature[signature] = refs;
    }

    public void Build()
    {
        if (_built)
            return;

        if (_exactAnchorBytes.Count != 0)
        {
            var automaton = new AhoCorasickMatcher(caseInsensitive: false);
            for (var id = 0; id < _exactAnchorBytes.Count; id++)
                automaton.Add(_exactAnchorBytes[id], id);
            automaton.Build();
            _exactMatcher = automaton;
        }

        if (_foldedAnchorBytes.Count != 0)
        {
            var automaton = new AhoCorasickMatcher(caseInsensitive: true);
            for (var id = 0; id < _foldedAnchorBytes.Count; id++)
                automaton.Add(_foldedAnchorBytes[id], id);
            automaton.Build();
            _foldedMatcher = automaton;
        }

        _built = true;
    }

    private static byte FoldByte(byte value)
        => value is >= (byte)'A' and <= (byte)'Z' ? (byte)(value + 32) : value;

    /// <summary>
    /// One scan over the byte layer collecting the start positions of every
    /// registered anchor occurrence, keyed by anchor id (capped per anchor).
    /// Exact and case-folded automata are scanned in the same pass.
    /// </summary>
    public Dictionary<int, List<int>> FindPositions(ReadOnlySpan<byte> data)
    {
        Build();
        var positions = new Dictionary<int, List<int>>();
        if (data.Length < MinAnchorLength)
            return positions;

        var dataLength = data.Length;
        var totalAnchors = _exactAnchorBytes.Count + _foldedAnchorBytes.Count;

        byte[] AnchorBytes(int anchorId)
            => anchorId < _exactAnchorBytes.Count ? _exactAnchorBytes[anchorId] : _foldedAnchorBytes[anchorId - _exactAnchorBytes.Count];

        void Collect(AhoCorasickMatcher? matcher, ReadOnlySpan<byte> span)
        {
            if (matcher is null)
                return;
            var state = 0;
            matcher.ScanUntil(span, ref state, 0, (id, endOffset) =>
            {
                var start = (int)endOffset - AnchorBytes(id).Length + 1;
                if (start < 0 || start >= dataLength)
                    return false;
                if (!positions.TryGetValue(id, out var list))
                    positions[id] = list = [];
                if (list.Count < MaxPositionsPerAnchor)
                    list.Add(start);
                return false;
            });
        }

        Collect(_exactMatcher, data);
        Collect(_foldedMatcher, data);
        return positions;
    }

    public IReadOnlyList<SubsigAnchorRef>? GetAnchors(LogicalSignature signature)
        => _anchorsBySignature.TryGetValue(signature, out var refs) ? refs : null;

    private static IEnumerable<HexPattern> CollectVariants(ContentSignature sub)
    {
        if (!sub.MatchOptions.HasFlag(ContentMatchOptions.Wide) ||
            sub.MatchOptions.HasFlag(ContentMatchOptions.Ascii))
        {
            yield return sub.Pattern;
        }

        if (sub.MatchOptions.HasFlag(ContentMatchOptions.Wide))
            yield return sub.Pattern.ToWideVariant();
    }

    private static int GetSubsigIndex(ContentSignature signature)
    {
        var hash = signature.Name.LastIndexOf('#');
        return hash >= 0 && int.TryParse(signature.Name[(hash + 1)..], out var index) ? index : 0;
    }
}
