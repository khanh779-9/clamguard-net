using System.Runtime.CompilerServices;

namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Sparse Aho-Corasick matcher for fixed byte patterns.
/// Transitions and output links use compact integer-indexed arrays/lists instead
/// of allocating a Dictionary and List for every trie node. This matters when
/// loading large ClamAV databases with hundreds of thousands of fixed patterns.
///
/// After Build(), the trie is frozen into contiguous arrays for cache-friendly
/// access and the top N depth layers are DFA-flattened into dense int[256]
/// tables, making Advance() O(1) for the most frequently visited states.
/// </summary>
public sealed class AhoCorasickMatcher
{
    private struct Node
    {
        public int FirstEdge;
        public int Fail;
        public int FirstOutput;
        public int LastOutput;
        public int OutputLink;

        public Node()
        {
            FirstEdge = -1;
            Fail = 0;
            FirstOutput = -1;
            LastOutput = -1;
            OutputLink = -1;
        }
    }

    private readonly record struct Edge(byte Value, int Target, int Next);

    private struct OutputEntry
    {
        public int PatternId;
        public int Next;

        public OutputEntry(int patternId, int next)
        {
            PatternId = patternId;
            Next = next;
        }
    }

    private readonly List<Node> _nodes = [new Node()];
    private readonly List<Edge> _edges = [];
    private readonly List<OutputEntry> _outputs = [];
    private readonly int[] _rootTransitions = CreateRootTransitions();
    private bool _built;

    // Frozen arrays: after Build(), list contents are snapshot into arrays
    // for cache-friendly contiguous access in the hot scan loop.
    private Node[] _frozenNodes = [];
    private Edge[] _frozenEdges = [];
    private OutputEntry[] _frozenOutputs = [];

    // DFA-flattened dense transition tables for the top trie layers.
    // _denseThreshold is the first state index NOT backed by a dense table.
    // States [0 .. _denseThreshold-1] use _denseTransitions[stateIndex * 256 + byte]
    // for O(1) transition lookup instead of edge-list traversal.
    private int[] _denseTransitions = [];
    private int _denseThreshold;

    /// <summary>
    /// Controls the maximum number of states that receive a dense int[256]
    /// transition table. Higher values trade RAM for speed. With ClamAV-sized
    /// databases the trie typically has 500K–2M states; flattening the first
    /// 8192 (32 MiB) covers the busiest part of the automaton.
    /// </summary>
    private const int MaxDenseStates = 8192;

    public int StateCount => _nodes.Count;

    public void Add(ReadOnlySpan<byte> pattern, int id)
    {
        if (_built)
            throw new InvalidOperationException("Cannot add patterns after Build().");
        if (pattern.IsEmpty)
            throw new ArgumentException("Pattern cannot be empty.", nameof(pattern));

        var state = 0;
        foreach (var value in pattern)
        {
            var next = FindTransitionBuild(state, value);
            if (next < 0)
            {
                next = _nodes.Count;
                _nodes.Add(new Node());

                var node = _nodes[state];
                _edges.Add(new Edge(value, next, node.FirstEdge));
                node.FirstEdge = _edges.Count - 1;
                _nodes[state] = node;

                if (state == 0)
                    _rootTransitions[value] = next;
            }

            state = next;
        }

        AddOutput(state, id);
    }

    public void Build()
    {
        if (_built)
            return;

        var queue = new Queue<int>();
        var root = _nodes[0];
        for (var edgeIndex = root.FirstEdge; edgeIndex >= 0; edgeIndex = _edges[edgeIndex].Next)
        {
            var childIndex = _edges[edgeIndex].Target;
            var child = _nodes[childIndex];
            child.Fail = 0;
            child.OutputLink = -1;
            _nodes[childIndex] = child;
            queue.Enqueue(childIndex);
        }

        while (queue.Count > 0)
        {
            var currentIndex = queue.Dequeue();
            var current = _nodes[currentIndex];

            for (var edgeIndex = current.FirstEdge; edgeIndex >= 0; edgeIndex = _edges[edgeIndex].Next)
            {
                var edge = _edges[edgeIndex];
                queue.Enqueue(edge.Target);

                var failureState = current.Fail;
                var fallback = FindTransitionBuild(failureState, edge.Value);
                while (failureState != 0 && fallback < 0)
                {
                    failureState = _nodes[failureState].Fail;
                    fallback = FindTransitionBuild(failureState, edge.Value);
                }

                var childFailure = fallback >= 0 && fallback != edge.Target ? fallback : 0;
                var child = _nodes[edge.Target];
                child.Fail = childFailure;

                var failureNode = _nodes[childFailure];
                child.OutputLink = failureNode.FirstOutput >= 0
                    ? childFailure
                    : failureNode.OutputLink;

                _nodes[edge.Target] = child;
            }
        }

        // Freeze lists into contiguous arrays for cache-friendly hot-loop access.
        _frozenNodes = _nodes.ToArray();
        _frozenEdges = _edges.ToArray();
        _frozenOutputs = _outputs.ToArray();

        // Release build-time mutable lists so memory is not held twice
        _nodes.Clear();
        _nodes.TrimExcess();
        _edges.Clear();
        _edges.TrimExcess();
        _outputs.Clear();
        _outputs.TrimExcess();

        // Build DFA-flattened dense transition tables for the first N states.
        // This eliminates edge-list traversal for the most-visited trie nodes.
        BuildDenseTransitions();

        _built = true;
    }

    private void BuildDenseTransitions()
    {
        var stateCount = _frozenNodes.Length;
        _denseThreshold = Math.Min(stateCount, MaxDenseStates);
        if (_denseThreshold <= 1)
        {
            // Only root – the root already has _rootTransitions.
            _denseThreshold = 0;
            _denseTransitions = [];
            return;
        }

        _denseTransitions = new int[_denseThreshold * 256];
        Array.Fill(_denseTransitions, -1);

        for (var state = 0; state < _denseThreshold; state++)
        {
            var baseIndex = state * 256;

            if (state == 0)
            {
                // Root: copy from _rootTransitions
                Array.Copy(_rootTransitions, 0, _denseTransitions, baseIndex, 256);
            }
            else
            {
                // Non-root: walk the edge list
                for (var edgeIndex = _frozenNodes[state].FirstEdge;
                     edgeIndex >= 0;
                     edgeIndex = _frozenEdges[edgeIndex].Next)
                {
                    var edge = _frozenEdges[edgeIndex];
                    _denseTransitions[baseIndex + edge.Value] = edge.Target;
                }
            }
        }
    }

    /// <summary>
    /// Finds distinct pattern IDs that occur in the supplied data without retaining
    /// every match position. Useful for candidate discovery and diagnostics.
    /// </summary>
    public HashSet<int> FindMatchingIds(ReadOnlySpan<byte> data)
    {
        Build();
        var matched = new HashSet<int>();
        if (data.IsEmpty || _frozenNodes.Length == 1)
            return matched;

        var nodes = _frozenNodes;
        var outputs = _frozenOutputs;
        var state = 0;
        for (var i = 0; i < data.Length; i++)
        {
            state = AdvanceFrozen(state, data[i]);
            var outputState = state;
            while (outputState >= 0)
            {
                for (var outputIndex = nodes[outputState].FirstOutput;
                     outputIndex >= 0;
                     outputIndex = outputs[outputIndex].Next)
                {
                    matched.Add(outputs[outputIndex].PatternId);
                }
                outputState = nodes[outputState].OutputLink;
            }
        }

        return matched;
    }

    public void Scan(ReadOnlySpan<byte> data, ref int state, long baseOffset, List<(int Id, long EndOffset)> matches)
    {
        ArgumentNullException.ThrowIfNull(matches);
        Build();
        if ((uint)state >= (uint)_frozenNodes.Length)
            state = 0;

        var nodes = _frozenNodes;
        var outputs = _frozenOutputs;
        for (var i = 0; i < data.Length; i++)
        {
            state = AdvanceFrozen(state, data[i]);
            var outputState = state;

            while (outputState >= 0)
            {
                for (var outputIndex = nodes[outputState].FirstOutput;
                     outputIndex >= 0;
                     outputIndex = outputs[outputIndex].Next)
                {
                    matches.Add((outputs[outputIndex].PatternId, baseOffset + i));
                }

                outputState = nodes[outputState].OutputLink;
            }
        }
    }

    /// <summary>
    /// Visits matches as they are found without materializing a list of every
    /// occurrence. Return true from the callback to stop scanning immediately.
    /// The state is retained by the caller so this also supports chunked streams.
    /// </summary>
    public bool ScanUntil(
        ReadOnlySpan<byte> data,
        ref int state,
        long baseOffset,
        Func<int, long, bool> onMatch,
        HashSet<int>? ignoredPatternIds = null)
    {
        ArgumentNullException.ThrowIfNull(onMatch);
        Build();
        if ((uint)state >= (uint)_frozenNodes.Length)
            state = 0;

        var nodes = _frozenNodes;
        var outputs = _frozenOutputs;
        for (var i = 0; i < data.Length; i++)
        {
            state = AdvanceFrozen(state, data[i]);
            var outputState = state;

            while (outputState >= 0)
            {
                for (var outputIndex = nodes[outputState].FirstOutput;
                     outputIndex >= 0;
                     outputIndex = outputs[outputIndex].Next)
                {
                    var patternId = outputs[outputIndex].PatternId;
                    if (ignoredPatternIds is { Count: > 0 } && ignoredPatternIds.Contains(patternId))
                        continue;
                    if (onMatch(patternId, baseOffset + i))
                        return true;
                }

                outputState = nodes[outputState].OutputLink;
            }
        }

        return false;
    }

    /// <summary>
    /// Frozen Advance: uses DFA-flattened dense tables for states below the
    /// threshold, falls back to edge-list traversal for deeper states.
    /// All access is against the frozen arrays for cache-friendly layout.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int AdvanceFrozen(int state, byte value)
    {
        var next = FindTransitionFrozen(state, value);
        while (state != 0 && next < 0)
        {
            state = _frozenNodes[state].Fail;
            next = FindTransitionFrozen(state, value);
        }

        return next >= 0 ? next : 0;
    }

    /// <summary>
    /// O(1) for states in the dense-flattened region, O(degree) for deeper states.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int FindTransitionFrozen(int state, byte value)
    {
        if ((uint)state < (uint)_denseThreshold)
            return _denseTransitions[state * 256 + value];

        for (var edgeIndex = _frozenNodes[state].FirstEdge;
             edgeIndex >= 0;
             edgeIndex = _frozenEdges[edgeIndex].Next)
        {
            var edge = _frozenEdges[edgeIndex];
            if (edge.Value == value)
                return edge.Target;
        }

        return -1;
    }

    /// <summary>
    /// Build-time transition lookup (before freezing). Uses the mutable lists.
    /// </summary>
    private int FindTransitionBuild(int state, byte value)
    {
        if (state == 0)
            return _rootTransitions[value];

        for (var edgeIndex = _nodes[state].FirstEdge;
             edgeIndex >= 0;
             edgeIndex = _edges[edgeIndex].Next)
        {
            var edge = _edges[edgeIndex];
            if (edge.Value == value)
                return edge.Target;
        }

        return -1;
    }

    private void AddOutput(int state, int id)
    {
        var node = _nodes[state];
        var outputIndex = _outputs.Count;
        _outputs.Add(new OutputEntry(id, -1));

        if (node.FirstOutput < 0)
        {
            node.FirstOutput = outputIndex;
        }
        else
        {
            var lastOutput = _outputs[node.LastOutput];
            lastOutput.Next = outputIndex;
            _outputs[node.LastOutput] = lastOutput;
        }

        node.LastOutput = outputIndex;
        _nodes[state] = node;
    }

    private static int[] CreateRootTransitions()
    {
        var transitions = new int[byte.MaxValue + 1];
        Array.Fill(transitions, -1);
        return transitions;
    }
}
