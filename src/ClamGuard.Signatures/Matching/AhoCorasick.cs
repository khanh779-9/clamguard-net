namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Sparse Aho-Corasick matcher for fixed byte patterns.
/// Transitions and output links use compact integer-indexed arrays/lists instead
/// of allocating a Dictionary and List for every trie node. This matters when
/// loading large ClamAV databases with hundreds of thousands of fixed patterns.
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
            var next = FindTransition(state, value);
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
                var fallback = FindTransition(failureState, edge.Value);
                while (failureState != 0 && fallback < 0)
                {
                    failureState = _nodes[failureState].Fail;
                    fallback = FindTransition(failureState, edge.Value);
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

        _built = true;
    }

    /// <summary>
    /// Finds distinct pattern IDs that occur in the supplied data without retaining
    /// every match position. Useful for candidate discovery and diagnostics.
    /// </summary>
    public HashSet<int> FindMatchingIds(ReadOnlySpan<byte> data)
    {
        Build();
        var matched = new HashSet<int>();
        if (data.IsEmpty || _nodes.Count == 1)
            return matched;

        var state = 0;
        for (var i = 0; i < data.Length; i++)
        {
            state = Advance(state, data[i]);
            var outputState = state;
            while (outputState >= 0)
            {
                for (var outputIndex = _nodes[outputState].FirstOutput;
                     outputIndex >= 0;
                     outputIndex = _outputs[outputIndex].Next)
                {
                    matched.Add(_outputs[outputIndex].PatternId);
                }
                outputState = _nodes[outputState].OutputLink;
            }
        }

        return matched;
    }

    public void Scan(ReadOnlySpan<byte> data, ref int state, long baseOffset, List<(int Id, long EndOffset)> matches)
    {
        ArgumentNullException.ThrowIfNull(matches);
        Build();
        if ((uint)state >= (uint)_nodes.Count)
            state = 0;

        for (var i = 0; i < data.Length; i++)
        {
            state = Advance(state, data[i]);
            var outputState = state;

            while (outputState >= 0)
            {
                for (var outputIndex = _nodes[outputState].FirstOutput;
                     outputIndex >= 0;
                     outputIndex = _outputs[outputIndex].Next)
                {
                    matches.Add((_outputs[outputIndex].PatternId, baseOffset + i));
                }

                outputState = _nodes[outputState].OutputLink;
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
        if ((uint)state >= (uint)_nodes.Count)
            state = 0;

        for (var i = 0; i < data.Length; i++)
        {
            state = Advance(state, data[i]);
            var outputState = state;

            while (outputState >= 0)
            {
                for (var outputIndex = _nodes[outputState].FirstOutput;
                     outputIndex >= 0;
                     outputIndex = _outputs[outputIndex].Next)
                {
                    var patternId = _outputs[outputIndex].PatternId;
                    if (ignoredPatternIds is { Count: > 0 } && ignoredPatternIds.Contains(patternId))
                        continue;
                    if (onMatch(patternId, baseOffset + i))
                        return true;
                }

                outputState = _nodes[outputState].OutputLink;
            }
        }

        return false;
    }

    private int Advance(int state, byte value)
    {
        var next = FindTransition(state, value);
        while (state != 0 && next < 0)
        {
            state = _nodes[state].Fail;
            next = FindTransition(state, value);
        }

        return next >= 0 ? next : 0;
    }

    private int FindTransition(int state, byte value)
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
