namespace ClamGuard.Signatures.Matching;

public sealed class AhoCorasickMatcher
{
    private sealed class Node
    {
        public Dictionary<byte, int> Next { get; } = new();
        public int Fail { get; set; }
        public List<int> Outputs { get; } = new();
    }

    private readonly List<Node> _nodes = [new Node()];
    private readonly HashSet<int> _patternIds = [];
    private bool _built;

    public int StateCount => _nodes.Count;

    public void Add(ReadOnlySpan<byte> pattern, int id)
    {
        if (_built) throw new InvalidOperationException("Cannot add patterns after Build().");
        if (pattern.IsEmpty) throw new ArgumentException("Pattern cannot be empty.", nameof(pattern));

        var state = 0;
        foreach (var b in pattern)
        {
            if (!_nodes[state].Next.TryGetValue(b, out var next))
            {
                next = _nodes.Count;
                _nodes[state].Next[b] = next;
                _nodes.Add(new Node());
            }
            state = next;
        }
        _nodes[state].Outputs.Add(id);
        _patternIds.Add(id);
    }

    public void Build()
    {
        if (_built) return;

        var q = new Queue<int>();
        foreach (var child in _nodes[0].Next.Values)
        {
            _nodes[child].Fail = 0;
            q.Enqueue(child);
        }

        while (q.Count > 0)
        {
            var current = q.Dequeue();
            foreach (var (b, child) in _nodes[current].Next)
            {
                q.Enqueue(child);
                var fail = _nodes[current].Fail;
                while (fail != 0 && !_nodes[fail].Next.ContainsKey(b))
                    fail = _nodes[fail].Fail;

                if (_nodes[fail].Next.TryGetValue(b, out var fallback) && fallback != child)
                    _nodes[child].Fail = fallback;
                else
                    _nodes[child].Fail = 0;

                if (_nodes[_nodes[child].Fail].Outputs.Count != 0)
                    _nodes[child].Outputs.AddRange(_nodes[_nodes[child].Fail].Outputs);
            }
        }

        _built = true;
    }

    /// <summary>
    /// Finds which pattern IDs occur at least once. Unlike <see cref="Scan"/>,
    /// this does not retain every match offset, making it suitable for cheap
    /// candidate filtering when the exact matcher validates each candidate later.
    /// </summary>
    public HashSet<int> FindMatchingIds(ReadOnlySpan<byte> data)
    {
        Build();
        var matched = new HashSet<int>();
        if (data.IsEmpty || _patternIds.Count == 0)
            return matched;

        var state = 0;
        for (var i = 0; i < data.Length; i++)
        {
            var value = data[i];
            while (state != 0 && !_nodes[state].Next.ContainsKey(value))
                state = _nodes[state].Fail;
            if (_nodes[state].Next.TryGetValue(value, out var next))
                state = next;

            foreach (var id in _nodes[state].Outputs)
            {
                matched.Add(id);
                if (matched.Count == _patternIds.Count)
                    return matched;
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
            var b = data[i];
            while (state != 0 && !_nodes[state].Next.ContainsKey(b))
                state = _nodes[state].Fail;
            if (_nodes[state].Next.TryGetValue(b, out var next))
                state = next;

            foreach (var id in _nodes[state].Outputs)
                matches.Add((id, baseOffset + i));
        }
    }
}
