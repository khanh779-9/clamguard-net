namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Small fixed-pattern fast path. ClamAV's production matcher has a BM backend
/// in addition to its AC trie. For a single long exact signature, BMH avoids
/// walking an AC automaton and skips ahead on mismatches.
/// </summary>
internal sealed class BoyerMooreHorspoolMatcher
{
    private readonly byte[] _pattern;
    private readonly int[] _shift = new int[256];

    public BoyerMooreHorspoolMatcher(ReadOnlySpan<byte> pattern)
    {
        if (pattern.IsEmpty)
            throw new ArgumentException("Pattern cannot be empty.", nameof(pattern));

        _pattern = pattern.ToArray();
        Array.Fill(_shift, _pattern.Length);
        for (var i = 0; i < _pattern.Length - 1; i++)
            _shift[_pattern[i]] = _pattern.Length - 1 - i;
    }

    public int PatternLength => _pattern.Length;

    /// <summary>Returns the first match at or after <paramref name="startOffset"/>.</summary>
    public int FindFirst(ReadOnlySpan<byte> data, int startOffset = 0)
    {
        if (_pattern.Length > data.Length)
            return -1;

        var lastStart = data.Length - _pattern.Length;
        var cursor = Math.Max(0, startOffset);
        while (cursor <= lastStart)
        {
            var j = _pattern.Length - 1;
            while (j >= 0 && data[cursor + j] == _pattern[j])
                j--;

            if (j < 0)
                return cursor;

            cursor += _shift[data[cursor + _pattern.Length - 1]];
        }
        return -1;
    }
}
