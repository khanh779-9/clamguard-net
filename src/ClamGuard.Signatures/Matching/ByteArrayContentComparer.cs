namespace ClamGuard.Signatures.Matching;

/// <summary>
/// Content comparer for cryptographic digests. ClamAV keeps digests as raw bytes;
/// comparing byte arrays by object identity would be incorrect and linear scanning
/// would waste time when a database contains many hashes.
/// </summary>
internal sealed class ByteArrayContentComparer : IEqualityComparer<byte[]>
{
    public static readonly ByteArrayContentComparer Instance = new();

    private ByteArrayContentComparer() { }

    public bool Equals(byte[]? x, byte[]? y)
        => ReferenceEquals(x, y) || (x is not null && y is not null && x.AsSpan().SequenceEqual(y));

    public int GetHashCode(byte[] obj)
    {
        ArgumentNullException.ThrowIfNull(obj);
        // Use the runtime's vectorized xxHash-based combiner. It hashes
        // 16/20/32-byte digests in a handful of SIMD iterations instead of
        // the byte-by-byte multiply-add loop, and provides better
        // distribution to reduce hash-bucket collisions.
        var hc = new HashCode();
        hc.AddBytes(obj);
        return hc.ToHashCode();
    }
}
