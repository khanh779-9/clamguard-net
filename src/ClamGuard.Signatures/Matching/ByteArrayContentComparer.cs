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
        unchecked
        {
            // A cheap 32-bit content hash over the complete digest. Digest lengths
            // are fixed and small (16/20/32 bytes) so this stays inexpensive.
            var hash = 17;
            foreach (var b in obj)
                hash = (hash * 31) + b;
            return hash;
        }
    }
}
