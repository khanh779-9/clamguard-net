using ClamGuard.Core;

namespace ClamGuard.Signatures.Parsing;

internal static class SignatureParserCommon
{
    internal static bool TryGetAlgorithm(string hashText, out HashAlgorithmKind algorithm, out byte[] hash)
    {
        algorithm = default;
        hash = Array.Empty<byte>();
        if (!Core.HexCodec.TryDecode(hashText, out hash))
            return false;

        algorithm = hash.Length switch
        {
            16 => HashAlgorithmKind.Md5,
            20 => HashAlgorithmKind.Sha1,
            32 => HashAlgorithmKind.Sha256,
            _ => throw new FormatException("Only MD5, SHA-1 and SHA-256 hash signatures are supported.")
        };
        return true;
    }

    internal static long? ParseSize(string value)
    {
        if (value == "*")
            return null;

        if (!long.TryParse(value, out var size) || size <= 0 || size >= uint.MaxValue)
            throw new FormatException($"Invalid file size: {value}");
        return size;
    }

    internal static uint ParseUInt(string value, string field)
        => uint.TryParse(value, out var result)
            ? result
            : throw new FormatException($"Invalid {field}: {value}");

    internal static int ParseInt(string value)
        => int.TryParse(value, out var result)
            ? result
            : throw new FormatException($"Invalid integer: {value}");

    internal static (int Minimum, int Maximum) ReadEngineRange(string attributes)
    {
        var minimum = 0;
        var maximum = int.MaxValue;

        foreach (var token in attributes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!token.StartsWith("Engine:", StringComparison.OrdinalIgnoreCase))
                continue;

            var range = token[7..];
            var parts = range.Split('-', 2, StringSplitOptions.TrimEntries);
            minimum = ParseInt(parts[0]);
            maximum = parts.Length == 2 ? ParseInt(parts[1]) : int.MaxValue;
            if (maximum < minimum)
                throw new FormatException($"Invalid Engine range: {range}");
            break;
        }

        return (minimum, maximum);
    }
}
