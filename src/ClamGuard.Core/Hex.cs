namespace ClamGuard.Core;

public static class HexCodec
{
    public static bool TryDecode(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (input.Length % 2 != 0) return false;
        var result = new byte[input.Length / 2];
        for (var i = 0; i < result.Length; i++)
        {
            var hi = ParseNibble(input[i * 2]);
            var lo = ParseNibble(input[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            result[i] = (byte)((hi << 4) | lo);
        }
        bytes = result;
        return true;
    }

    public static string ToLowerHex(ReadOnlySpan<byte> bytes)
        => Convert.ToHexString(bytes).ToLowerInvariant();

    private static int ParseNibble(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1
    };
}
