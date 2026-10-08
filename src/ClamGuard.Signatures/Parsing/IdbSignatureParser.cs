using ClamGuard.Core;
using ClamGuard.Signatures;

namespace ClamGuard.Signatures.Parsing;

internal static class IdbSignatureParser
{
    internal static IconDatabase ParseIdbFile(string path)
        => ParseIdbLines(File.ReadLines(path), path);

    internal static IconDatabase ParseIdbLines(IEnumerable<string> lines, string path)
    {
        var database = new IconDatabase();
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var parts = line.Split(':');
            if (parts.Length != 4)
                throw new FormatException($"Invalid IDB signature in {path}: {line}");
            if (parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
                throw new FormatException($"IDB name/group fields cannot be empty in {path}: {line}");
            if (!Core.HexCodec.TryDecode(parts[3], out var rawHash) || rawHash.Length != 62)
                throw new FormatException($"Invalid IDB metric in {path}: {line}");

            var hex = parts[3];
            var side = Convert.ToInt32(hex[..2], 16);
            if (side is not (16 or 24 or 32))
                throw new FormatException($"Unsupported IDB side {side} in {path}: {line}");

            var cursor = 2;
            uint[] colorAvg = new uint[3]; byte[] colorX = new byte[3]; byte[] colorY = new byte[3];
            uint[] grayAvg = new uint[3]; byte[] grayX = new byte[3]; byte[] grayY = new byte[3];
            byte[] brightAvg = new byte[3]; byte[] brightX = new byte[3]; byte[] brightY = new byte[3];
            byte[] darkAvg = new byte[3]; byte[] darkX = new byte[3]; byte[] darkY = new byte[3];
            byte[] edgeAvg = new byte[3]; byte[] edgeX = new byte[3]; byte[] edgeY = new byte[3];
            byte[] noEdgeAvg = new byte[3]; byte[] noEdgeX = new byte[3]; byte[] noEdgeY = new byte[3];

            for (var i = 0; i < 3; i++) { colorAvg[i] = ReadHex(hex, ref cursor, 3); colorX[i] = ReadByteHex(hex, ref cursor, 2); colorY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { grayAvg[i] = ReadHex(hex, ref cursor, 3); grayX[i] = ReadByteHex(hex, ref cursor, 2); grayY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { brightAvg[i] = ReadByteHex(hex, ref cursor, 2); brightX[i] = ReadByteHex(hex, ref cursor, 2); brightY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { darkAvg[i] = ReadByteHex(hex, ref cursor, 2); darkX[i] = ReadByteHex(hex, ref cursor, 2); darkY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { edgeAvg[i] = ReadByteHex(hex, ref cursor, 2); edgeX[i] = ReadByteHex(hex, ref cursor, 2); edgeY[i] = ReadByteHex(hex, ref cursor, 2); }
            for (var i = 0; i < 3; i++) { noEdgeAvg[i] = ReadByteHex(hex, ref cursor, 2); noEdgeX[i] = ReadByteHex(hex, ref cursor, 2); noEdgeY[i] = ReadByteHex(hex, ref cursor, 2); }
            var rsum = ReadByteHex(hex, ref cursor, 2);
            var gsum = ReadByteHex(hex, ref cursor, 2);
            var bsum = ReadByteHex(hex, ref cursor, 2);
            var ccount = ReadByteHex(hex, ref cursor, 2);
            if (rsum + gsum + bsum > 103 || ccount > 100)
                throw new FormatException($"Invalid IDB color spread data in {path}: {line}");

            var limit = side - side / 8;
            if (colorX.Any(x => x > limit) || colorY.Any(x => x > limit) || grayX.Any(x => x > limit) || grayY.Any(x => x > limit) ||
                brightX.Any(x => x > limit) || brightY.Any(x => x > limit) || darkX.Any(x => x > limit) || darkY.Any(x => x > limit) ||
                edgeX.Any(x => x > limit) || edgeY.Any(x => x > limit) || noEdgeX.Any(x => x > limit) || noEdgeY.Any(x => x > limit) ||
                colorAvg.Any(x => x > 4072) || grayAvg.Any(x => x > 4072))
                throw new FormatException($"Invalid IDB coordinate/average data in {path}: {line}");

            var metric = new IconMetric(side, colorAvg, colorX, colorY, grayAvg, grayX, grayY,
                brightAvg, brightX, brightY, darkAvg, darkX, darkY, edgeAvg, edgeX, edgeY,
                noEdgeAvg, noEdgeX, noEdgeY, rsum, gsum, bsum, ccount);
            database.Add(new IconDatabaseEntry(parts[0], parts[1], parts[2], metric)
            {
                SourceEntry = raw
            });
        }
        return database;
    }

    private static uint ReadHex(string text, ref int cursor, int digits)
    {
        if (cursor + digits > text.Length || !uint.TryParse(text[cursor..(cursor + digits)], System.Globalization.NumberStyles.HexNumber, null, out var value))
            throw new FormatException("Invalid hexadecimal IDB metric.");
        cursor += digits;
        return value;
    }

    private static byte ReadByteHex(string text, ref int cursor, int digits) => (byte)ReadHex(text, ref cursor, digits);
}
