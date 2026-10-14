using System.Buffers.Binary;

namespace ClamGuard.Scanner;

internal static class BmpFallback
{
    public static bool TryDecode(ReadOnlySpan<byte> d, out RgbImage image)
    {
        image = null!;
        if (d.Length < 54 || d[0] != 'B' || d[1] != 'M') return false;

        var off = BinaryPrimitives.ReadInt32LittleEndian(d.Slice(10, 4));
        var w = BinaryPrimitives.ReadInt32LittleEndian(d.Slice(18, 4));
        var h0 = BinaryPrimitives.ReadInt32LittleEndian(d.Slice(22, 4));
        var bpp = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(28, 2));
        var h = Math.Abs((long)h0); // long: Math.Abs(int.MinValue) would throw
        if (w < 1 || h < 1 || bpp != 24) return false;
        if (w > ImageDecoder.MaxImageDimension || h > ImageDecoder.MaxImageDimension) return false;
        if ((long)w * h * 3 > ImageDecoder.MaxImagePixelBytes) return false;

        var rows = (int)h;
        var stride = ((w * 3 + 3) / 4) * 4;
        if (off < 0 || off + (long)stride * rows > d.Length) return false;

        var rgb = new byte[w * rows * 3];
        for (var y = 0; y < rows; y++)
        {
            var sy = h0 > 0 ? rows - 1 - y : y;
            for (var x = 0; x < w; x++)
            {
                var p = off + sy * stride + x * 3;
                var q = (y * w + x) * 3;
                rgb[q]     = d[p + 2];
                rgb[q + 1] = d[p + 1];
                rgb[q + 2] = d[p];
            }
        }

        image = new RgbImage(w, rows, rgb);
        return true;
    }
}
