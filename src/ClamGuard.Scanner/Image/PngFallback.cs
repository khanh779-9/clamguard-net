using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace ClamGuard.Scanner;

internal static class PngFallback
{
    public static bool TryDecode(ReadOnlySpan<byte> d, out RgbImage image)
    {
        image = null!;
        if (d.Length < 33 || !d[..8].SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
            return false;

        var palette = Array.Empty<byte>();
        var trns = Array.Empty<byte>();
        var pos = 8;
        int w = 0, h = 0, bit = 0, ct = 0;
        using var all = new MemoryStream();

        while (pos + 12 <= d.Length)
        {
            var len = (long)BinaryPrimitives.ReadUInt32BigEndian(d.Slice(pos, 4));
            var type = Encoding.ASCII.GetString(d.Slice(pos + 4, 4));
            if (pos + 12 + len > d.Length) return false;
            var body = d.Slice(pos + 8, (int)len);
            if (type == "IHDR")
            {
                if (body.Length != 13) return false;
                var uw = BinaryPrimitives.ReadUInt32BigEndian(body);
                var uh = BinaryPrimitives.ReadUInt32BigEndian(body.Slice(4, 4));
                if (uw < 1 || uh < 1 ||
                    uw > ImageDecoder.MaxImageDimension || uh > ImageDecoder.MaxImageDimension)
                    return false;
                w = (int)uw;
                h = (int)uh;
                bit = body[8];
                ct = body[9];
                if (bit != 8 || body[12] != 0) return false;
                if (ct is not (2 or 3 or 6)) return false;
                if ((long)w * h * 3 > ImageDecoder.MaxImagePixelBytes) return false;
            }
            else if (type == "IDAT")
            {
                all.Write(body);
            }
            else if (type == "PLTE")
            {
                palette = body.ToArray();
            }
            else if (type == "tRNS")
            {
                trns = body.ToArray();
            }
            else if (type == "IEND")
            {
                break;
            }
            pos += 12 + (int)len;
        }

        if (w < 1 || h < 1 || all.Length == 0) return false;

        var bpp = ct switch
        {
            2 => 3,
            3 => 1,
            6 => 4,
            _ => 0
        };
        if (bpp == 0) return false;

        // Raw inflated size is exactly (w*bpp + 1) * h (filter byte per scanline). Allow one extra
        // scanline of slack for malformed-but-decodable streams, hard-capped, and abort inflate
        // the moment output exceeds it so a decompression bomb never materializes.
        var expectedRaw = ((long)w * bpp + 1) * h;
        var maxRaw = Math.Min(expectedRaw + w * bpp + 1L, ImageDecoder.MaxImagePixelBytes * 4L);
        if (!TryInflateBounded(all.ToArray(), maxRaw, out var raw)) return false;
        if (raw.Length < expectedRaw) return false;

        var scan = w * bpp;
        var prev = new byte[scan];
        var cur = new byte[scan];
        var rgb = new byte[w * h * 3];
        var rp = 0;

        for (var y = 0; y < h; y++)
        {
            var f = raw[rp++];
            Array.Copy(raw, rp, cur, 0, scan);
            rp += scan;

            for (var x = 0; x < scan; x++)
            {
                byte a = x >= bpp ? cur[x - bpp] : (byte)0;
                var b = prev[x];
                byte c = x >= bpp ? prev[x - bpp] : (byte)0;
                cur[x] = f switch
                {
                    0 => cur[x],
                    1 => (byte)(cur[x] + a),
                    2 => (byte)(cur[x] + b),
                    3 => (byte)(cur[x] + ((a + b) / 2)),
                    4 => (byte)(cur[x] + Paeth(a, b, c)),
                    _ => cur[x]
                };
            }

            for (var x = 0; x < w; x++)
            {
                var q = (y * w + x) * 3;
                if (ct == 2)
                {
                    rgb[q]     = cur[x * 3];
                    rgb[q + 1] = cur[x * 3 + 1];
                    rgb[q + 2] = cur[x * 3 + 2];
                }
                else if (ct == 6)
                {
                    rgb[q]     = cur[x * 4];
                    rgb[q + 1] = cur[x * 4 + 1];
                    rgb[q + 2] = cur[x * 4 + 2];
                }
                else if (ct == 3)
                {
                    var idx = cur[x];
                    var p = idx * 3;
                    if (p + 2 >= palette.Length) return false;
                    rgb[q]     = palette[p];
                    rgb[q + 1] = palette[p + 1];
                    rgb[q + 2] = palette[p + 2];
                }
                else
                {
                    return false;
                }
            }

            Array.Copy(cur, prev, scan);
        }

        image = new RgbImage(w, h, rgb);
        return true;
    }

    private static bool TryInflateBounded(byte[] compressed, long maxOutput, out byte[] output)
    {
        output = [];
        if (compressed.Length == 0 || maxOutput <= 0 || maxOutput > int.MaxValue) return false;
        try
        {
            using var input = new MemoryStream(compressed, writable: false);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var result = new MemoryStream();
            var buffer = new byte[64 * 1024];
            while (true)
            {
                var read = zlib.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                if (result.Length > maxOutput - read) return false;
                result.Write(buffer, 0, read);
            }
            output = result.ToArray();
            return output.Length != 0;
        }
        catch (InvalidDataException) { return false; }
        catch (IOException) { return false; }
    }

    private static byte Paeth(byte a, byte b, byte c)
    {
        var p = a + b - c;
        var pa = Math.Abs(p - a);
        var pb = Math.Abs(p - b);
        var pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }
}
