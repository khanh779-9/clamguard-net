using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace ClamGuard.Scanner;

internal static class ImageDecoder
{
    public static bool TryDecode(ReadOnlySpan<byte> data, out RgbImage image)
    {
        image = null!;
        if (TryDecodeWpf(data, out image)) return true;
        return PngFallback.TryDecode(data, out image) ||
               GifFallback.TryDecode(data, out image) ||
               BmpFallback.TryDecode(data, out image);
    }

    private static bool TryDecodeWpf(ReadOnlySpan<byte> data, out RgbImage image)
    {
        image = null!;
        try
        {
            var bitmapImageType = Type.GetType("System.Windows.Media.Imaging.BitmapImage, PresentationCore", false);
            var formatType = Type.GetType("System.Windows.Media.Imaging.FormatConvertedBitmap, PresentationCore", false);
            var pixelFormatsType = Type.GetType("System.Windows.Media.PixelFormats, PresentationCore", false);
            var rectType = Type.GetType("System.Windows.Int32Rect, WindowsBase", false);
            if (bitmapImageType is null || formatType is null || pixelFormatsType is null || rectType is null) return false;

            using var ms = new MemoryStream(data.ToArray(), writable: false);
            var bitmap = Activator.CreateInstance(bitmapImageType)!;
            bitmapImageType.GetMethod("BeginInit")!.Invoke(bitmap, null);
            bitmapImageType.GetProperty("StreamSource")!.SetValue(bitmap, ms);
            var cacheType = Type.GetType("System.Windows.Media.Imaging.BitmapCacheOption, PresentationCore", false)!;
            bitmapImageType.GetProperty("CacheOption")!.SetValue(bitmap, Enum.Parse(cacheType, "OnLoad"));
            bitmapImageType.GetMethod("EndInit")!.Invoke(bitmap, null);

            var converted = Activator.CreateInstance(formatType)!;
            formatType.GetMethod("BeginInit")!.Invoke(converted, null);
            formatType.GetProperty("Source")!.SetValue(converted, bitmap);
            var bgra = pixelFormatsType.GetProperty("Bgra32", BindingFlags.Public | BindingFlags.Static)!.GetValue(null);
            formatType.GetProperty("DestinationFormat")!.SetValue(converted, bgra);
            formatType.GetMethod("EndInit")!.Invoke(converted, null);

            var sourceType = Type.GetType("System.Windows.Media.Imaging.BitmapSource, PresentationCore", false)!;
            var w = (int)sourceType.GetProperty("PixelWidth")!.GetValue(converted)!;
            var h = (int)sourceType.GetProperty("PixelHeight")!.GetValue(converted)!;
            var raw = new byte[w * h * 4];
            var copy = sourceType.GetMethod("CopyPixels", new[] { rectType, typeof(Array), typeof(int), typeof(int) });
            if (copy is null) return false;
            var rect = Activator.CreateInstance(rectType, new object?[] { 0, 0, w, h });
            copy.Invoke(converted, new object?[] { rect, raw, w * 4, 0 });
            var rgb = new byte[w * h * 3];
            for (var i = 0; i < w * h; i++)
            {
                rgb[i * 3]     = raw[i * 4 + 2];
                rgb[i * 3 + 1] = raw[i * 4 + 1];
                rgb[i * 3 + 2] = raw[i * 4];
            }
            image = new RgbImage(w, h, rgb);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

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
            var len = (int)BinaryPrimitives.ReadUInt32BigEndian(d.Slice(pos, 4));
            var type = Encoding.ASCII.GetString(d.Slice(pos + 4, 4));
            if (pos + 12 + len > d.Length) return false;
            var body = d.Slice(pos + 8, len);
            if (type == "IHDR")
            {
                w = (int)BinaryPrimitives.ReadUInt32BigEndian(body[..4]);
                h = (int)BinaryPrimitives.ReadUInt32BigEndian(body.Slice(4, 4));
                bit = body[8];
                ct = body[9];
                if (bit != 8 || body[12] != 0) return false;
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
            pos += 12 + len;
        }

        if (w < 1 || h < 1 || all.Length == 0) return false;

        using var z = new MemoryStream(all.ToArray());
        using var def = new ZLibStream(z, CompressionMode.Decompress);
        using var rawMs = new MemoryStream();
        def.CopyTo(rawMs);
        var raw = rawMs.ToArray();

        var bpp = ct switch
        {
            0 => 1,
            2 => 3,
            3 => 1,
            4 => 2,
            6 => 4,
            _ => 0
        };
        if (bpp == 0 || raw.Length < (w * bpp + 1) * h) return false;

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

    private static byte Paeth(byte a, byte b, byte c)
    {
        var p = a + b - c;
        var pa = Math.Abs(p - a);
        var pb = Math.Abs(p - b);
        var pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }
}

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
        var h = Math.Abs(h0);
        if (w < 1 || h < 1 || bpp != 24) return false;

        var stride = ((w * 3 + 3) / 4) * 4;
        if (off < 0 || off + stride * h > d.Length) return false;

        var rgb = new byte[w * h * 3];
        for (var y = 0; y < h; y++)
        {
            var sy = h0 > 0 ? h - 1 - y : y;
            for (var x = 0; x < w; x++)
            {
                var p = off + sy * stride + x * 3;
                var q = (y * w + x) * 3;
                rgb[q]     = d[p + 2];
                rgb[q + 1] = d[p + 1];
                rgb[q + 2] = d[p];
            }
        }

        image = new RgbImage(w, h, rgb);
        return true;
    }
}

internal static class GifFallback
{
    public static bool TryDecode(ReadOnlySpan<byte> data, out RgbImage image)
    {
        image = null!;
        if (data.Length < 13 ||
            !(data[..6].SequenceEqual("GIF87a"u8) || data[..6].SequenceEqual("GIF89a"u8)))
            return false;

        var width = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(6, 2));
        var height = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2));
        var packed = data[10];
        if (width == 0 || height == 0) return false;

        var pos = 13;
        byte[]? globalPalette = null;
        if ((packed & 0x80) != 0)
        {
            var count = 2 << (packed & 7);
            var bytes = checked(count * 3);
            if (pos + bytes > data.Length) return false;
            globalPalette = data.Slice(pos, bytes).ToArray();
            pos += bytes;
        }

        while (pos < data.Length)
        {
            var marker = data[pos++];
            if (marker == 0x3b) break; // trailer
            if (marker == 0x21)
            {
                if (pos >= data.Length) return false;
                pos++; // extension label
                if (!SkipSubBlocks(data, ref pos)) return false;
                continue;
            }
            if (marker != 0x2c) return false;
            if (pos + 9 > data.Length) return false;

            var left = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos, 2));
            var top = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos + 2, 2));
            var frameWidth = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos + 4, 2));
            var frameHeight = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos + 6, 2));
            var imagePacked = data[pos + 8];
            pos += 9;
            if (frameWidth == 0 || frameHeight == 0 ||
                (long)left + frameWidth > width || (long)top + frameHeight > height)
                return false;

            byte[]? localPalette = null;
            if ((imagePacked & 0x80) != 0)
            {
                var count = 2 << (imagePacked & 7);
                var bytes = checked(count * 3);
                if (pos + bytes > data.Length) return false;
                localPalette = data.Slice(pos, bytes).ToArray();
                pos += bytes;
            }

            if (pos >= data.Length) return false;
            var minCodeSize = data[pos++];
            if (minCodeSize < 2 || minCodeSize > 8) return false;
            if (!ReadSubBlocks(data, ref pos, out var compressed)) return false;
            if (!DecodeLzw(compressed, minCodeSize, checked(frameWidth * frameHeight), out var indices)) return false;

            var palette = localPalette ?? globalPalette;
            if (palette is null) return false;
            var rgb = new byte[checked(width * height * 3)];
            var interlaced = (imagePacked & 0x40) != 0;
            var srcIndex = 0;
            if (interlaced)
            {
                foreach (var (start, step) in new[] { (0, 8), (4, 8), (2, 4), (1, 2) })
                    for (var y = start; y < frameHeight && srcIndex < indices.Length; y += step)
                        for (var x = 0; x < frameWidth && srcIndex < indices.Length; x++)
                            if (!PutPixel(rgb, width, left + x, top + y, indices[srcIndex++], palette)) return false;
            }
            else
            {
                for (var y = 0; y < frameHeight; y++)
                    for (var x = 0; x < frameWidth; x++)
                        if (!PutPixel(rgb, width, left + x, top + y, indices[srcIndex++], palette)) return false;
            }

            image = new RgbImage(width, height, rgb);
            return true; // ClamAV's image path hashes the first decoded frame.
        }
        return false;
    }

    private static bool PutPixel(byte[] rgb, int canvasWidth, int x, int y, byte paletteIndex, byte[] palette)
    {
        var p = paletteIndex * 3;
        if (p + 2 >= palette.Length) return false;
        var q = (y * canvasWidth + x) * 3;
        rgb[q]     = palette[p];
        rgb[q + 1] = palette[p + 1];
        rgb[q + 2] = palette[p + 2];
        return true;
    }

    private static bool ReadSubBlocks(ReadOnlySpan<byte> data, ref int pos, out byte[] content)
    {
        using var ms = new MemoryStream();
        while (true)
        {
            if (pos >= data.Length) { content = []; return false; }
            var size = data[pos++];
            if (size == 0) break;
            if (pos + size > data.Length) { content = []; return false; }
            ms.Write(data.Slice(pos, size));
            pos += size;
        }
        content = ms.ToArray();
        return true;
    }

    private static bool SkipSubBlocks(ReadOnlySpan<byte> data, ref int pos)
    {
        while (true)
        {
            if (pos >= data.Length) return false;
            var size = data[pos++];
            if (size == 0) return true;
            if (pos + size > data.Length) return false;
            pos += size;
        }
    }

    private static bool DecodeLzw(ReadOnlySpan<byte> compressed, int minCodeSize, int expectedLength, out byte[] output)
    {
        output = new byte[expectedLength];
        var clear = 1 << minCodeSize;
        var end = clear + 1;
        var nextCode = clear + 2;
        var codeSize = minCodeSize + 1;
        var prefix = new short[4096];
        var suffix = new byte[4096];
        var stack = new byte[4096];
        for (var i = 0; i < clear; i++) suffix[i] = (byte)i;

        var bitPos = 0;
        var outPos = 0;
        var previous = -1;
        var previousFirst = (byte)0;
        while (outPos < expectedLength)
        {
            if (!ReadCode(compressed, ref bitPos, codeSize, out var code)) return false;
            if (code == clear)
            {
                codeSize = minCodeSize + 1;
                nextCode = clear + 2;
                previous = -1;
                continue;
            }
            if (code == end) break;
            if (code >= 4096) return false;

            var current = code;
            var stackPos = 0;
            if (current == nextCode && previous >= 0)
            {
                stack[stackPos++] = previousFirst;
                current = previous;
            }
            while (current >= clear + 2)
            {
                if (current >= nextCode || stackPos >= stack.Length) return false;
                stack[stackPos++] = suffix[current];
                current = prefix[current];
            }
            if (current < 0 || current >= clear) return false;
            var first = suffix[current];
            if (stackPos >= stack.Length) return false;
            stack[stackPos++] = first;
            if (outPos + stackPos > expectedLength) return false;
            for (var i = stackPos - 1; i >= 0; i--) output[outPos++] = stack[i];

            if (previous >= 0 && nextCode < 4096)
            {
                prefix[nextCode] = (short)previous;
                suffix[nextCode] = first;
                nextCode++;
                if (nextCode == (1 << codeSize) && codeSize < 12)
                    codeSize++;
            }
            previous = code;
            previousFirst = first;
        }
        return outPos == expectedLength;
    }

    private static bool ReadCode(ReadOnlySpan<byte> data, ref int bitPos, int codeSize, out int code)
    {
        if (bitPos + codeSize > data.Length * 8) { code = 0; return false; }
        var value = 0;
        for (var i = 0; i < codeSize; i++)
            value |= ((data[(bitPos + i) >> 3] >> ((bitPos + i) & 7)) & 1) << i;
        bitPos += codeSize;
        code = value;
        return true;
    }
}
