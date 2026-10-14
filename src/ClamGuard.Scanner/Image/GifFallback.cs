using System.Buffers.Binary;

namespace ClamGuard.Scanner;

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
        if (width > ImageDecoder.MaxImageDimension || height > ImageDecoder.MaxImageDimension) return false;
        if ((long)width * height * 3 > ImageDecoder.MaxImagePixelBytes) return false;

        var pos = 13;
        byte[]? globalPalette = null;
        if ((packed & 0x80) != 0)
        {
            var count = 2 << (packed & 7);
            var bytes = count * 3;
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
                var bytes = count * 3;
                if (pos + bytes > data.Length) return false;
                localPalette = data.Slice(pos, bytes).ToArray();
                pos += bytes;
            }

            if (pos >= data.Length) return false;
            var minCodeSize = data[pos++];
            if (minCodeSize < 2 || minCodeSize > 8) return false;
            if (!ReadSubBlocks(data, ref pos, out var compressed)) return false;
            if (!DecodeLzw(compressed, minCodeSize, frameWidth * frameHeight, out var indices)) return false;

            var palette = localPalette ?? globalPalette;
            if (palette is null) return false;
            var rgb = new byte[width * height * 3];
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
        if (bitPos + codeSize > (long)data.Length * 8) { code = 0; return false; }
        var value = 0;
        for (var i = 0; i < codeSize; i++)
            value |= ((data[(bitPos + i) >> 3] >> ((bitPos + i) & 7)) & 1) << i;
        bitPos += codeSize;
        code = value;
        return true;
    }
}
