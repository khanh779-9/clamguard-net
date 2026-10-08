using System.Buffers.Binary;

namespace ClamGuard.Scanner;

internal static class IconDecoder
{
    public static bool TryDecode(byte[] bytes, out RgbImage image)
    {
        image = null!;
        if (bytes.Length < 40) return false;

        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
        if (headerSize < 40 || headerSize > bytes.Length) return false;

        var width = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4, 4));
        var encodedHeight = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8, 4));
        var height = encodedHeight / 2;
        var planes = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(12, 2));
        var bpp = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(14, 2));
        var clrUsed = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(32, 4));
        if (width < 16 || height < 16 || width > 256 || height > 256 ||
            planes is not (0 or 1) || bpp is not (1 or 4 or 8 or 16 or 24 or 32))
            return false;

        var paletteCount = bpp <= 8 ? (clrUsed != 0 ? (int)Math.Min(clrUsed, 1u << bpp) : 1 << bpp) : 0;
        var dataOffset = checked((int)headerSize + paletteCount * 4);
        if (dataOffset > bytes.Length) return false;

        var colorStride = checked(((width * bpp + 31) / 32) * 4);
        var colorBytes = checked(colorStride * height);
        if (dataOffset + colorBytes > bytes.Length) return false;

        var andStride = checked(((width + 31) / 32) * 4);
        var maskOffset = dataOffset + colorBytes;
        var hasMask = maskOffset >= 0 && maskOffset + (long)andStride * height <= bytes.Length;
        var pixels = new uint[checked(width * height)];
        var anyExplicitAlpha = false;

        for (var y = 0; y < height; y++)
        {
            var srcRow = y * colorStride;
            var dstY = height - 1 - y;
            for (var x = 0; x < width; x++)
            {
                byte r, g, b, a = 255;
                if (bpp == 24)
                {
                    var p = dataOffset + srcRow + x * 3;
                    b = bytes[p]; g = bytes[p + 1]; r = bytes[p + 2];
                }
                else if (bpp == 32)
                {
                    var p = dataOffset + srcRow + x * 4;
                    b = bytes[p]; g = bytes[p + 1]; r = bytes[p + 2]; a = bytes[p + 3];
                    anyExplicitAlpha |= a != 0;
                }
                else if (bpp == 16)
                {
                    var p = dataOffset + srcRow + x * 2;
                    var v = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(p, 2));
                    // ClamAV treats icon 16-bpp pixels as 5-5-5-style RGB values.
                    b = Expand5((byte)(v & 0x1f));
                    g = Expand5((byte)((v >> 5) & 0x1f));
                    r = Expand5((byte)((v >> 10) & 0x1f));
                }
                else
                {
                    var bitPos = x * bpp;
                    var p = dataOffset + srcRow + bitPos / 8;
                    var shift = 8 - bpp - bitPos % 8;
                    var paletteIndex = (bytes[p] >> shift) & ((1 << bpp) - 1);
                    var palOffset = checked((int)headerSize + paletteIndex * 4);
                    if (palOffset + 4 > bytes.Length) return false;
                    var pal = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(palOffset, 4));
                    b = (byte)pal; g = (byte)(pal >> 8); r = (byte)(pal >> 16);
                }

                pixels[dstY * width + x] = ((uint)a << 24) | ((uint)r << 16) | ((uint)g << 8) | b;
            }
        }

        // 32-bit icons with real alpha use that alpha channel. Otherwise ClamAV
        // uses the XOR/AND icon mask to determine transparency.
        if (bpp != 32 || !anyExplicitAlpha)
        {
            if (!hasMask)
            {
                // Broken 32-bit icons are treated as fully opaque.
                if (bpp != 32) return false;
                for (var i = 0; i < pixels.Length; i++) pixels[i] |= 0xff000000u;
            }
            else
            {
                for (var y = 0; y < height; y++)
                {
                    var srcRow = maskOffset + y * andStride;
                    var dstY = height - 1 - y;
                    for (var x = 0; x < width; x++)
                    {
                        var maskByte = bytes[srcRow + (x >> 3)];
                        var transparent = ((maskByte >> (7 - (x & 7))) & 1) != 0;
                        var index = dstY * width + x;
                        pixels[index] = (pixels[index] & 0x00ffffffu) | (transparent ? 0u : 0xff000000u);
                    }
                }
            }
        }

        var rgb = new byte[checked(width * height * 3)];
        for (var i = 0; i < pixels.Length; i++)
        {
            var c = pixels[i];
            var a = (c >> 24) & 0xffu;
            var r = 0xffu - a + a * ((c >> 16) & 0xffu) / 0xffu;
            var g = 0xffu - a + a * ((c >> 8) & 0xffu) / 0xffu;
            var b = 0xffu - a + a * (c & 0xffu) / 0xffu;
            var q = i * 3;
            rgb[q] = (byte)r; rgb[q + 1] = (byte)g; rgb[q + 2] = (byte)b;
        }

        image = new RgbImage(width, height, rgb);
        return true;
    }

    private static byte Expand5(byte v) => (byte)((v << 3) | (v >> 2));
}
