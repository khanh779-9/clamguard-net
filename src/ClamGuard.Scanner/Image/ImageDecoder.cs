using System.Reflection;

namespace ClamGuard.Scanner;

internal static class ImageDecoder
{
    /// <summary>Hard cap on any declared image width or height accepted from untrusted data.</summary>
    internal const int MaxImageDimension = 4096;

    /// <summary>Hard cap on total decoded pixel bytes (e.g. width * height * 3 for RGB output).</summary>
    internal const long MaxImagePixelBytes = 64L * 1024 * 1024;

    /// <summary>
    /// Decodes image data from an untrusted source into BGR bytes for fuzzy hashing.
    /// Decoded dimensions are capped at MaxImageDimension (4096) per axis and total decoded
    /// pixel bytes at MaxImagePixelBytes (64 MiB); PNG IDAT decompression is bounded and aborted
    /// as soon as output exceeds its cap. Malformed or over-cap input returns false instead of
    /// throwing, so callers only need the boolean result.
    /// </summary>
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
            if (w < 1 || h < 1 ||
                w > MaxImageDimension || h > MaxImageDimension ||
                (long)w * h * 4 > MaxImagePixelBytes)
                return false;
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
