using System.Reflection;

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
