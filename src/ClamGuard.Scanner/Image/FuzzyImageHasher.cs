namespace ClamGuard.Scanner;

internal sealed record RgbImage(int Width, int Height, byte[] Pixels)
{
    public int Index(int x, int y) => (y * Width + x) * 3;
}

internal static class ImageFuzzyHasher
{
    public static byte[] Compute(RgbImage source)
    {
        const int size = 32;
        var gray = new double[size, size];
        var resized = ResizeLanczos3(source, size, size);
        for (var y = 0; y < size; y++)
            for (var x = 0; x < size; x++)
            {
                var q = resized.Index(x, y);
                gray[y, x] = Math.Round(
                    0.299 * resized.Pixels[q] +
                    0.587 * resized.Pixels[q + 1] +
                    0.114 * resized.Pixels[q + 2],
                    MidpointRounding.AwayFromZero);
            }

        var coeff = new double[8, 8];
        for (var v = 0; v < 8; v++)
            for (var u = 0; u < 8; u++)
            {
                double sum = 0;
                for (var y = 0; y < size; y++)
                    for (var x = 0; x < size; x++)
                        sum += gray[y, x] *
                               Math.Cos(Math.PI / size * (x + 0.5) * u) *
                               Math.Cos(Math.PI / size * (y + 0.5) * v);
                coeff[v, u] = sum * 4.0;
            }

        var values = new double[64];
        var k = 0;
        for (var y = 0; y < 8; y++)
            for (var x = 0; x < 8; x++)
                values[k++] = coeff[y, x];
        Array.Sort(values);
        var median = (values[31] + values[32]) / 2.0;

        var hash = new byte[8];
        k = 0;
        for (var i = 0; i < 8; i++)
        {
            byte value = 0;
            for (var bit = 7; bit >= 0; bit--, k++)
                if (coeff[k / 8, k % 8] > median)
                    value |= (byte)(1 << bit);
            hash[i] = value;
        }
        return hash;
    }

    private static RgbImage ResizeLanczos3(RgbImage source, int width, int height)
    {
        if (source.Width == width && source.Height == height)
            return source;

        var horizontal = new byte[checked(width * source.Height * 3)];
        var xWeights = BuildWeights(source.Width, width, 3.0);
        for (var y = 0; y < source.Height; y++)
            for (var x = 0; x < width; x++)
            {
                var weights = xWeights[x];
                for (var c = 0; c < 3; c++)
                {
                    double sum = 0;
                    foreach (var (index, weight) in weights)
                        sum += source.Pixels[source.Index(index, y) + c] * weight;
                    horizontal[(y * width + x) * 3 + c] = ClampByte(sum);
                }
            }

        var vertical = new byte[checked(width * height * 3)];
        var yWeights = BuildWeights(source.Height, height, 3.0);
        for (var y = 0; y < height; y++)
            for (var x = 0; x < width; x++)
            {
                var weights = yWeights[y];
                for (var c = 0; c < 3; c++)
                {
                    double sum = 0;
                    foreach (var (index, weight) in weights)
                        sum += horizontal[(index * width + x) * 3 + c] * weight;
                    vertical[(y * width + x) * 3 + c] = ClampByte(sum);
                }
            }
        return new RgbImage(width, height, vertical);
    }

    private static (int Index, double Weight)[][] BuildWeights(int sourceLength, int destinationLength, double radius)
    {
        var scale = (double)destinationLength / sourceLength;
        var kernelScale = Math.Min(1.0, scale);
        var support = radius / kernelScale;
        var all = new (int, double)[destinationLength][];
        for (var dst = 0; dst < destinationLength; dst++)
        {
            var center = (dst + 0.5) / scale - 0.5;
            var first = Math.Max(0, (int)Math.Ceiling(center - support));
            var last = Math.Min(sourceLength - 1, (int)Math.Floor(center + support));
            var list = new List<(int, double)>();
            var sum = 0.0;
            for (var src = first; src <= last; src++)
            {
                var distance = Math.Abs((src - center) * kernelScale);
                var weight = Lanczos(distance, radius);
                if (weight == 0) continue;
                list.Add((src, weight));
                sum += weight;
            }
            if (sum == 0)
                list.Add((Math.Clamp((int)Math.Round(center), 0, sourceLength - 1), 1.0));
            else
                for (var i = 0; i < list.Count; i++) list[i] = (list[i].Item1, list[i].Item2 / sum);
            all[dst] = list.ToArray();
        }
        return all;
    }

    private static double Lanczos(double x, double radius)
    {
        if (x >= radius) return 0;
        if (x < 1e-12) return 1;
        var pix = Math.PI * x;
        return (Math.Sin(pix) / pix) * (Math.Sin(pix / radius) / (pix / radius));
    }

    private static byte ClampByte(double value)
        => (byte)Math.Clamp((int)Math.Round(value, MidpointRounding.AwayFromZero), 0, 255);
}
