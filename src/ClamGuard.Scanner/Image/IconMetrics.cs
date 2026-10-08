using ClamGuard.Signatures;

namespace ClamGuard.Scanner;

internal static class IconMetrics
{
    private sealed record Metric(
        uint[] ColorAvg, byte[] ColorX, byte[] ColorY,
        uint[] GrayAvg, byte[] GrayX, byte[] GrayY,
        byte[] BrightAvg, byte[] BrightX, byte[] BrightY,
        byte[] DarkAvg, byte[] DarkX, byte[] DarkY,
        byte[] EdgeAvg, byte[] EdgeX, byte[] EdgeY,
        byte[] NoEdgeAvg, byte[] NoEdgeX, byte[] NoEdgeY,
        byte RSum, byte GSum, byte BSum, byte CCount);

    public static bool Matches(RgbImage source, IconMetric reference, bool alreadyPrepared = false)
    {
        var image = alreadyPrepared ? source : PrepareForClam(source);
        if (image.Width != reference.Side || image.Height != reference.Side) return false;
        var m = Compute(image, reference.Side);
        var enginesize = (reference.Side >> 3) - 2;
        if (enginesize < 0 || enginesize > 2) return false;
        var bw = m.CCount == 0 && reference.CCount == 0;
        int edge, noedge, bright, dark, confidence;
        if (bw)
        {
            edge = MatchBw(Concat(m.EdgeAvg, m.ColorAvg), Concat(m.EdgeX, m.ColorX), Concat(m.EdgeY, m.ColorY),
                           Concat(reference.EdgeAvg, reference.ColorAvg), Concat(reference.EdgeX, reference.ColorX), Concat(reference.EdgeY, reference.ColorY), reference.Side);
            noedge = MatchBw(Concat(m.NoEdgeAvg, m.GrayAvg), Concat(m.NoEdgeX, m.GrayX), Concat(m.NoEdgeY, m.GrayY),
                             Concat(reference.NoEdgeAvg, reference.GrayAvg), Concat(reference.NoEdgeX, reference.GrayX), Concat(reference.NoEdgeY, reference.GrayY), reference.Side);
            bright = Match3(m.BrightAvg, m.BrightX, m.BrightY, reference.BrightAvg, reference.BrightX, reference.BrightY, 255, reference.Side);
            dark = Match3(m.DarkAvg, m.DarkX, m.DarkY, reference.DarkAvg, reference.DarkX, reference.DarkY, 255, reference.Side);
            confidence = (bright + dark + edge * 2 + noedge) / 6;
            return confidence >= 70;
        }
        edge = Match3(m.EdgeAvg, m.EdgeX, m.EdgeY, reference.EdgeAvg, reference.EdgeX, reference.EdgeY, 255, reference.Side);
        noedge = Match3(m.NoEdgeAvg, m.NoEdgeX, m.NoEdgeY, reference.NoEdgeAvg, reference.NoEdgeX, reference.NoEdgeY, 255, reference.Side);
        bright = Match3(m.BrightAvg, m.BrightX, m.BrightY, reference.BrightAvg, reference.BrightX, reference.BrightY, 255, reference.Side);
        dark = Match3(m.DarkAvg, m.DarkX, m.DarkY, reference.DarkAvg, reference.DarkX, reference.DarkY, 255, reference.Side);
        var color = m.CCount != 0 && reference.CCount != 0 ? Match3(m.ColorAvg, m.ColorX, m.ColorY, reference.ColorAvg, reference.ColorX, reference.ColorY, 4072, reference.Side) : 0;
        var gray = m.CCount != 0 && reference.CCount != 0 ? Match3(m.GrayAvg, m.GrayX, m.GrayY, reference.GrayAvg, reference.GrayX, reference.GrayY, 4072, reference.Side) : 0;
        var colors = (Spread(m.RSum, reference.RSum) + Spread(m.GSum, reference.GSum) + Spread(m.BSum, reference.BSum) + Spread(m.CCount, reference.CCount)) / 4;
        confidence = (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6;
        return confidence >= 64 + 4 * (2 - enginesize);
    }

    private static Metric Compute(RgbImage image, int side)
    {
        var ks = side / 4;
        var colorAvg = new uint[3]; var colorX = new byte[3]; var colorY = new byte[3];
        var grayAvg = Enumerable.Repeat(uint.MaxValue, 3).ToArray(); var grayX = new byte[3]; var grayY = new byte[3];
        var brightAvg = new uint[3]; var brightX = new byte[3]; var brightY = new byte[3];
        var darkAvg = Enumerable.Repeat(uint.MaxValue, 3).ToArray(); var darkX = new byte[3]; var darkY = new byte[3];
        var col = new uint[side, side]; var light = new uint[side, side];
        var ss = new byte[side * side]; var vv = new byte[side * side];
        uint ccount = 0, rsum = 0, gsum = 0, bsum = 0;
        for (var y = 0; y < side; y++)
        {
            for (var x = 0; x < side; x++)
            {
                var q = image.Index(x, y);
                var r = image.Pixels[q];
                var g = image.Pixels[q + 1];
                var b = image.Pixels[q + 2];
                var max = Math.Max(r, Math.Max(g, b));
                var min = Math.Min(r, Math.Min(g, b));
                var delta = max - min;
                var sat = delta == 0 ? 0 : 255 * delta / max;
                ss[y * side + x] = (byte)sat;
                vv[y * side + x] = max;
            }
        }

        for (var y = 0; y <= side - ks; y++)
        {
            for (var x = 0; x <= side - ks; x++)
            {
                uint csum = 0, lsum = 0;
                for (var yy = 0; yy < ks; yy++)
                {
                    for (var xx = 0; xx < ks; xx++)
                    {
                        var s = ss[(y + yy) * side + x + xx];
                        var v = vv[(y + yy) * side + x + xx];
                        csum += (uint)Math.Sqrt(s * s * v);
                        lsum += v;
                    }
                }
                col[y, x] = csum;
                light[y, x] = lsum;
            }
        }

        for (var y = 0; y < side; y++)
        {
            for (var x = 0; x < side; x++)
            {
                if (ss[y * side + x] > 85 && vv[y * side + x] > 85)
                {
                    ccount++;
                    var q = image.Index(x, y);
                    var r = image.Pixels[q];
                    var g = image.Pixels[q + 1];
                    var b = image.Pixels[q + 2];
                    var delta = Math.Max(r, Math.Max(g, b)) - Math.Min(r, Math.Min(g, b));
                    if (delta > 0)
                    {
                        rsum += (uint)(100 - 100 * Math.Abs(g - b) / delta);
                        gsum += (uint)(100 - 100 * Math.Abs(r - b) / delta);
                        bsum += (uint)(100 - 100 * Math.Abs(r - g) / delta);
                    }
                }
            }
        }

        Select(col, side, ks, true, colorAvg, colorX, colorY);
        Select(col, side, ks, false, grayAvg, grayX, grayY);
        Select(light, side, ks, true, brightAvg, brightX, brightY);
        Select(light, side, ks, false, darkAvg, darkX, darkY);

        for (var i = 0; i < 3; i++)
        {
            colorAvg[i] /= (uint)(ks * ks);
            grayAvg[i] = grayAvg[i] == uint.MaxValue ? 0 : grayAvg[i] / (uint)(ks * ks);
            brightAvg[i] /= (uint)(ks * ks);
            darkAvg[i] = darkAvg[i] == uint.MaxValue ? 0 : darkAvg[i] / (uint)(ks * ks);
        }

        var cpercent = (int)(ccount * 100 / (uint)(side * side));
        byte rs, gs, bs, cp;
        if (cpercent <= 5)
        {
            rs = gs = bs = cp = 0;
        }
        else
        {
            rs = (byte)Math.Min(255, rsum / (int)ccount);
            gs = (byte)Math.Min(255, gsum / (int)ccount);
            bs = (byte)Math.Min(255, bsum / (int)ccount);
            cp = (byte)Math.Min(100, cpercent);
        }

        var lab = new double[side, side];
        for (var y = 0; y < side; y++)
        {
            for (var x = 0; x < side; x++)
            {
                var q = image.Index(x, y);
                lab[y, x] = LabDiff(image.Pixels[q], image.Pixels[q + 1], image.Pixels[q + 2]);
            }
        }

        var sobel = new double[side, side];
        double peak = 0;
        for (var y = 1; y < side - 1; y++)
        {
            for (var x = 1; x < side - 1; x++)
            {
                var gx = lab[y - 1, x - 1] + 2 * lab[y, x - 1] + lab[y + 1, x - 1] - lab[y - 1, x + 1] - 2 * lab[y, x + 1] - lab[y + 1, x + 1];
                var gy = lab[y - 1, x - 1] + 2 * lab[y - 1, x] + lab[y - 1, x + 1] - lab[y + 1, x - 1] - 2 * lab[y + 1, x] - lab[y + 1, x + 1];
                sobel[y, x] = Math.Sqrt(gx * gx + gy * gy);
                peak = Math.Max(peak, sobel[y, x]);
            }
        }

        if (peak > 0)
        {
            for (var y = 1; y < side - 1; y++)
                for (var x = 1; x < side - 1; x++)
                    sobel[y, x] = sobel[y, x] * 255 / peak;
        }

        for (var x = 0; x < side; x++)
            sobel[0, x] = sobel[side - 1, x] = 0;
        for (var y = 0; y < side; y++)
            sobel[y, 0] = sobel[y, side - 1] = 0;

        var tmp = new double[side, side];
        for (var y = 1; y < side - 1; y++)
        {
            for (var x = 1; x < side - 1; x++)
            {
                var sum = 0d;
                var tot = 0;
                for (var dx = -1; dx <= 1; dx++)
                {
                    var c = sobel[y, x + dx];
                    var w = dx == 0 ? 2 : 1;
                    sum += c * w;
                    tot += w;
                }
                tmp[y, x] = sum / tot;
            }
        }

        for (var y = 1; y < side - 1; y++)
        {
            for (var x = 1; x < side - 1; x++)
            {
                var sum = 0d;
                var tot = 0;
                for (var dy = -1; dy <= 1; dy++)
                {
                    var w = dy == 0 ? 2 : 1;
                    sum += tmp[y + dy, x] * w;
                    tot += w;
                }
                sobel[y, x] = sum / tot;
            }
        }

        var edgeRaw = new uint[side, side];
        for (var y = 0; y <= side - ks; y++)
        {
            for (var x = 0; x <= side - ks; x++)
            {
                uint sum = 0;
                for (var yy = 0; yy < ks; yy++)
                    for (var xx = 0; xx < ks; xx++)
                        sum += (uint)Math.Clamp((int)Math.Round(sobel[y + yy, x + xx]), 0, 255);
                edgeRaw[y, x] = sum;
            }
        }

        var bwOnly = cp == 0;
        var edgeA = new byte[6]; var edgeX = new byte[6]; var edgeY = new byte[6];
        var noA = new byte[6]; var noX = new byte[6]; var noY = new byte[6];
        SelectEdge(edgeRaw, side, ks, true, edgeA, edgeX, edgeY);
        SelectEdge(edgeRaw, side, ks, false, noA, noX, noY);

        var eAvg = edgeA[..3]; var eX = edgeX[..3]; var eY = edgeY[..3];
        var nAvg = noA[..3]; var nX = noX[..3]; var nY = noY[..3];
        if (bwOnly)
        {
            var e2 = edgeA[3..]; var x2 = edgeX[3..]; var y2 = edgeY[3..];
            var n2 = noA[3..];
            colorAvg = e2.Select(v => (uint)v * 1u).ToArray();
            colorX = x2; colorY = y2;
            grayAvg = n2.Select(v => (uint)v * 1u).ToArray();
            grayX = noX[3..]; grayY = noY[3..];
        }

        return new Metric(
            colorAvg.Select(v => Math.Min(v, 4072)).ToArray(), colorX, colorY,
            grayAvg.Select(v => Math.Min(v, 4072)).ToArray(), grayX, grayY,
            brightAvg.Select(v => (byte)Math.Min(v, 255)).ToArray(), brightX, brightY,
            darkAvg.Select(v => (byte)Math.Min(v, 255)).ToArray(), darkX, darkY,
            eAvg, eX, eY,
            nAvg, nX, nY,
            rs, gs, bs, cp);
    }

    private static void Select(uint[,] map, int side, int ks, bool high, uint[] avg, byte[] xs, byte[] ys)
    {
        for (var i = 0; i < 3; i++)
        {
            var found = false;
            uint best = high ? 0 : uint.MaxValue;
            int bx = 0, by = 0;
            for (var y = 0; y < side - ks; y++)
            {
                for (var x = 0; x < side - 1 - ks; x++)
                {
                    var z = map[y, x];
                    if (high ? z <= best : z >= best) continue;
                    var overlap = false;
                    for (var j = 0; j < i; j++)
                    {
                        if (x + ks > xs[j] && x < xs[j] + ks && y + ks > ys[j] && y < ys[j] + ks)
                        {
                            overlap = true;
                            break;
                        }
                    }
                    if (!overlap)
                    {
                        best = z;
                        bx = x;
                        by = y;
                        found = true;
                    }
                }
            }
            if (!found) break;
            avg[i] = best;
            xs[i] = (byte)bx;
            ys[i] = (byte)by;
        }
    }

    private static void SelectEdge(uint[,] map, int side, int ks, bool high, byte[] avg, byte[] xs, byte[] ys)
    {
        for (var i = 0; i < 6; i++)
        {
            var found = false;
            uint best = high ? 0 : uint.MaxValue;
            int bx = 0, by = 0;
            for (var y = 0; y < side - ks; y++)
            {
                for (var x = 0; x < side - 1 - ks; x++)
                {
                    var z = map[y, x];
                    if (high ? z <= best : z >= best) continue;
                    var overlap = false;
                    for (var j = 0; j < i; j++)
                    {
                        if (x + ks > xs[j] && x < xs[j] + ks && y + ks > ys[j] && y < ys[j] + ks)
                        {
                            overlap = true;
                            break;
                        }
                    }
                    if (!overlap)
                    {
                        best = z;
                        bx = x;
                        by = y;
                        found = true;
                    }
                }
            }
            if (!found) break;
            avg[i] = (byte)Math.Min(255, best / (uint)(ks * ks));
            xs[i] = (byte)bx;
            ys[i] = (byte)by;
        }
    }

    private static int Match3(byte[] a1, byte[] x1, byte[] y1, byte[] a2, byte[] x2, byte[] y2, int max, int side) =>
        Match3u(a1.Select(v => (uint)v).ToArray(), x1, y1, a2.Select(v => (uint)v).ToArray(), x2, y2, max, side);

    private static int Match3(uint[] a1, byte[] x1, byte[] y1, uint[] a2, byte[] x2, byte[] y2, int max, int side) =>
        Match3u(a1, x1, y1, a2, x2, y2, max, side);

    private static int Match3u(uint[] a1, byte[] x1, byte[] y1, uint[] a2, byte[] x2, byte[] y2, int max, int side)
    {
        var ks = side / 4;
        var total = 0;
        for (var i = 0; i < 3; i++)
        {
            var best = 0;
            for (var j = 0; j < 3; j++)
            {
                var dx = x1[i] - x2[j];
                var dy = y1[i] - y2[j];
                var d = Math.Sqrt(dx * dx + dy * dy);
                if (d <= ks * .75 && Math.Abs((long)a1[i] - a2[j]) <= max / 5)
                    best = Math.Max(best, 100 - (int)(d * 60 / (ks * .75)));
            }
            total += best;
        }
        return total / 3;
    }

    private static int MatchBw(uint[] a1, byte[] x1, byte[] y1, uint[] a2, byte[] x2, byte[] y2, int side)
    {
        var ks = side / 4;
        var total = 0;
        for (var i = 0; i < 6; i++)
        {
            var best = 0;
            for (var j = 0; j < 6; j++)
            {
                var dx = x1[i] - x2[j];
                var dy = y1[i] - y2[j];
                var d = Math.Sqrt(dx * dx + dy * dy);
                if (d <= ks * .75 && Math.Abs((long)a1[i] - a2[j]) <= 51)
                    best = Math.Max(best, 100 - (int)(d * 60 / (ks * .75)));
            }
            total += best;
        }
        return total / 6;
    }

    private static uint[] Concat(uint[] a, uint[] b) => a.Concat(b).ToArray();
    private static uint[] Concat(byte[] a, uint[] b) => a.Select(static v => (uint)v).Concat(b).ToArray();
    private static byte[] Concat(byte[] a, byte[] b) => a.Concat(b).ToArray();
    private static int Spread(byte a, byte b)
    {
        var d = Math.Abs(a - b) * 10;
        return d < 100 ? 100 - d : 0;
    }

    // Port of pe_icons.c scaling logic.
    public static RgbImage PrepareForClam(RgbImage source)
    {
        var width = source.Width;
        var height = source.Height;
        if (width < 16 || height < 16 || width > 256 || height > 256) return source;
        if (width < height * 3 / 4 || height < width * 3 / 4) return source;

        var scalemode = 2;
        if (width == height)
        {
            if (width is 16 or 24 or 32) scalemode = 0;
            else if (width % 32 == 0 || width % 24 == 0) scalemode = 1;
        }
        if (scalemode == 0) return source;

        var image = source;
        if (scalemode == 1)
        {
            var w = image.Width;
            var h = image.Height;
            while (w > 32)
            {
                if (w < 2 || h < 2) break;
                var nw = w / 2;
                var nh = h / 2;
                var pixels = new byte[nw * nh * 3];
                for (var y = 0; y < nh; y++)
                {
                    for (var x = 0; x < nw; x++)
                    {
                        var p00 = image.Index(x * 2, y * 2);
                        var p01 = image.Index(x * 2 + 1, y * 2);
                        var p10 = image.Index(x * 2, y * 2 + 1);
                        var p11 = image.Index(x * 2 + 1, y * 2 + 1);
                        var q = (y * nw + x) * 3;
                        pixels[q]     = Average4(image.Pixels[p00], image.Pixels[p01], image.Pixels[p10], image.Pixels[p11]);
                        pixels[q + 1] = Average4(image.Pixels[p00 + 1], image.Pixels[p01 + 1], image.Pixels[p10 + 1], image.Pixels[p11 + 1]);
                        pixels[q + 2] = Average4(image.Pixels[p00 + 2], image.Pixels[p01 + 2], image.Pixels[p10 + 2], image.Pixels[p11 + 2]);
                    }
                }
                image = new RgbImage(nw, nh, pixels);
                w = nw;
                h = nh;
            }
            return image;
        }

        var d32 = Math.Abs(width - 32) + Math.Abs(height - 32);
        var d24 = Math.Abs(width - 24) + Math.Abs(height - 24);
        var newSize = d32 < d24 ? 32 : d24 < (Math.Abs(width - 16) + Math.Abs(height - 16)) ? 24 : 16;
        var scalex = (double)width / newSize;
        var scaley = (double)height / newSize;
        var output = new byte[newSize * newSize * 3];
        for (var y = 0; y < newSize; y++)
        {
            var oldy = (int)(y * scaley);
            for (var x = 0; x < newSize; x++)
            {
                var oldx = Math.Min(width - 1, (int)(x * scalex + 0.5f));
                var src = image.Index(oldx, Math.Min(height - 1, oldy));
                var dst = (y * newSize + x) * 3;
                output[dst] = image.Pixels[src];
                output[dst + 1] = image.Pixels[src + 1];
                output[dst + 2] = image.Pixels[src + 2];
            }
        }
        return new RgbImage(newSize, newSize, output);
    }

    private static byte Average4(byte a, byte b, byte c, byte d)
    {
        var ab = (a & b) + (((a ^ b) & 0xfe) >> 1);
        var cd = (c & d) + (((c ^ d) & 0xfe) >> 1);
        return (byte)((ab & cd) + (((ab ^ cd) & 0xfe) >> 1));
    }

    private static double LabDiff(byte r0, byte g0, byte b0)
    {
        double r = r0 / 255.0, g = g0 / 255.0, b = b0 / 255.0;
        r = r > 0.04045 ? Math.Pow((r + 0.055) / 1.055, 2.4) : r / 12.92;
        g = g > 0.04045 ? Math.Pow((g + 0.055) / 1.055, 2.4) : g / 12.92;
        b = b > 0.04045 ? Math.Pow((b + 0.055) / 1.055, 2.4) : b / 12.92;
        var x = (0.4124 * r + 0.3576 * g + 0.1805 * b) * 100 / 95.047;
        var y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
        var z = (0.0193 * r + 0.1192 * g + 0.9505 * b) * 100 / 108.883;
        x = x > 0.008856 ? Math.Pow(x, 1 / 3.0) : 7.787 * x + 16 / 116.0;
        y = y > 0.008856 ? Math.Pow(y, 1 / 3.0) : 7.787 * y + 16 / 116.0;
        z = z > 0.008856 ? Math.Pow(z, 1 / 3.0) : 7.787 * z + 16 / 116.0;
        var l = 116 * y - 16;
        var a = 500 * (x - y);
        var bb = 200 * (y - z);
        var dl = l - 53.192777691077211;
        var da = a - 0.0031420942181448197;
        var db = bb + 0.0062075877844014471;
        return Math.Sqrt(dl * dl + da * da + db * db);
    }
}
