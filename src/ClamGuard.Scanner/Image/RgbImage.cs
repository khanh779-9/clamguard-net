namespace ClamGuard.Scanner;

internal sealed record RgbImage(int Width, int Height, byte[] Pixels)
{
    public int Index(int x, int y) => (y * Width + x) * 3;
}
