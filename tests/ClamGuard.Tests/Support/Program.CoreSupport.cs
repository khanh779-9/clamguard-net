internal static partial class Program
{
    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("TEST FAILED: " + message);
        Console.WriteLine("PASS: " + message);
    }

    private static void WriteCvdFixture(string path, uint version, string ndbLine, bool truncatePayload = false)
    {
        using var tarBuffer = new MemoryStream();
        using (var tarWriter = new TarWriter(tarBuffer, TarEntryFormat.Ustar, leaveOpen: true))
        {
            var copying = new UstarTarEntry(TarEntryType.RegularFile, "COPYING")
            { DataStream = new MemoryStream(Encoding.ASCII.GetBytes("ClamAV raw-tar fixture\n")) };
            tarWriter.WriteEntry(copying);

            var entry = new UstarTarEntry(TarEntryType.RegularFile, "selection.ndb")
            { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(ndbLine)) };
            tarWriter.WriteEntry(entry);
        }

        var payload = tarBuffer.ToArray();
        using var file = File.Create(path);
        var headerBytes = new byte[512];
        var header = Encoding.ASCII.GetBytes($"ClamAV-VDB:01 Jan 2026 00-00 +0000:{version}:1:150:abc:def:builder:1767225600\n");
        header.CopyTo(headerBytes, 0);
        file.Write(headerBytes);
        if (!truncatePayload)
            file.Write(payload);
    }

    private static uint RarCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var i = 0; i < 8; i++)
                crc = (crc >> 1) ^ (0xEDB88320u & (uint)-(int)(crc & 1));
        }
        return crc ^ 0xFFFFFFFFu;
    }

    private static byte[] BuildRar4Block(byte type, ushort flags, ReadOnlySpan<byte> body)
    {
        var size = checked(7 + body.Length);
        var block = new byte[size];
        block[2] = type;
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(3, 2), flags);
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(5, 2), checked((ushort)size));
        body.CopyTo(block.AsSpan(7));
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(0, 2), checked((ushort)RarCrc32(block.AsSpan(2))));
        return block;
    }

    private static byte[] CreateMinimalRar4(string name, byte[] content)
    {
        var nameBytes = Encoding.ASCII.GetBytes(name);
        var mainBody = new byte[6]; // RESERVED1 + RESERVED2
        var main = BuildRar4Block(0x73, 0, mainBody);

        var fileBody = new byte[25 + nameBytes.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(0, 4), checked((uint)content.Length)); // PACK_SIZE
        BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(4, 4), checked((uint)content.Length)); // UNP_SIZE
        fileBody[8] = 0; // HOST_OS
        BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(9, 4), RarCrc32(content));
        BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(13, 4), 0); // FTIME
        fileBody[17] = 20; // UNP_VER
        fileBody[18] = 0x30; // METHOD: store
        BinaryPrimitives.WriteUInt16LittleEndian(fileBody.AsSpan(19, 2), checked((ushort)nameBytes.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(21, 4), 0); // ATTR
        nameBytes.CopyTo(fileBody.AsSpan(25));
        var file = BuildRar4Block(0x74, 0, fileBody);
        var end = BuildRar4Block(0x7B, 0, []);

        return [
            0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00,
            ..main,
            ..file,
            ..content,
            ..end
        ];
    }

    private static string EncodeBcNumber(ulong value)
    {
        var digits = Math.Max(1, (64 - System.Numerics.BitOperations.LeadingZeroCount(value) + 3) / 4);
        var chars = new char[digits + 1];
        chars[0] = (char)(0x60 + digits);
        for (var i = 0; i < digits; i++)
            chars[i + 1] = (char)(0x60 + ((value >> (i * 4)) & 0xF));
        return new string(chars);
    }

    private static string EncodeBcFixed(ulong value, int width)
    {
        var chars = new char[width];
        for (var i = 0; i < width; i++)
            chars[i] = (char)(0x60 + ((value >> (i * 4)) & 0xF));
        return new string(chars);
    }

    private static string EncodeBcString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value + "\0");
        return "|" + EncodeBcNumber((ulong)bytes.Length) + new string(bytes.SelectMany(b => new[] { (char)(0x60 + (b & 0xF)), (char)(0x60 + (b >> 4)) }).ToArray());
    }

    private static string BuildMinimalClamBc()
    {
        var magic1 = 0x53e5493e9f3d1c30UL;
        var header = "ClamBC" + EncodeBcNumber(6) + EncodeBcNumber(0) + EncodeBcString("test") +
                     EncodeBcNumber(0) + EncodeBcNumber(0) + EncodeBcNumber(0) + EncodeBcNumber(0) + EncodeBcNumber(0) +
                     EncodeBcString("test") + EncodeBcNumber(0) + EncodeBcNumber(1) + EncodeBcNumber(magic1) + EncodeBcFixed(42, 2) + ":";
        var typeTable = "T" + EncodeBcFixed(69, 2);
        var apis = "E" + EncodeBcNumber(0) + EncodeBcNumber(0);
        var globals = "G" + EncodeBcNumber(0) + EncodeBcNumber(0);
        var function = "A" + EncodeBcFixed(0, 1) + EncodeBcNumber(1) + "L" + EncodeBcNumber(0) + "F" + EncodeBcNumber(1) + EncodeBcNumber(1);
        var block = "B" + EncodeBcNumber(1) + EncodeBcNumber(0) + EncodeBcFixed(20, 2);
        return string.Join("\n", new[] { header, "Test", typeTable, apis, globals, function, block, "S" });
    }

    private static string BcNumber(ulong value)
    {
        if (value == 0) return "`";
        var digits = new List<char>();
        var v = value;
        while (v != 0) { digits.Add((char)(0x60 + (v & 0xF))); v >>= 4; }
        var text = new string(new[] { (char)(0x60 + digits.Count) });
        return text + new string(digits.ToArray());
    }

    private static string BcFixed(int value, int width)
    {
        var chars = new char[width];
        for (var i = 0; i < width; i++) chars[i] = (char)(0x60 + ((value >> (4 * i)) & 0xF));
        return new string(chars);
    }

    private static string BcString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value + "\0");
        var encoded = new StringBuilder();
        foreach (var b in bytes) encoded.Append((char)(0x60 + (b & 0xF))).Append((char)(0x60 + ((b >> 4) & 0xF)));
        return "|" + BcNumber((ulong)bytes.Length) + encoded;
    }

    private static string BcConstant64(ulong value)
    {
        var encoded = new StringBuilder("P");
        for (var i = 0; i < 16; i++) encoded.Append((char)(0x60 + ((value >> (4 * i)) & 0xF)));
        return encoded.ToString();
    }
    private static (string HtmlPath, string AsciiPath) CreateNormalizedTextSamples()
    {
        var htmlPath = Path.Combine(Path.GetTempPath(), "sample-normalized.html");
        File.WriteAllText(htmlPath, "<HTML>\n<!-- remove me -->\n<BODY> HeLLo </BODY>\n</HTML>");
        var asciiPath = Path.Combine(Path.GetTempPath(), "sample-normalized.txt");
        File.WriteAllText(asciiPath, "  HeLLo\tWORLD  ");
        return (htmlPath, asciiPath);
    }
}
