internal static partial class Program
{
    private static byte[] CreateZipEntry(string name, byte[] content)
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry(name, System.IO.Compression.CompressionLevel.NoCompression);
            using var output = entry.Open();
            output.Write(content);
        }
        return ms.ToArray();
    }

    private static byte[] CreateBinHex(string fileName, byte[] content)
    {
        const string alphabet = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        using var raw = new MemoryStream();
        var name = Encoding.ASCII.GetBytes(fileName);
        raw.WriteByte((byte)name.Length);
        raw.Write(name);
        raw.WriteByte(1); // BinHex file version byte
        raw.Write("TEXT"u8);
        raw.Write("ttxt"u8);
        raw.Write(new byte[2]);
        Span<byte> lengths = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(lengths, (uint)content.Length);
        BinaryPrimitives.WriteUInt32BigEndian(lengths[4..], 0);
        raw.Write(lengths);
        raw.Write(new byte[2]);
        foreach (var b in content)
        {
            if (b == 0x90) { raw.WriteByte(0x90); raw.WriteByte(0); }
            else raw.WriteByte(b);
        }
        raw.Write(new byte[2]);
        raw.Write(new byte[2]);
        var bytes = raw.ToArray();
        using var encoded = new MemoryStream();
        uint acc = 0; var bits = 0;
        foreach (var b in bytes)
        {
            acc = (acc << 8) | b; bits += 8;
            while (bits >= 6)
            {
                bits -= 6;
                encoded.WriteByte((byte)alphabet[(int)((acc >> bits) & 0x3f)]);
            }
        }
        if (bits != 0) encoded.WriteByte((byte)alphabet[(int)((acc << (6 - bits)) & 0x3f)]);
        var prefix = Encoding.ASCII.GetBytes("(This file must be converted with BinHex 4.0)\r\n");
        var all = new MemoryStream(); all.Write(prefix); all.WriteByte((byte)':'); all.WriteByte((byte)'\r'); all.WriteByte((byte)'\n'); all.Write(encoded.ToArray()); all.WriteByte((byte)':'); all.WriteByte((byte)'\r'); all.WriteByte((byte)'\n');
        return all.ToArray();
    }

    private static byte[] CreateUuEncoded(string fileName, byte[] content)
    {
        using var ms = new MemoryStream();
        var begin = Encoding.ASCII.GetBytes($"begin 644 {fileName}\n");
        ms.Write(begin);
        Span<byte> quad = stackalloc byte[4];
        for (var offset = 0; offset < content.Length; offset += 45)
        {
            var count = Math.Min(45, content.Length - offset);
            ms.WriteByte((byte)(' ' + count));
            for (var i = 0; i < count; i += 3)
            {
                var remaining = Math.Min(3, count - i);
                var a = content[offset + i];
                var b = remaining > 1 ? content[offset + i + 1] : (byte)0;
                var c = remaining > 2 ? content[offset + i + 2] : (byte)0;
                quad[0] = (byte)(' ' + ((a >> 2) & 0x3f));
                quad[1] = (byte)(' ' + (((a << 4) | (b >> 4)) & 0x3f));
                quad[2] = (byte)(' ' + (((b << 2) | (c >> 6)) & 0x3f));
                quad[3] = (byte)(' ' + (c & 0x3f));
                ms.Write(quad);
            }
            ms.WriteByte((byte)'\n');
        }
        ms.Write(" \nend\n"u8);
        return ms.ToArray();
    }

    private static byte[] CreateTnef(string fileName, byte[] content)
    {
        using var ms = new MemoryStream();
        var u32 = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(u32, 0x223E9F78u); ms.Write(u32);
        var u16 = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(u16, 0x0100); ms.Write(u16);
        void Attr(byte level, ushort type, ushort tag, byte[] value)
        {
            ms.WriteByte(level);
            BinaryPrimitives.WriteUInt32LittleEndian(u32, ((uint)type << 16) | tag); ms.Write(u32);
            BinaryPrimitives.WriteInt32LittleEndian(u32, value.Length); ms.Write(u32);
            ms.Write(value);
            BinaryPrimitives.WriteUInt16LittleEndian(u16, 0); ms.Write(u16);
        }
        Attr(2, 1, 0x8010, Encoding.ASCII.GetBytes(fileName + "\0"));
        Attr(2, 2, 0x800f, content);
        return ms.ToArray();
    }

    private static byte[] BuildIsoHeaderSample()
    {
        var data = new byte[32774];
        data[32768] = 1;
        "CD001"u8.CopyTo(data.AsSpan(32769));
        return data;
    }

    private static byte[] BuildDmgTrailerSample()
    {
        var data = new byte[1024];
        "koly"u8.CopyTo(data.AsSpan(512));
        return data;
    }

    private static byte[] CreateTarEntry(string name, byte[] content)
    {
        using var ms = new MemoryStream();
        var header = new byte[512];
        Encoding.ASCII.GetBytes(name).AsSpan().CopyTo(header.AsSpan(0, Math.Min(name.Length, 100)));
        Encoding.ASCII.GetBytes(Convert.ToString(0x1a4, 8).PadLeft(7, '0') + "\0").AsSpan().CopyTo(header.AsSpan(100, 8));
        Encoding.ASCII.GetBytes(Convert.ToString(content.Length, 8).PadLeft(11, '0') + "\0").AsSpan().CopyTo(header.AsSpan(124, 12));
        header[156] = (byte)'0';
        "ustar"u8.CopyTo(header.AsSpan(257));
        "00"u8.CopyTo(header.AsSpan(263));
        for (var i = 148; i < 156; i++) header[i] = (byte)' ';
        var checksum = header.Sum(static b => (int)b);
        Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8).PadLeft(6, '0') + " \0").AsSpan().CopyTo(header.AsSpan(148, 8));
        ms.Write(header);
        ms.Write(content);
        var pad = (512 - (content.Length % 512)) % 512;
        if (pad != 0) ms.Write(new byte[pad]);
        ms.Write(new byte[1024]);
        return ms.ToArray();
    }

    private static byte[] CreateOldTarEntry(string name, byte[] content)
    {
        var data = CreateTarEntry(name, content);
        var header = data.AsSpan(0, 512);
        header.Slice(257, 8).Clear();
        // Tar checksums are computed with the checksum field treated as spaces;
        // reset it first so the previous POSIX checksum text is not summed in.
        header.Slice(148, 8).Fill((byte)' ');
        var checksum = 0;
        foreach (var b in header) checksum += b;
        Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8).PadLeft(6, '0') + " \0").AsSpan().CopyTo(header.Slice(148, 8));
        return data;
    }

    private static byte[] CreateGzip(byte[] content)
    {
        using var ms = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(content);
        return ms.ToArray();
    }

    private static byte[] CreateCpioNewc(string name, byte[] content)
    {
        static string Hex32(uint value) => value.ToString("x8");
        var fileName = Encoding.ASCII.GetBytes(name + "\0");
        using var ms = new MemoryStream();
        void Header(uint mode, uint size, uint nameSize)
        {
            var text = "070701" + Hex32(1) + Hex32(mode) + Hex32(0) + Hex32(0) + Hex32(1) + Hex32(0) + Hex32(size) +
                       Hex32(0) + Hex32(0) + Hex32(0) + Hex32(0) + Hex32(nameSize) + Hex32(0);
            ms.Write(Encoding.ASCII.GetBytes(text));
        }
        Header(0x81A4, (uint)content.Length, (uint)fileName.Length);
        ms.Write(fileName);
        while (ms.Length % 4 != 0) ms.WriteByte(0);
        ms.Write(content);
        while (ms.Length % 4 != 0) ms.WriteByte(0);
        var trailer = Encoding.ASCII.GetBytes("TRAILER!!!\0");
        Header(0, 0, (uint)trailer.Length);
        ms.Write(trailer);
        while (ms.Length % 4 != 0) ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] CreateCpioOld(string name, byte[] content, bool littleEndian = true)
    {
        using var ms = new MemoryStream();
        var nameBytes = Encoding.ASCII.GetBytes(name + "\0");
        void U16(ushort value)
        {
            Span<byte> b = stackalloc byte[2];
            if (littleEndian) BinaryPrimitives.WriteUInt16LittleEndian(b, value);
            else BinaryPrimitives.WriteUInt16BigEndian(b, value);
            ms.Write(b);
        }
        void U32(uint value)
        {
            Span<byte> b = stackalloc byte[4];
            if (littleEndian) BinaryPrimitives.WriteUInt32LittleEndian(b, value);
            else BinaryPrimitives.WriteUInt32BigEndian(b, value);
            ms.Write(b);
        }
        U16(0x71C7);
        U16(0); U16(1); U16(0x81A4); U16(0); U16(0); U16(1); U16(0);
        U32(0); U16((ushort)nameBytes.Length); U32((uint)content.Length);
        ms.Write(nameBytes);
        if ((ms.Length & 1) != 0) ms.WriteByte(0);
        ms.Write(content);
        if ((ms.Length & 1) != 0) ms.WriteByte(0);
        U16(0x71C7);
        U16(0); U16(0); U16(0); U16(0); U16(0); U16(0); U16(0); U32(0);
        var trailer = Encoding.ASCII.GetBytes("TRAILER!!!\0");
        U16((ushort)trailer.Length); U32(0);
        ms.Write(trailer);
        if ((ms.Length & 1) != 0) ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] CreatePdfAsciiHex(byte[] content)
    {
        var hex = Encoding.ASCII.GetBytes(Convert.ToHexString(content) + ">");
        var prefix = Encoding.ASCII.GetBytes($"%PDF-1.7\n1 0 obj\n<< /Length {hex.Length} /Filter /ASCIIHexDecode >>\nstream\n");
        var suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n%%EOF\n");
        return prefix.Concat(hex).Concat(suffix).ToArray();
    }

    private static bool TryNativeCompress(string executable, string extension, byte[] content, out byte[] archive)
    {
        archive = [];
        var inputPath = Path.Combine(Path.GetTempPath(), "clamguard-test-" + Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(inputPath, content);
            var psi = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            if (executable.Equals("bzip2", StringComparison.OrdinalIgnoreCase) || executable.EndsWith("bzip2.exe", StringComparison.OrdinalIgnoreCase))
            {
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add("--");
                psi.ArgumentList.Add(inputPath);
            }
            else
            {
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add("--");
                psi.ArgumentList.Add(inputPath);
            }
            using var process = Process.Start(psi);
            if (process is null) return false;
            using var ms = new MemoryStream();
            process.StandardOutput.BaseStream.CopyTo(ms);
            process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0) return false;
            archive = ms.ToArray();
            return archive.Length != 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            try { File.Delete(inputPath); } catch { }
        }
    }

    private static byte[] CreateCpioOdc(string name, byte[] content)
    {
        static string Octal(int value, int width) => Convert.ToString(value, 8).PadLeft(width, '0');
        using var ms = new MemoryStream();
        var nameBytes = Encoding.ASCII.GetBytes(name + "\0");
        var fields = new[] {
            "070707", Octal(0, 6), Octal(1, 6), Octal(0x81A4, 6), Octal(0, 6), Octal(0, 6),
            Octal(1, 6), Octal(0, 6), Octal(0, 11), Octal(nameBytes.Length, 6), Octal(content.Length, 11) };
        ms.Write(Encoding.ASCII.GetBytes(string.Concat(fields)));
        ms.Write(nameBytes);
        if (ms.Length % 2 != 0) ms.WriteByte(0);
        ms.Write(content);
        if (ms.Length % 2 != 0) ms.WriteByte(0);
        var trailer = Encoding.ASCII.GetBytes(string.Concat(new[] {
            "070707", Octal(0, 6), Octal(0, 6), Octal(0, 6), Octal(0, 6), Octal(0, 6),
            Octal(0, 6), Octal(0, 6), Octal(0, 11), Octal(11, 6), Octal(0, 11) }));
        ms.Write(trailer);
        ms.Write(Encoding.ASCII.GetBytes("TRAILER!!!\0"));
        if (ms.Length % 2 != 0) ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] CreatePdfFlate(byte[] content)
    {
        using var compressed = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
            z.Write(content);
        var c = compressed.ToArray();
        var prefix = Encoding.ASCII.GetBytes($"%PDF-1.7\n1 0 obj\n<< /Length {c.Length} /Filter /FlateDecode >>\nstream\n");
        var suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n%%EOF\n");
        return prefix.Concat(c).Concat(suffix).ToArray();
    }

    private static byte[] CreateCwsSwf(byte[] body)
    {
        using var compressed = new MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
            z.Write(body);
        using var ms = new MemoryStream();
        ms.Write("CWS"u8);
        ms.WriteByte(9);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)(body.Length + 8));
        ms.Write(len);
        ms.Write(compressed.ToArray());
        return ms.ToArray();
    }

    private static byte[] BuildAutoItMarker()
    {
        var magic = Convert.FromHexString("a3484bbe986c4aa9994c530a86d6487d41555321454130");
        return magic.Concat(new byte[] { 0x35 }).Concat("AUTOIT"u8.ToArray()).ToArray();
    }

    private static byte[] BuildInstallShieldMarker()
    {
        using var ms = new MemoryStream();
        ms.Write("InstallShield\0"u8);
        ms.Write(new byte[292]);
        ms.WriteByte(0x06);
        ms.Write(new byte[7]);
        ms.Write(new byte[16]);
        Span<byte> one = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(one, 1);
        ms.Write(one);
        return ms.ToArray();
    }

    private static byte[] BuildMinimalSisHeader()
    {
        var data = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 0x10201A7A);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 0x10000419);
        return data;
    }

    private static byte[] BuildMinimalSzddHeader()
    {
        var data = new byte[14];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 0x44445A53);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0x3327F088);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8), 0x0041);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(10), 1);
        return data;
    }

    private static byte[] CreatePdfLzw(byte[] content)
    {
        var codes = new List<int>(content.Length + 2) { 256 };
        codes.AddRange(content.Select(static b => (int)b));
        codes.Add(257);

        var output = new List<byte>();
        uint bitBuffer = 0;
        var bitCount = 0;
        foreach (var code in codes)
        {
            bitBuffer = (bitBuffer << 9) | (uint)code;
            bitCount += 9;
            while (bitCount >= 8)
            {
                bitCount -= 8;
                output.Add((byte)((bitBuffer >> bitCount) & 0xFF));
                bitBuffer &= bitCount == 0 ? 0u : (uint)((1UL << bitCount) - 1);
            }
        }
        if (bitCount != 0)
            output.Add((byte)(bitBuffer << (8 - bitCount)));

        using var ms = new MemoryStream();
        var dict = $"<< /Length {output.Count} /Filter /LZWDecode /DecodeParms << /EarlyChange 1 >> >>\nstream\n";
        ms.Write(Encoding.ASCII.GetBytes("%PDF-1.7\n"));
        ms.Write(Encoding.ASCII.GetBytes(dict));
        ms.Write(output.ToArray());
        ms.Write(Encoding.ASCII.GetBytes("\nendstream\n%%EOF\n"));
        return ms.ToArray();
    }

    private static byte[] CreateMinimalOle2(byte[] content)
    {
        const int sectorSize = 512;
        const int streamSectors = 8;
        var data = new byte[sectorSize + sectorSize * (2 + streamSectors + 1)];
        var header = data.AsSpan(0, 512);
        header[0] = 0xD0; header[1] = 0xCF; header[2] = 0x11; header[3] = 0xE0; header[4] = 0xA1; header[5] = 0xB1; header[6] = 0x1A; header[7] = 0xE1;
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(28, 2), 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(30, 2), 9);
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(32, 2), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(40, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(44, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(48, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(56, 4), 4096);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(60, 4), 0xFFFFFFFE);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(64, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(68, 4), 0xFFFFFFFE);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(72, 4), 0);
        for (var i = 0; i < 109; i++) BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(76 + i * 4, 4), 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(76, 4), 2 + streamSectors);

        var dir = data.AsSpan(512, 512);
        WriteOleDirEntry(dir.Slice(0, 128), "Root Entry", 5, 0xFFFFFFFF, 0);
        WriteOleDirEntry(dir.Slice(128, 128), "Payload", 2, 2, 4096);

        var fat = data.AsSpan(512 + (2 + streamSectors) * sectorSize, sectorSize);
        for (var i = 0; i < 128; i++) BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(i * 4, 4), 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(0, 4), 0xFFFFFFFE); // directory sector 0 ends the chain
        for (var i = 0; i < streamSectors; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice((2 + i) * 4, 4), i + 2 == 2 + streamSectors - 1 ? 0xFFFFFFFEu : (uint)(3 + i));
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice((2 + streamSectors) * 4, 4), 0xFFFFFFFD); // FAT sector marks itself

        var stream = data.AsSpan(512 + 2 * sectorSize, streamSectors * sectorSize);
        content.AsSpan(0, Math.Min(content.Length, stream.Length)).CopyTo(stream);
        return data;

        static void WriteOleDirEntry(Span<byte> entry, string name, byte objectType, uint startSector, ulong size)
        {
            var nameBytes = Encoding.Unicode.GetBytes(name + "\0");
            nameBytes.AsSpan(0, Math.Min(nameBytes.Length, 64)).CopyTo(entry);
            BinaryPrimitives.WriteUInt16LittleEndian(entry.Slice(64, 2), (ushort)Math.Min(64, nameBytes.Length));
            entry[66] = objectType;
            BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(68, 4), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(72, 4), 0xFFFFFFFF);
            BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(76, 4), objectType == 5 ? 0xFFFFFFFFu : 0xFFFFFFFFu);
            BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(116, 4), startSector);
            BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(120, 8), size);
        }
    }
}
