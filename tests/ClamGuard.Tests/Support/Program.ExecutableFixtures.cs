internal static partial class Program
{
    private static byte[] BuildMachOFat32TwoSlices()
    {
        const int first = 0x40, second = 0x80, sliceSize = 0x40;
        var data = new byte[second + sliceSize];
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0), 0xCAFEBABE);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 2);

        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), 0x01000007);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), 3);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16), first);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20), sliceSize);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(24), 2);

        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28), 0x0000000C);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(32), 0);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(36), second);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(40), sliceSize);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(44), 2);

        // Both entries are valid thin x86_64 Mach-O headers; only the second carries
        // the test signature.
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first), 0xFEEDFACF);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first + 4), 0x01000007);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first + 8), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first + 12), 2);

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second), 0xFEEDFACF);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second + 4), 0x01000007);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second + 8), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second + 12), 2);
        new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }.AsSpan().CopyTo(data.AsSpan(second + 0x20, 4));
        return data;
    }

    private static byte[] BuildMinimalElf32()
    {
        var data = new byte[160];
        data[0] = 0x7f; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
        data[4] = 1; data[5] = 1; data[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(16), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(18), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(24), 0x08048000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(28), 52);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), 84);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(40), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(42), 32);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(44), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(46), 40);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(48), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(50), 0);
        // PT_LOAD covering the file; entry virtual address resolves to raw offset 0.
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(52), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(56), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(60), 0x08048000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(64), 0x08048000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(68), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(72), (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(76), 5);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(80), 0x1000);
        return data;
    }

    private static byte[] BuildMachO64WithSection()
    {
        const int loadCommandSize = 152;
        const int sectionOffset = 0x200;
        var data = new byte[0x300];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 0xFEEDFACF);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0x01000007);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(12), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), loadCommandSize);
        // LC_SEGMENT_64
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), 0x19);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(36), loadCommandSize);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(56), 0);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(64), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(72), 0x100);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(80), sectionOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(88), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(96), 7);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(100), 5);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(104), 1);
        var section = 32 + 72;
        "__text"u8.CopyTo(data.AsSpan(section));
        "__TEXT"u8.CopyTo(data.AsSpan(section + 16));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(section + 32), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(section + 40), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 48), sectionOffset);
        "MACH"u8.CopyTo(data.AsSpan(sectionOffset));
        return data;
    }

    private static byte[] BuildMachOFat32()
    {
        var thin = BuildMachO64WithSection();
        var data = new byte[0x20 + thin.Length];
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0), 0xCAFEBABE);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), 0x01000007);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), 3);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16), 0x20);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20), (uint)thin.Length);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(24), 2);
        thin.CopyTo(data.AsSpan(0x20));
        return data;
    }
}
