internal static partial class Program
{
    private static byte[] BuildMinimalPe()
    {
        var data = new byte[0x600];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3c), 0x80);
        data[0x80] = (byte)'P'; data[0x81] = (byte)'E';
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x86), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94), 0xE0);
        var opt = 0x98;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(opt), 0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 16), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 60), 0x200);
        var section = 0x178;
        ".text"u8.CopyTo(data.AsSpan(section));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 20), 0x200);
        "ABCD"u8.CopyTo(data.AsSpan(0x200));
        data[0x204] = (byte)'E';
        return data;
    }

    private static byte[] BuildPeWithImport(bool pe32Plus, string library = "KERNEL32.dll", string function = "CreateFileA")
    {
        var optionalSize = pe32Plus ? 0xF0 : 0xE0;
        var section = 0x98 + optionalSize;
        var data = new byte[0x600];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3c), 0x80);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x80), 0x00004550);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x84), pe32Plus ? (ushort)0x8664 : (ushort)0x14c);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x86), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94), (ushort)optionalSize);
        var opt = 0x98;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(opt), pe32Plus ? (ushort)0x20B : (ushort)0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 16), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 32), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 36), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 56), 0x2000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 60), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 92), 16);
        var dd = opt + (pe32Plus ? 112 : 96);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(dd + 8), 0x1100);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(dd + 12), 0x28);

        ".text"u8.CopyTo(data.AsSpan(section));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8), 0x400);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12), 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16), 0x400);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 20), 0x200);

        // Import descriptor at RVA 0x1100 -> raw 0x300.
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x300), 0x1180);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x30C), 0x1160);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x310), 0x1190);
        // INT and IAT point to one IMAGE_IMPORT_BY_NAME record.
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x380), 0x1198);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x390), 0x1198);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x398), 0);
        Encoding.ASCII.GetBytes(function + "\0").CopyTo(data.AsSpan(0x39A));
        Encoding.ASCII.GetBytes(library + "\0").CopyTo(data.AsSpan(0x360));
        return data;
    }
}
