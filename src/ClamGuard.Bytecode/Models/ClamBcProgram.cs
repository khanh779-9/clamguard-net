using System.Buffers.Binary;

namespace ClamGuard.Bytecode;

internal sealed record ClamBcProgram(
    BytecodeMetadata Metadata,
    IReadOnlyList<ClamBcType> Types,
    IReadOnlyDictionary<int, string> ApiNames,
    IReadOnlyList<ulong[]> Globals,
    IReadOnlyList<ClamBcFunction> Functions,
    string RuleFile)
{
    public bool IsCompatible(int level)
        => Metadata.FormatLevel is 6 or 7
        && (Metadata.MinimumFunctionality == 0 || level >= Metadata.MinimumFunctionality)
        && (Metadata.MaximumFunctionality == 0 || level <= Metadata.MaximumFunctionality);

    public bool IsEligibleForFile(ReadOnlySpan<byte> data)
    {
        var hasPe = data.Length >= 2 && data[0] == (byte)'M' && data[1] == (byte)'Z';
        var hasElf = data.Length >= 4 && data[0] == 0x7F && data[1] == (byte)'E' && data[2] == (byte)'L' && data[3] == (byte)'F';
        var hasMachO = data.Length >= 4 && (
            BinaryPrimitives.ReadUInt32BigEndian(data[..4]) is 0xFEEDFACE or 0xFEEDFACF or 0xCAFEBABE or 0xCAFEBABF ||
            BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) is 0xFEEDFACE or 0xFEEDFACF or 0xBEBAFECA or 0xBFBAFECA);
        var hasPdf = data.Length >= 5 && data[..5].SequenceEqual("%PDF-"u8);
        return Metadata.Kind switch
        {
            ClamBcKind.PeUnpacker or ClamBcKind.PeAll => hasPe,
            ClamBcKind.ElfUnpacker => hasElf,
            ClamBcKind.MachOUnpacker => hasMachO,
            ClamBcKind.Pdf => hasPdf,
            _ => true
        };
    }
}
