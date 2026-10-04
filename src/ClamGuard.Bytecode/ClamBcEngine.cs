using System.Buffers.Binary;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Globalization;
using System.Diagnostics;
using System.IO.Compression;

namespace ClamGuard.Bytecode;

public sealed class ClamBcEngine
{
    private readonly IReadOnlyList<ClamBcProgram> _programs;

    private ClamBcEngine(IReadOnlyList<ClamBcProgram> programs) => _programs = programs;

    public int ProgramCount => _programs.Count;

    public static ClamBcEngine LoadText(string text, string source = "inline.cbc", BytecodeScanOptions? options = null)
    {
        options ??= new BytecodeScanOptions();
        ValidateOptions(options);
        var program = ClamBcParser.Parse(text, source, options);
        return new ClamBcEngine(program is null ? Array.Empty<ClamBcProgram>() : [program]);
    }

    public static ClamBcEngine LoadDirectory(string directory, BytecodeScanOptions? options = null)
    {
        options ??= new BytecodeScanOptions();
        ValidateOptions(options);
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);

        var programs = new List<ClamBcProgram>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.cbc", SearchOption.AllDirectories)
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (programs.Count >= options.MaxRules) break;
            try
            {
                var program = ClamBcParser.Parse(File.ReadAllText(file), file, options);
                if (program is not null) programs.Add(program);
            }
            catch (FormatException)
            {
                // Skip malformed/incompatible bytecode safely.
            }
            catch (OverflowException)
            {
                // Skip integer-overflowing bytecode safely.
            }
            catch (IndexOutOfRangeException)
            {
                // Skip structurally truncated bytecode safely.
            }
            catch (ArgumentException)
            {
                // Skip malformed argument encodings safely.
            }
        }
        return new ClamBcEngine(programs);
    }

    private static void ValidateOptions(BytecodeScanOptions options)
    {
        if (options.MaxRules is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(options.MaxRules));
        if (options.MaxInstructions is < 1 or > 100_000_000) throw new ArgumentOutOfRangeException(nameof(options.MaxInstructions));
        if (options.MaxCallDepth is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(options.MaxCallDepth));
        if (options.MaxAllocatedBytesPerRule is < 4096 or > 512 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(options.MaxAllocatedBytesPerRule));
        if (options.MaxExtractedBytes is < 4096 or > 512 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(options.MaxExtractedBytes));
        if (options.MaxBufferBytes is < 4096 or > 512 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(options.MaxBufferBytes));
        if (options.MaxApiObjects is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(options.MaxApiObjects));
        if (options.MaxRuntime <= TimeSpan.Zero || options.MaxRuntime > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(options.MaxRuntime));
    }

    public IReadOnlyList<BytecodeMatch> Scan(ReadOnlySpan<byte> data, BytecodeScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new BytecodeScanOptions();
        ValidateOptions(options);
        var results = new List<BytecodeMatch>();
        foreach (var program in _programs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!program.IsCompatible(options.EngineFunctionalityLevel)) continue;
            if (!program.IsEligibleForFile(data)) continue;
            var vm = new ClamBcVirtualMachine(program, data, options, cancellationToken);
            var result = vm.Run();
            if (!result.Matched) continue;
            results.Add(new BytecodeMatch(
                string.IsNullOrWhiteSpace(result.VirusName) ? program.Metadata.DefaultName : result.VirusName!,
                program.RuleFile,
                result.Offset,
                result.ReturnValue,
                result.Detail));
        }
        return results;
    }
}

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

internal sealed record ClamBcType(int Id, int Kind, int NumElements, int ContainedType, int Size, int Align)
{
    public bool IsPointer => Id is >= 65 and <= 68 || Kind == 5;
}

internal sealed class ClamBcFunction
{
    public required int ArgumentCount { get; init; }
    public required int[] LocalTypes { get; init; }
    public required List<ClamBcInstruction> Instructions { get; init; }
    public required int BasicBlockCount { get; init; }
    public required List<int> BlockStarts { get; init; }
}

internal sealed record ClamBcOperand(int Index, bool IsConstant = false, ulong Constant = 0, bool IsGlobal = false, int GlobalId = -1);

internal sealed record ClamBcInstruction(
    int Opcode,
    int Type,
    int Destination,
    IReadOnlyList<ClamBcOperand> Operands,
    int TargetTrue = -1,
    int TargetFalse = -1,
    int TargetBlock = -1,
    int ApiOrFunctionId = -1,
    int CastSourceWidth = 0,
    int GepScale = 1);

internal sealed class ClamBcParser
{
    private const ulong Magic1 = 0x53e5493e9f3d1c30UL;
    private const int Magic2 = 42;
    private const int StaticTypeStart = 69;
    private readonly string[] _lines;
    private int _line;
    private readonly List<ClamBcType> _types = [];

    private ClamBcParser(string text)
    {
        _lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
    }

    public static ClamBcProgram? Parse(string text, string file, BytecodeScanOptions options)
    {
        var parser = new ClamBcParser(text);
        return parser.ParseProgram(file, options);
    }

    private ClamBcProgram? ParseProgram(string file, BytecodeScanOptions options)
    {
        var header = NextNonEmpty();
        if (!header.StartsWith("ClamBC", StringComparison.Ordinal)) throw new FormatException("Invalid ClamBC header");
        var metadata = ParseHeader(header);
        if (metadata.FormatLevel is not 6 and not 7) return null;
        if ((metadata.MinimumFunctionality != 0 && metadata.MinimumFunctionality > options.EngineFunctionalityLevel)
            || (metadata.MaximumFunctionality != 0 && metadata.MaximumFunctionality < options.EngineFunctionalityLevel)) return null;

        var logic = NextNonEmpty();
        ParseTypes(NextNonEmpty());
        var apis = ParseApis(NextNonEmpty());
        var globals = ParseGlobals(NextNonEmpty());
        var functions = new List<ClamBcFunction>();

        while (_line < _lines.Length)
        {
            var current = NextNonEmpty();
            if (string.IsNullOrEmpty(current) || current[0] == 'S') break;
            if (current[0] != 'A') throw new FormatException("Expected function header");
            var function = ParseFunctionHeader(current);
            for (var bb = 0; bb < function.BasicBlockCount; bb++)
                ParseBasicBlock(NextNonEmpty(), function);
            if (function.Instructions.Count == 0) throw new FormatException("Empty bytecode function");
            functions.Add(function);
        }

        if (functions.Count == 0) throw new FormatException("No bytecode functions");
        var defaultName = ExtractName(logic, Path.GetFileNameWithoutExtension(file));
        var finalMetadata = metadata with { LogicSignature = logic, DefaultName = defaultName };
        return new ClamBcProgram(finalMetadata, _types, apis, globals, functions, file);
    }

    private BytecodeMetadata ParseHeader(string line)
    {
        var offset = 6;
        var format = checked((int)ReadNumber(line, ref offset));
        var timestamp = ReadNumber(line, ref offset);
        var sigmaker = ReadString(line, ref offset);
        var targetExclude = checked((int)ReadNumber(line, ref offset));
        var kindValue = checked((int)ReadNumber(line, ref offset));
        var min = checked((int)ReadNumber(line, ref offset));
        var max = checked((int)ReadNumber(line, ref offset));
        var maxResource = checked((int)ReadNumber(line, ref offset));
        var compiler = ReadString(line, ref offset);
        _ = ReadNumber(line, ref offset); // num_types
        _ = ReadNumber(line, ref offset); // num_functions
        var magic1 = ReadNumber(line, ref offset);
        var magic2 = ReadFixedNumber(line, ref offset, 2);
        if (magic1 != Magic1 || magic2 != Magic2) throw new FormatException("Invalid ClamBC magic numbers");
        if (offset >= line.Length || line[offset] != ':') throw new FormatException("Missing ClamBC line length");
        return new BytecodeMetadata(
            format,
            timestamp,
            sigmaker,
            targetExclude,
            Enum.IsDefined(typeof(ClamBcKind), kindValue) ? (ClamBcKind)kindValue : ClamBcKind.Generic,
            min,
            max,
            maxResource,
            compiler,
            null,
            string.Empty);
    }

    private void ParseTypes(string line)
    {
        if (!line.StartsWith('T')) throw new FormatException("Invalid type table");
        var offset = 1;
        if (ReadFixedNumber(line, ref offset, 2) != StaticTypeStart) throw new FormatException("Unsupported type table start");
        _types.Clear();
        for (var id = 1; id <= 64; id++)
        {
            var width = Math.Max(1, (id + 7) / 8);
            _types.Add(new ClamBcType(id, 0, 1, 0, width, width));
        }
        for (var id = 65; id <= 68; id++) _types.Add(new ClamBcType(id, 5, 1, id - 61, 8, 8));

        // Parse custom type descriptors sufficiently to validate their bounds and pointer/array widths.
        while (offset < line.Length)
        {
            var kind = ReadFixedNumber(line, ref offset, 1);
            var id = _types.Count + 1;
            switch (kind)
            {
                case 1:
                case 2:
                case 3:
                {
                    var count = checked((int)ReadNumber(line, ref offset));
                    for (var i = 0; i < count; i++) _ = ReadNumber(line, ref offset);
                    _types.Add(new ClamBcType(id, kind, count, 0, 0, 8));
                    break;
                }
                case 4:
                {
                    var count = checked((int)ReadNumber(line, ref offset));
                    var element = checked((int)ReadNumber(line, ref offset));
                    var size = count > 0 && count <= 1_000_000 ? count * TypeSize(element) : 0;
                    _types.Add(new ClamBcType(id, kind, count, element, size, 1));
                    break;
                }
                case 5:
                {
                    var target = checked((int)ReadNumber(line, ref offset));
                    _types.Add(new ClamBcType(id, kind, 1, target, 8, 8));
                    break;
                }
                default:
                    throw new FormatException("Invalid ClamBC type kind");
            }
        }
    }

    private int TypeSize(int id)
        => id is >= 1 and <= 64 ? Math.Max(1, (id + 7) / 8) : _types.FirstOrDefault(t => t.Id == id)?.Size ?? 8;

    private static int TypeWidth(int id) => id switch
    {
        <= 0 => 64,
        <= 1 => 1,
        <= 8 => 8,
        <= 16 => 16,
        <= 32 => 32,
        _ => 64
    };

    private static IReadOnlyDictionary<int, string> ParseApis(string line)
    {
        if (!line.StartsWith('E')) throw new FormatException("Invalid API table");
        var offset = 1;
        var maxApi = ReadNumber(line, ref offset);
        var count = checked((int)ReadNumber(line, ref offset));
        if (maxApi > 512UL || (ulong)count > maxApi) throw new FormatException("Unsafe API table");
        var result = new Dictionary<int, string>();
        for (var i = 0; i < count; i++)
        {
            var id = checked((int)ReadNumber(line, ref offset));
            _ = ReadNumber(line, ref offset); // prototype type
            result[id - 1] = ReadString(line, ref offset);
        }
        return result;
    }

    private static IReadOnlyList<ulong[]> ParseGlobals(string line)
    {
        if (!line.StartsWith('G')) throw new FormatException("Invalid globals table");
        var offset = 1;
        _ = ReadNumber(line, ref offset); // max global id
        var count = checked((int)ReadNumber(line, ref offset));
        if (count < 0 || count > 4096) throw new FormatException("Too many globals");
        var result = new List<ulong[]>(count);
        for (var i = 0; i < count; i++)
        {
            _ = ReadNumber(line, ref offset); // type id
            if (offset + 1 < line.Length && line[offset] == '@' && line[offset + 1] == '`')
            {
                offset += 2;
                result.Add([0]);
                continue;
            }
            var values = new List<ulong>();
            while (offset < line.Length && line[offset] != '`') values.Add(ReadNumber(line, ref offset));
            if (offset < line.Length && line[offset] == '`') offset++;
            result.Add(values.ToArray());
        }
        return result;
    }

    private ClamBcFunction ParseFunctionHeader(string line)
    {
        var offset = 1;
        var args = ReadFixedNumber(line, ref offset, 1);
        _ = ReadNumber(line, ref offset); // return type
        if (offset >= line.Length || line[offset++] != 'L') throw new FormatException("Missing locals header");
        var locals = checked((int)ReadNumber(line, ref offset));
        var total = checked(args + locals);
        var localTypes = new int[total];
        for (var i = 0; i < total; i++)
        {
            localTypes[i] = checked((int)ReadNumber(line, ref offset));
            _ = ReadFixedNumber(line, ref offset, 1); // by-value/pointer marker
        }
        if (offset >= line.Length || line[offset++] != 'F') throw new FormatException("Missing function body header");
        var insts = checked((int)ReadNumber(line, ref offset));
        var blocks = checked((int)ReadNumber(line, ref offset));
        if (insts <= 0 || insts > 10_000_000 || blocks <= 0 || blocks > 65535) throw new FormatException("Unsafe function size");
        return new ClamBcFunction
        {
            ArgumentCount = args,
            LocalTypes = localTypes,
            Instructions = new List<ClamBcInstruction>(insts),
            BasicBlockCount = blocks,
            BlockStarts = new List<int>(blocks)
        };
    }

    private static void ParseBasicBlock(string line, ClamBcFunction function)
    {
        if (!line.StartsWith('B')) throw new FormatException("Invalid basic block");
        var offset = 1;
        function.BlockStarts.Add(function.Instructions.Count);
        while (offset < line.Length)
        {
            if (line[offset] == 'T') { offset++; break; }
            var type = checked((int)ReadNumber(line, ref offset));
            var destination = checked((int)ReadNumber(line, ref offset));
            var opcode = ReadFixedNumber(line, ref offset, 2);
            function.Instructions.Add(ParseInstruction(line, ref offset, opcode, type, destination, function));
        }
        if (offset != line.Length) throw new FormatException("Trailing bytes in basic block");
    }

    private static ClamBcInstruction ParseInstruction(string line, ref int offset, int opcode, int type, int destination, ClamBcFunction function)
    {
        if (opcode == 18) // JMP
            return new ClamBcInstruction(opcode, 0, 0, [], TargetBlock: checked((int)ReadNumber(line, ref offset)));
        if (opcode == 17) // BRANCH
        {
            var condition = ReadOperand(line, ref offset, function);
            return new ClamBcInstruction(opcode, 0, 0, [condition], TargetTrue: checked((int)ReadNumber(line, ref offset)), TargetFalse: checked((int)ReadNumber(line, ref offset)));
        }
        if (opcode == 19) // RET
            return new ClamBcInstruction(opcode, checked((int)ReadNumber(line, ref offset)), 0, [ReadOperand(line, ref offset, function)]);
        if (opcode == 20) return new ClamBcInstruction(opcode, 0, 0, []);
        if (opcode == 32 || opcode == 33) // CALL_DIRECT / CALL_API
        {
            var count = ReadFixedNumber(line, ref offset, 1);
            if (count > 128) throw new FormatException("Too many bytecode call operands");
            var id = checked((int)ReadNumber(line, ref offset)) - 1;
            var operands = new ClamBcOperand[count];
            for (var i = 0; i < count; i++) operands[i] = ReadOperand(line, ref offset, function);
            return new ClamBcInstruction(opcode, type, destination, operands, ApiOrFunctionId: id);
        }
        if (opcode is 14 or 15 or 16) // trunc/sext/zext
        {
            var source = ReadOperand(line, ref offset, function);
            var sourceWidth = source.IsConstant ? Math.Clamp(type, 1, 64) : TypeWidth(function.LocalTypes.ElementAtOrDefault(source.Index));
            return new ClamBcInstruction(opcode, type, destination, [source], CastSourceWidth: sourceWidth);
        }
        if (opcode is 21 or 22 or 23 or 24 or 25 or 26 or 27 or 28 or 29 or 30)
        {
            var compareType = checked((int)ReadNumber(line, ref offset));
            return new ClamBcInstruction(opcode, compareType, destination, [ReadOperand(line, ref offset, function), ReadOperand(line, ref offset, function)]);
        }
        if (opcode == 31) return new ClamBcInstruction(opcode, type, destination, [ReadOperand(line, ref offset, function), ReadOperand(line, ref offset, function), ReadOperand(line, ref offset, function)]); // select
        if (opcode is 34) return new ClamBcInstruction(opcode, type, destination, [ReadOperand(line, ref offset, function), ReadOperand(line, ref offset, function)]); // copy
        if (opcode is 35 or 36)
        {
            var scale = checked((int)ReadNumber(line, ref offset));
            if (scale <= 0 || scale > 16 * 1024 * 1024) throw new FormatException("Unsafe GEP scale");
            var pointer = ReadOperand(line, ref offset, function);
            var index = ReadOperand(line, ref offset, function);
            return new ClamBcInstruction(opcode, type, destination, [pointer, index], GepScale: scale);
        }
        if (opcode == 37)
        {
            var count = ReadFixedNumber(line, ref offset, 1);
            if (count > 64) throw new FormatException("Unsafe GEPN operand count");
            var scale = checked((int)ReadNumber(line, ref offset));
            if (scale <= 0 || scale > 16 * 1024 * 1024) throw new FormatException("Unsafe GEPN scale");
            var operands = new ClamBcOperand[count + 1];
            for (var i = 0; i < operands.Length; i++) operands[i] = ReadOperand(line, ref offset, function);
            return new ClamBcInstruction(opcode, type, destination, operands, GepScale: scale);
        }
        var countDefault = opcode switch
        {
            >= 1 and <= 13 => 2,
            38 => 2,
            39 => 1,
            40 or 41 or 42 or 43 => 3,
            44 or 45 => 0,
            46 or 47 or 48 => 1,
            49 => 2,
            50 => 1,
            _ => 0
        };
        var defaults = new ClamBcOperand[countDefault];
        for (var i = 0; i < defaults.Length; i++) defaults[i] = ReadOperand(line, ref offset, function);
        return new ClamBcInstruction(opcode, type, destination, defaults);
    }

    private static ClamBcOperand ReadOperand(string text, ref int offset, ClamBcFunction function)
    {
        if (offset >= text.Length) throw new FormatException("Missing operand");
        var raw = text[offset];
        if ((raw >= '@' && raw <= 'O') || raw == 'P')
        {
            var value = ReadNumber(text, ref offset, normalizeFirst: true);
            var typeWidth = ReadFixedNumber(text, ref offset, 1);
            if (typeWidth == 0)
                return new ClamBcOperand(0, false, 0, true, checked((int)value));
            var bits = Math.Clamp(typeWidth * 8, 1, 64);
            if (bits < 64) value &= (1UL << bits) - 1;
            return new ClamBcOperand(function.LocalTypes.Length + 1, true, value);
        }
        var index = checked((int)ReadNumber(text, ref offset));
        if (index >= function.LocalTypes.Length + 10_000_000) throw new FormatException("Operand index overflow");
        return new ClamBcOperand(index);
    }

    private string NextNonEmpty()
    {
        while (_line < _lines.Length)
        {
            var line = _lines[_line++].TrimEnd();
            if (!string.IsNullOrWhiteSpace(line)) return line;
        }
        return string.Empty;
    }

    private static string ExtractName(string logic, string fallback)
    {
        var match = Regex.Match(logic, @"\{(?<name>[^}]+)\}");
        if (match.Success) return match.Groups["name"].Value;
        var semicolon = logic.IndexOf(';');
        return semicolon > 0 ? logic[..semicolon].Trim() : fallback;
    }

    internal static ulong ReadNumber(string text, ref int offset, bool normalizeFirst = false)
    {
        if (offset >= text.Length) throw new FormatException("Unexpected end of ClamBC number");
        var raw = text[offset];
        var first = normalizeFirst ? (char)(raw | (char)0x20) : raw;
        var lim = first - (char)0x60;
        if (lim < 0 || lim > 0x10) throw new FormatException("Invalid ClamBC number length");
        var end = offset + lim + 1;
        if (end > text.Length) throw new FormatException("ClamBC number overflow");
        ulong value = 0;
        var shift = 0;
        for (var i = offset + 1; i < end; i++, shift += 4)
        {
            var c = text[i];
            if ((c & 0xF0) != 0x60) throw new FormatException("Invalid ClamBC digit");
            value |= (ulong)(c & 0x0F) << shift;
        }
        offset = end;
        return value;
    }

    private static int ReadFixedNumber(string text, ref int offset, int width)
    {
        if (offset + width > text.Length) throw new FormatException("ClamBC fixed number overflow");
        var value = 0;
        var shift = 0;
        for (var i = 0; i < width; i++, shift += 4)
        {
            var c = text[offset++];
            if ((c & 0xF0) != 0x60) throw new FormatException("Invalid ClamBC fixed digit");
            value |= (c & 0x0F) << shift;
        }
        return value;
    }

    private static string ReadString(string text, ref int offset)
    {
        if (offset >= text.Length || text[offset++] != '|') throw new FormatException("Missing ClamBC string");
        var len = checked((int)ReadNumber(text, ref offset));
        if (len < 0 || offset + (len * 2L) > text.Length) throw new FormatException("ClamBC string overflow");
        var buffer = new byte[len];
        for (var i = 0; i < len; i++)
        {
            var a = text[offset++];
            var b = text[offset++];
            if ((a & 0xF0) != 0x60 || (b & 0xF0) != 0x60) throw new FormatException("Invalid ClamBC string digit");
            buffer[i] = (byte)((a & 0x0F) | ((b & 0x0F) << 4));
        }
        if (buffer.Length > 0 && buffer[^1] == 0) buffer = buffer[..^1];
        return Encoding.UTF8.GetString(buffer);
    }
}

internal sealed class ClamBcVirtualMachine
{
    private readonly ClamBcProgram _program;
    private readonly ReadOnlyMemory<byte> _originalFile;
    private ReadOnlyMemory<byte> _file;
    private readonly BytecodeScanOptions _options;
    private readonly CancellationToken _token;
    private readonly Dictionary<ulong, ClamBcPointer> _pointers = new();
    private readonly Dictionary<int, HashSet<uint>> _hashSets = new();
    private readonly Dictionary<int, ClamBcMapState> _maps = new();
    private readonly Dictionary<int, ClamBcBufferState> _buffers = new();
    private readonly Dictionary<int, ClamBcInflateState> _inflates = new();
    private readonly Dictionary<int, JsonElement> _jsonObjects = new();
    private JsonDocument? _jsonDocument;
    private ulong _nextPointer = 1;
    private int _nextHashSet;
    private int _nextMap;
    private int _nextBuffer;
    private int _nextInflate;
    private int _nextJsonObject;
    private long _fileOffset;
    private readonly MemoryStream _extractBuffer = new();
    private uint _containerType;
    private bool _extractedReady;
    private bool _bytecodeDisabled;
    private bool _jitDisabled;
    private long _executed;
    private string? _virusName;
    private long? _matchOffset;
    private long _returnValue;
    private int _allocated;
    private readonly Stopwatch _runtime = Stopwatch.StartNew();
    private readonly List<ClamBcPdfObject> _pdfObjects = new();
    private int _pdfPhase;
    private int _pdfFlags;
    private int _pdfDumpedObjectId = -1;

    public ClamBcVirtualMachine(ClamBcProgram program, ReadOnlySpan<byte> file, BytecodeScanOptions options, CancellationToken token)
    {
        _program = program;
        _file = file.ToArray();
        _originalFile = _file;
        _options = options;
        _token = token;
        InitializePdfContext();
    }

    public (bool Matched, string? VirusName, long? Offset, long ReturnValue, string? Detail) Run()
    {
        try
        {
            ExecuteFunction(0, Array.Empty<ulong>(), 0);
            return (_virusName is not null || _returnValue != 0, _virusName, _matchOffset, _returnValue, null);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or OverflowException or IndexOutOfRangeException or ArgumentException)
        {
            return (false, null, null, 0, $"bytecode skipped: {ex.Message}");
        }
    }

    private ulong ExecuteFunction(int functionId, ulong[] args, int depth)
    {
        if ((uint)functionId >= (uint)_program.Functions.Count) throw new InvalidOperationException("function id out of range");
        if (depth > _options.MaxCallDepth) throw new InvalidOperationException("call depth exceeded");
        var function = _program.Functions[functionId];
        var locals = new Dictionary<int, ulong>();
        for (var i = 0; i < args.Length; i++) locals[i] = args[i];

        var block = 0;
        while (block >= 0 && block < function.BasicBlockCount)
        {
            var start = function.BlockStarts[block];
            var end = block + 1 < function.BasicBlockCount ? function.BlockStarts[block + 1] : function.Instructions.Count;
            for (var pc = start; pc < end; pc++)
            {
                _token.ThrowIfCancellationRequested();
                if (++_executed > _options.MaxInstructions) throw new InvalidOperationException("instruction budget exceeded");
                if ((_executed & 1023) == 0 && _runtime.Elapsed > _options.MaxRuntime) throw new OperationCanceledException("bytecode runtime budget exceeded", _token);
                var inst = function.Instructions[pc];
                switch (inst.Opcode)
                {
                    case 1: locals[inst.Destination] = Bin(inst, locals, static (a, b) => a + b); break;
                    case 2: locals[inst.Destination] = Bin(inst, locals, static (a, b) => a - b); break;
                    case 3: locals[inst.Destination] = Bin(inst, locals, static (a, b) => a * b); break;
                    case 4: locals[inst.Destination] = UDiv(inst, locals); break;
                    case 5: locals[inst.Destination] = SDiv(inst, locals); break;
                    case 6: locals[inst.Destination] = URem(inst, locals); break;
                    case 7: locals[inst.Destination] = SRem(inst, locals); break;
                    case 8: locals[inst.Destination] = ShiftLeft(inst, locals); break;
                    case 9: locals[inst.Destination] = ShiftRightLogical(inst, locals); break;
                    case 10: locals[inst.Destination] = ShiftRightArithmetic(inst, locals); break;
                    case 11: locals[inst.Destination] = Bin(inst, locals, static (a, b) => a & b); break;
                    case 12: locals[inst.Destination] = Bin(inst, locals, static (a, b) => a | b); break;
                    case 13: locals[inst.Destination] = Bin(inst, locals, static (a, b) => a ^ b); break;
                    case 14: locals[inst.Destination] = Truncate(Get(inst.Operands[0], locals), inst.Type); break;
                    case 15: locals[inst.Destination] = SignExtend(Get(inst.Operands[0], locals), inst.CastSourceWidth); break;
                    case 16: locals[inst.Destination] = Truncate(Get(inst.Operands[0], locals), inst.CastSourceWidth); break;
                    case 17:
                        block = (Get(inst.Operands[0], locals) & 1UL) != 0 ? inst.TargetTrue : inst.TargetFalse;
                        goto NextBlock;
                    case 18:
                        block = inst.TargetBlock;
                        goto NextBlock;
                    case 19:
                        _returnValue = unchecked((long)Get(inst.Operands[0], locals));
                        return Get(inst.Operands[0], locals);
                    case 20: return 0;
                    case 21: locals[inst.Destination] = Compare(inst, locals, static (a, b) => a == b); break;
                    case 22: locals[inst.Destination] = Compare(inst, locals, static (a, b) => a != b); break;
                    case 23: locals[inst.Destination] = Compare(inst, locals, static (a, b) => a > b); break;
                    case 24: locals[inst.Destination] = Compare(inst, locals, static (a, b) => a >= b); break;
                    case 25: locals[inst.Destination] = Compare(inst, locals, static (a, b) => a < b); break;
                    case 26: locals[inst.Destination] = Compare(inst, locals, static (a, b) => a <= b); break;
                    case 27: locals[inst.Destination] = Compare(inst, locals, static (a, b) => (long)a > (long)b); break;
                    case 28: locals[inst.Destination] = Compare(inst, locals, static (a, b) => (long)a >= (long)b); break;
                    case 29: locals[inst.Destination] = Compare(inst, locals, static (a, b) => (long)a <= (long)b); break;
                    case 30: locals[inst.Destination] = Compare(inst, locals, static (a, b) => (long)a < (long)b); break;
                    case 31: locals[inst.Destination] = Get(inst.Operands[0], locals) != 0 ? Get(inst.Operands[1], locals) : Get(inst.Operands[2], locals); break;
                    case 32: locals[inst.Destination] = ExecuteFunction(inst.ApiOrFunctionId, inst.Operands.Select(x => Get(x, locals)).ToArray(), depth + 1); break;
                    case 33: locals[inst.Destination] = ExecuteApi(inst.ApiOrFunctionId, inst.Operands.Select(x => Get(x, locals)).ToArray()); break;
                    case 34: locals[inst.Destination] = Get(inst.Operands[0], locals); break;
                    case 35:
                    case 36:
                    case 37: locals[inst.Destination] = GEP(inst, locals); break;
                    case 38: Store(inst, locals); break;
                    case 39: locals[inst.Destination] = Load(inst, locals); break;
                    case 40: Memset(inst, locals); break;
                    case 41:
                    case 42: Memcpy(inst, locals); break;
                    case 43: locals[inst.Destination] = Memcmp(inst, locals); break;
                    case 44: locals[inst.Destination] = BitConverter.IsLittleEndian ? 0UL : 1UL; break;
                    case 45: throw new InvalidOperationException("bytecode abort");
                    case 46: locals[inst.Destination] = BinaryPrimitives.ReverseEndianness((ushort)Get(inst.Operands[0], locals)); break;
                    case 47: locals[inst.Destination] = BinaryPrimitives.ReverseEndianness((uint)Get(inst.Operands[0], locals)); break;
                    case 48: locals[inst.Destination] = BinaryPrimitives.ReverseEndianness(Get(inst.Operands[0], locals)); break;
                    case 49: locals[inst.Destination] = PtrDiff32(Get(inst.Operands[0], locals), Get(inst.Operands[1], locals)); break;
                    case 50: locals[inst.Destination] = PtrToInt64(Get(inst.Operands[0], locals)); break;
                    default: throw new InvalidOperationException($"unsupported opcode {inst.Opcode}");
                }
            }
        NextBlock:;
        }
        return 0;
    }

    private ulong ExecuteApi(int id, ulong[] args)
    {
        if (!_program.ApiNames.TryGetValue(id, out var name))
            throw new InvalidOperationException($"undeclared bytecode API id {id}");
        return name switch
        {
            "test1" => args.Length >= 2 && (uint)args[0] == 0xf00dbeef && (uint)args[1] == 0xbeeff00d ? 0x12345678UL : 0x55UL,
            "test2" => args.Length >= 1 && (uint)args[0] == 0xf00d ? 0xd00fUL : 0x5555UL,
            "read" => ApiRead(args),
            "write" => ApiWrite(args),
            "seek" => ApiSeek(args),
            "setvirusname" => ApiSetVirusName(args),
            "debug_print_str" or "debug_print_str_start" or "debug_print_str_nonl" => 0,
            "debug_print_uint" => 0,
            "disasm_x86" => 0,
            "trace_directory" or "trace_scope" or "trace_source" or "trace_op" or "trace_value" or "trace_ptr" => 0,
            "pe_rawaddr" => ApiPeRawAddr(args),
            "file_find" => ApiFileFind(args),
            "file_find_limit" => ApiFileFindLimit(args),
            "file_byteat" => ApiByteAt(args),
            "malloc" => ApiMalloc(args),
            "get_pe_section" => ApiGetPeSection(args),
            "fill_buffer" => ApiFillBuffer(args),
            "extract_new" => ApiExtractNew(args),
            "read_number" => ApiReadNumber(args),
            "hashset_new" => ApiHashSetNew(),
            "hashset_add" => ApiHashSetAdd(args),
            "hashset_remove" => ApiHashSetRemove(args),
            "hashset_contains" => ApiHashSetContains(args),
            "hashset_empty" => ApiHashSetEmpty(args),
            "hashset_done" => ApiHashSetDone(args),
            "buffer_pipe_new" => ApiBufferNew(args),
            "buffer_pipe_new_fromfile" => ApiBufferNewFromFile(args),
            "buffer_pipe_read_avail" => ApiBufferReadAvail(args),
            "buffer_pipe_read_get" => ApiBufferReadGet(args),
            "buffer_pipe_read_stopped" => ApiBufferReadStopped(args),
            "buffer_pipe_write_avail" => ApiBufferWriteAvail(args),
            "buffer_pipe_write_get" => ApiBufferWriteGet(args),
            "buffer_pipe_write_stopped" => ApiBufferWriteStopped(args),
            "buffer_pipe_done" => ApiBufferDone(args),
            "inflate_init" => ApiInflateInit(args),
            "inflate_process" => ApiInflateProcess(args),
            "inflate_done" => ApiInflateDone(args),
            "bytecode_rt_error" => 0,
            "jsnorm_init" or "jsnorm_process" or "jsnorm_done" => 0,
            "lzma_init" or "lzma_process" or "lzma_done" or "bzip2_init" or "bzip2_process" or "bzip2_done" => unchecked((ulong)-1),
            "ilog2" => ApiILog2(args),
            "ipow" => ApiIPow(args),
            "iexp" => ApiIExp(args),
            "isin" => ApiISin(args),
            "icos" => ApiICos(args),
            "memstr" => ApiMemstr(args),
            "hex2ui" => ApiHex2Ui(args),
            "atoi" => ApiAtoi(args),
            "entropy_buffer" => ApiEntropy(args),
            "map_new" => ApiMapNew(args),
            "map_addkey" => ApiMapAddKey(args),
            "map_setvalue" => ApiMapSetValue(args),
            "map_remove" => ApiMapRemove(args),
            "map_find" => ApiMapFind(args),
            "map_getvaluesize" => ApiMapGetValueSize(args),
            "map_getvalue" => ApiMapGetValue(args),
            "map_done" => ApiMapDone(args),
            "engine_functionality_level" => (ulong)_options.EngineFunctionalityLevel,
            "engine_dconf_level" => (ulong)_options.EngineFunctionalityLevel,
            "engine_scan_options" => _options.EngineScanOptions,
            "engine_db_options" => _options.EngineDatabaseOptions,
            "engine_scan_options_ex" => _options.EngineScanOptionsEx,
            "extract_set_container" => args.Length > 0 ? (_containerType = (uint)Math.Min(args[0], uint.MaxValue), 0UL).Item2 : unchecked((ulong)-1),
            "input_switch" => ApiInputSwitch(args),
            "get_environment" => ApiGetEnvironment(args),
            "disable_bytecode_if" => ApiDisableBytecode(args),
            "disable_jit_if" => ApiDisableJit(args),
            "version_compare" => unchecked((ulong)(long)ApiVersionCompare(args)),
            "check_platform" => ApiCheckPlatform(args),
            "pdf_get_obj_num" => ApiPdfGetObjNum(), "pdf_get_flags" => ApiPdfGetFlags(), "pdf_set_flags" => ApiPdfSetFlags(args), "pdf_lookupobj" => ApiPdfLookup(args),
            "pdf_getobjsize" => ApiPdfGetObjSize(args), "pdf_getobj" => ApiPdfGetObj(args), "pdf_getobjid" => ApiPdfGetObjId(args), "pdf_getobjflags" => ApiPdfGetObjFlags(args),
            "pdf_setobjflags" => ApiPdfSetObjFlags(args), "pdf_get_offset" => ApiPdfGetOffset(args), "pdf_get_phase" => (ulong)_pdfPhase,
            "pdf_get_dumpedobjid" => unchecked((ulong)(long)_pdfDumpedObjectId), "matchicon" => ApiMatchIcon(args), "running_on_jit" => 0UL,
            "get_file_reliability" => 3,
            "json_is_active" => ApiJsonEnsure() ? 1UL : 0UL,
            "json_get_object" => ApiJsonGetObject(args), "json_get_type" => ApiJsonGetType(args),
            "json_get_array_length" => ApiJsonArrayLength(args), "json_get_array_idx" => ApiJsonArrayIndex(args),
            "json_get_string_length" => ApiJsonStringLength(args), "json_get_string" => ApiJsonGetString(args),
            "json_get_boolean" => ApiJsonBoolean(args), "json_get_int" => ApiJsonInt(args),
            _ => throw new InvalidOperationException($"unsupported bytecode API '{name}'")
        };
    }

    private ulong ApiRead(ulong[] args)
    {
        if (args.Length < 2 || !TryPointer(args[0], out var ptr)) return ulong.MaxValue;
        var count = (long)Math.Min(args[1], int.MaxValue);
        if (count < 0 || _fileOffset < 0 || _fileOffset > _file.Length) return ulong.MaxValue;
        var available = Math.Min(count, _file.Length - _fileOffset);
        if (available <= 0) return 0;
        if (ptr.Offset < 0 || ptr.Offset + available > ptr.Buffer.Length) return ulong.MaxValue;
        _file.Span.Slice((int)_fileOffset, (int)available).CopyTo(ptr.Buffer.AsSpan(ptr.Offset, (int)available));
        _fileOffset += available;
        return (ulong)available;
    }

    private ulong ApiSeek(ulong[] args)
    {
        if (args.Length < 2) return ulong.MaxValue;
        var pos = unchecked((long)args[0]);
        var whence = args[1];
        long target = whence switch
        {
            0 => pos,
            1 => _fileOffset + pos,
            2 => _file.Length + pos,
            _ => -1
        };
        if (target < 0 || target > _file.Length) return ulong.MaxValue;
        _fileOffset = target;
        return (ulong)target;
    }

    private ulong ApiSetVirusName(ulong[] args)
    {
        if (args.Length > 0 && TryReadString(args[0], out var name) && !string.IsNullOrWhiteSpace(name)) _virusName = name;
        _matchOffset ??= _fileOffset;
        return 0;
    }

    private ulong ApiFileFindLimit(ulong[] args)
    {
        if (args.Length < 3 || !TryPointer(args[0], out var needle)) return unchecked((ulong)-1);
        var len = Math.Min((int)Math.Min(args[1], (ulong)int.MaxValue), needle.Buffer.Length - needle.Offset);
        var limit = Math.Min((long)args[2], _file.Length - _fileOffset);
        if (len <= 0 || limit < len) return unchecked((ulong)-1);
        var start = (int)_fileOffset;
        var span = _file.Span.Slice(start, (int)Math.Min(limit, int.MaxValue));
        var pos = span.IndexOf(needle.Buffer.AsSpan(needle.Offset, len));
        return pos < 0 ? unchecked((ulong)-1) : (ulong)(_fileOffset + pos);
    }
    private ulong ApiByteAt(ulong[] args)
    {
        if (args.Length == 0) return 0;
        var offset = unchecked((long)args[0]);
        return offset >= 0 && offset < _file.Length ? _file.Span[(int)offset] : unchecked((ulong)-1);
    }

    private ulong ApiMalloc(ulong[] args)
    {
        var size = (int)Math.Min(args.Length == 0 ? 0UL : args[0], (ulong)_options.MaxAllocatedBytesPerRule);
        if (size < 0 || _allocated + size > _options.MaxAllocatedBytesPerRule) return 0;
        var id = _nextPointer++;
        _pointers[id] = new ClamBcPointer(new byte[size], 0);
        _allocated += size;
        return id;
    }

    private ulong ApiFileFind(ulong[] args)
    {
        if (args.Length < 2 || !TryPointer(args[0], out var ptr)) return ulong.MaxValue;
        var count = (int)Math.Min(args[1], 1024UL);
        if (count <= 0 || ptr.Offset < 0 || ptr.Offset + count > ptr.Buffer.Length) return ulong.MaxValue;
        var start = (int)Math.Clamp(_fileOffset, 0, _file.Length);
        var idx = _file.Span[start..].IndexOf(ptr.Buffer.AsSpan(ptr.Offset, count));
        if (idx >= 0)
        {
            var absolute = start + idx;
            _matchOffset = absolute;
            return (ulong)absolute;
        }
        return ulong.MaxValue;
    }

    private ulong ApiMemstr(ulong[] args)
    {
        if (args.Length < 4 || !TryPointer(args[0], out var hay) || !TryPointer(args[2], out var needle)) return ulong.MaxValue;
        var hayLen = (int)Math.Min(args[1], (ulong)Math.Max(0, hay.Buffer.Length - hay.Offset));
        var needleLen = (int)Math.Min(args[3], (ulong)Math.Max(0, needle.Buffer.Length - needle.Offset));
        if (hayLen <= 0 || needleLen <= 0 || needleLen > hayLen) return ulong.MaxValue;
        var idx = hay.Buffer.AsSpan(hay.Offset, hayLen).IndexOf(needle.Buffer.AsSpan(needle.Offset, needleLen));
        return idx >= 0 ? (ulong)idx : ulong.MaxValue;
    }

    private ulong ApiReadNumber(ulong[] args)
    {
        var radix = args.Length == 0 ? 0 : args[0];
        if (radix is not 10 and not 16 || _fileOffset < 0 || _fileOffset >= _file.Length) return ulong.MaxValue;
        var i = (int)_fileOffset;
        while (i < _file.Length && (_file.Span[i] == (byte)' ' || _file.Span[i] == (byte)'\t' || _file.Span[i] == (byte)'\r' || _file.Span[i] == (byte)'\n')) i++;
        var start = i;
        while (i < _file.Length)
        {
            var c = _file.Span[i];
            var digit = c is >= (byte)'0' and <= (byte)'9' || radix == 16 && (c is >= (byte)'a' and <= (byte)'f' || c is >= (byte)'A' and <= (byte)'F');
            if (!digit) break;
            i++;
        }
        if (i == start) return ulong.MaxValue;
        var text = Encoding.ASCII.GetString(_file.Span[start..i]);
        if (!long.TryParse(text, radix == 16 ? System.Globalization.NumberStyles.HexNumber : System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var value)) return ulong.MaxValue;
        _fileOffset = i;
        return unchecked((ulong)value);
    }

    private static ulong ParseHexByte(byte value)
        => value switch
        {
            >= (byte)'0' and <= (byte)'9' => (uint)(value - '0'),
            >= (byte)'a' and <= (byte)'f' => (uint)(value - 'a' + 10),
            >= (byte)'A' and <= (byte)'F' => (uint)(value - 'A' + 10),
            _ => 0
        };

    private ulong ApiWrite(ulong[] args)
    {
        if (args.Length < 2 || !TryPointer(args[0], out var ptr)) return unchecked((ulong)-1);
        var len = (int)Math.Min(args[1], (ulong)Math.Max(0, ptr.Buffer.Length - ptr.Offset));
        if (len <= 0) return 0;
        if (_extractBuffer.Length + len > _options.MaxExtractedBytes) return unchecked((ulong)-1);
        _extractBuffer.Write(ptr.Buffer, ptr.Offset, len);
        return (ulong)len;
    }
    private ulong ApiFillBuffer(ulong[] args)
    {
        if (args.Length < 5 || !TryPointer(args[0], out var p)) return unchecked((ulong)-1);
        var buflen = (int)Math.Min(args[1], (ulong)Math.Max(0, p.Buffer.Length - p.Offset));
        var filled = Math.Min((int)Math.Min(args[2], (ulong)buflen), buflen);
        var pos = Math.Min((int)Math.Min(args[3], (ulong)filled), filled);
        var remain = filled - pos;
        if (remain > 0) p.Buffer.AsSpan(p.Offset + pos, remain).CopyTo(p.Buffer.AsSpan(p.Offset, remain));
        var toFill = buflen - remain;
        if (toFill <= 0 || _fileOffset >= _file.Length) return (ulong)remain;
        var take = (int)Math.Min(toFill, _file.Length - _fileOffset);
        _file.Span.Slice((int)_fileOffset, take).CopyTo(p.Buffer.AsSpan(p.Offset + remain, take));
        _fileOffset += take;
        return (ulong)(remain + take);
    }
    private ulong ApiExtractNew(ulong[] args) { if (_extractBuffer.Length == 0) return 0; _extractedReady = true; return 0; }
    private ulong ApiHashSetNew() { var id=_nextHashSet++; if(id>=_options.MaxApiObjects)return unchecked((ulong)-1); _hashSets[id]=new(); return (ulong)id; }
    private ulong HashSetMutation(ulong[] args,bool add){if(args.Length<2||args[0]>int.MaxValue||!_hashSets.TryGetValue((int)args[0],out var s))return unchecked((ulong)-1); return add?(s.Add((uint)args[1])?0UL:0UL):(s.Remove((uint)args[1])?0UL:0UL);}
    private ulong ApiHashSetAdd(ulong[] a)=>HashSetMutation(a,true); private ulong ApiHashSetRemove(ulong[] a)=>HashSetMutation(a,false);
    private ulong ApiHashSetContains(ulong[] a)=>a.Length>=2&&a[0]<=int.MaxValue&&_hashSets.TryGetValue((int)a[0],out var s)&&s.Contains((uint)a[1])?1UL:0UL;
    private ulong ApiHashSetEmpty(ulong[] a)=>a.Length>=1&&a[0]<=int.MaxValue&&_hashSets.TryGetValue((int)a[0],out var s)&&s.Count==0?1UL:0UL;
    private ulong ApiHashSetDone(ulong[] a){if(a.Length==0||a[0]>int.MaxValue||!_hashSets.Remove((int)a[0]))return unchecked((ulong)-1);return 0;}
    private ulong ApiBufferNew(ulong[] a){if(a.Length==0||a[0]==0||a[0]>(ulong)_options.MaxBufferBytes)return unchecked((ulong)-1);var id=_nextBuffer++;if(id>=_options.MaxApiObjects)return unchecked((ulong)-1);_buffers[id]=new ClamBcBufferState(new byte[(int)a[0]],0,0,false);return (ulong)id;}
    private ulong ApiBufferNewFromFile(ulong[] a){if(a.Length==0||a[0]>(ulong)_file.Length)return unchecked((ulong)-1);var id=_nextBuffer++;if(id>=_options.MaxApiObjects)return unchecked((ulong)-1);_buffers[id]=new ClamBcBufferState(null,(long)a[0],0,true);return (ulong)id;}
    private ulong ApiBufferReadAvail(ulong[] a){if(!TryGetBuffer(a,out var b))return 0;return b.FileBacked?(ulong)Math.Min(8192,Math.Max(0,_file.Length-b.ReadCursor)):(ulong)Math.Max(0,b.WriteCursor-b.ReadCursor);}
    private ulong ApiBufferReadGet(ulong[] a){if(!TryGetBuffer(a,out var b)||a.Length<2||a[1]==0)return 0;var avail=ApiBufferReadAvail(a);if(a[1]>avail)return 0;var len=checked((int)a[1]);if(b.FileBacked){var c=new byte[len];_file.Span.Slice((int)b.ReadCursor,len).CopyTo(c);return NewPointerHandle(c);}return NewPointerHandle(b.Data!,checked((int)b.ReadCursor));}
    private ulong ApiBufferReadStopped(ulong[] a){if(!TryGetBuffer(a,out var b)||a.Length<2)return unchecked((ulong)-1);var amount=(long)Math.Min(a[1],(ulong)int.MaxValue);var avail=(long)ApiBufferReadAvail([a[0]]);if(amount>avail)amount=avail;if(amount<0)return unchecked((ulong)-1);b.ReadCursor+=amount;if(!b.FileBacked&&b.Data is not null&&b.ReadCursor>=b.Data.Length&&b.WriteCursor>=b.Data.Length)b.ReadCursor=b.WriteCursor=0;return 0;}
    private ulong ApiBufferWriteAvail(ulong[] a){if(!TryGetBuffer(a,out var b)||b.FileBacked||b.Data is null)return 0;return (ulong)Math.Max(0,b.Data.Length-b.WriteCursor);}
    private ulong ApiBufferWriteGet(ulong[] a){if(!TryGetBuffer(a,out var b)||b.FileBacked||b.Data is null||a.Length<2)return 0;var len=Math.Min((int)Math.Min(a[1],(ulong)int.MaxValue),b.Data.Length-b.WriteCursor);return len<=0?0:NewPointerHandle(b.Data,b.WriteCursor);}
    private ulong ApiBufferWriteStopped(ulong[] a){if(!TryGetBuffer(a,out var b)||b.FileBacked||b.Data is null||a.Length<2)return unchecked((ulong)-1);b.WriteCursor+=Math.Min((int)Math.Min(a[1],(ulong)int.MaxValue),b.Data.Length-b.WriteCursor);return 0;}
    private ulong ApiBufferDone(ulong[] a){if(a.Length==0||a[0]>int.MaxValue||!_buffers.Remove((int)a[0]))return unchecked((ulong)-1);return 0;}
    private bool TryGetBuffer(ulong[] a,out ClamBcBufferState b){b=null!;return a.Length>0&&a[0]<=int.MaxValue&&_buffers.TryGetValue((int)a[0],out b!);}
    private int NewPointer(byte[] d,int o=0){var h=_nextPointer++;_pointers[h]=new ClamBcPointer(d,Math.Clamp(o,0,d.Length));return unchecked((int)h);}
    private ulong NewPointerHandle(byte[] d,int o=0)=>unchecked((ulong)NewPointer(d,o));
    private ulong ApiInflateInit(ulong[] a){if(a.Length<3||a[0]>int.MaxValue||a[1]>int.MaxValue||!_buffers.ContainsKey((int)a[0])||!_buffers.ContainsKey((int)a[1]))return unchecked((ulong)-1);var id=_nextInflate++;if(id>=_options.MaxApiObjects)return unchecked((ulong)-1);_inflates[id]=new ClamBcInflateState((int)a[0],(int)a[1],unchecked((int)a[2]),false);return (ulong)id;}
    private ulong ApiInflateProcess(ulong[] a){if(a.Length==0||a[0]>int.MaxValue||!_inflates.TryGetValue((int)a[0],out var st)||st.Done)return unchecked((ulong)-1);if(!_buffers.TryGetValue(st.From,out var from)||!_buffers.TryGetValue(st.To,out var to)||from.Data is null||to.Data is null)return unchecked((ulong)-1);var ia=(int)ApiBufferReadAvail([(ulong)st.From]);var oa=(int)ApiBufferWriteAvail([(ulong)st.To]);if(ia<=0||oa<=0)return unchecked((ulong)-1);try{using var src=new MemoryStream(from.Data, checked((int)from.ReadCursor), ia, false);using var dst=new MemoryStream(to.Data, to.WriteCursor, oa, true);var before=dst.Position;using Stream ds=st.WindowBits>=24?new GZipStream(src,CompressionMode.Decompress,true):st.WindowBits<0?new DeflateStream(src,CompressionMode.Decompress,true):new ZLibStream(src,CompressionMode.Decompress,true);ds.CopyTo(dst);var written=checked((int)(dst.Position-before));from.ReadCursor+=ia;to.WriteCursor+=written;st.Done=true;return 1;}catch(InvalidDataException){return unchecked((ulong)-1);}}
    private ulong ApiInflateDone(ulong[] a){if(a.Length==0||a[0]>int.MaxValue||!_inflates.Remove((int)a[0]))return unchecked((ulong)-1);return 0;}
    private ulong ApiILog2(ulong[] a){if(a.Length<2||a[1]==0)return 0x7fff_ffffUL;return unchecked((ulong)(long)Math.Round((1<<26)*Math.Log((double)a[0]/a[1],2),MidpointRounding.AwayFromZero));}
    private ulong ApiIPow(ulong[] a){if(a.Length<3)return unchecked((ulong)-1);var x=unchecked((int)a[0]);var y=unchecked((int)a[1]);var c=unchecked((int)a[2]);return unchecked((ulong)(long)Math.Round(c*Math.Pow(x,y),MidpointRounding.AwayFromZero));}
    private ulong ApiIExp(ulong[] a){if(a.Length<3||a[1]==0)return 0x7fff_ffffUL;var x=unchecked((int)a[0]);var y=unchecked((int)a[1]);var c=unchecked((int)a[2]);return unchecked((ulong)(uint)Math.Round(c*Math.Exp((double)x/y),MidpointRounding.AwayFromZero));}
    private ulong ApiISin(ulong[] a){if(a.Length<3||a[1]==0)return 0x7fff_ffffUL;var x=unchecked((int)a[0]);var y=unchecked((int)a[1]);var c=unchecked((int)a[2]);return unchecked((ulong)(long)Math.Round(c*Math.Sin((double)x/y),MidpointRounding.AwayFromZero));}
    private ulong ApiICos(ulong[] a){if(a.Length<3||a[1]==0)return 0x7fff_ffffUL;var x=unchecked((int)a[0]);var y=unchecked((int)a[1]);var c=unchecked((int)a[2]);return unchecked((ulong)(long)Math.Round(c*Math.Cos((double)x/y),MidpointRounding.AwayFromZero));}
    private ulong ApiHex2Ui(ulong[] a){if(a.Length<2)return unchecked((ulong)-1);var h=HexNibble((byte)a[0]);var l=HexNibble((byte)a[1]);return h<0||l<0?unchecked((ulong)-1):(ulong)((h<<4)|l);}
    private static int HexNibble(byte b)=>b switch{>= (byte)'0' and <= (byte)'9'=>b-'0',>= (byte)'a' and <= (byte)'f'=>b-'a'+10,>= (byte)'A' and <= (byte)'F'=>b-'A'+10,_=>-1};
    private ulong ApiAtoi(ulong[] a){if(a.Length<2||!TryPointer(a[0],out var p))return unchecked((ulong)-1);var len=(int)Math.Min(a[1],(ulong)Math.Max(0,p.Buffer.Length-p.Offset));var t=Encoding.ASCII.GetString(p.Buffer,p.Offset,len).TrimStart();if(t.StartsWith("-",StringComparison.Ordinal))return unchecked((ulong)-1);if(t.StartsWith('+'))t=t[1..];var d=new string(t.TakeWhile(char.IsDigit).ToArray());return d.Length>0&&int.TryParse(d,NumberStyles.None,CultureInfo.InvariantCulture,out var v)?(ulong)(uint)v:unchecked((ulong)-1);}
    private ulong ApiEntropy(ulong[] a){if(a.Length<2||!TryPointer(a[0],out var p))return unchecked((ulong)-1);var len=(int)Math.Min(a[1],(ulong)Math.Max(0,p.Buffer.Length-p.Offset));if(len<=0)return unchecked((ulong)-1);Span<int> c=stackalloc int[256];for(var i=0;i<len;i++)c[p.Buffer[p.Offset+i]]++;double e=0;for(var i=0;i<256;i++)if(c[i]>0){var q=(double)c[i]/len;e-=q*Math.Log2(q);}return (ulong)Math.Max(0,Math.Min(uint.MaxValue,Math.Truncate(e*(1<<26))));}
    private ClamBcMapState? GetMap(ulong id)=>id<=int.MaxValue&&_maps.TryGetValue((int)id,out var m)?m:null;
    private ulong ApiMapNew(ulong[] a){if(a.Length<2||a[0]==0||a[0]>4096||a[1]>(ulong)_options.MaxMapValueBytes)return unchecked((ulong)-1);var id=_nextMap++;if(id>=_options.MaxApiObjects)return unchecked((ulong)-1);_maps[id]=new ClamBcMapState((int)a[0],(int)a[1]);return (ulong)id;}
    private bool TryMapKey(ulong[] a,ClamBcMapState m,out string key){key=string.Empty;if(a.Length<3||!TryPointer(a[0],out var p))return false;var n=(int)Math.Min(a[1],(ulong)Math.Max(0,p.Buffer.Length-p.Offset));if(n!=m.KeySize)return false;key=Convert.ToHexString(p.Buffer.AsSpan(p.Offset,n));return true;}
    private ulong ApiMapAddKey(ulong[] a){var m=GetMap(a.Length>2?a[2]:ulong.MaxValue);if(m is null||!TryMapKey(a,m,out var k))return unchecked((ulong)-1);var added=m.Values.TryAdd(k,new ClamBcMapValue());m.CurrentKey=k;return added?1UL:0UL;}
    private ulong ApiMapSetValue(ulong[] a){var m=GetMap(a.Length>2?a[2]:ulong.MaxValue);if(m is null||m.CurrentKey is null||a.Length<2||!TryPointer(a[0],out var p))return unchecked((ulong)-1);var n=(int)Math.Min(a[1],(ulong)Math.Max(0,p.Buffer.Length-p.Offset));if(n!=m.ValueSize)return unchecked((ulong)-1);m.Values[m.CurrentKey]=new ClamBcMapValue(p.Buffer.AsSpan(p.Offset,n).ToArray());return 0;}
    private ulong ApiMapRemove(ulong[] a){var m=GetMap(a.Length>2?a[2]:ulong.MaxValue);if(m is null||!TryMapKey(a,m,out var k))return unchecked((ulong)-1);var ok=m.Values.Remove(k);m.CurrentKey=null;return ok?1UL:0UL;}
    private ulong ApiMapFind(ulong[] a){var m=GetMap(a.Length>2?a[2]:ulong.MaxValue);if(m is null||!TryMapKey(a,m,out var k))return unchecked((ulong)-1);m.CurrentKey=m.Values.ContainsKey(k)?k:null;return m.CurrentKey is null?0UL:1UL;}
    private ulong ApiMapGetValueSize(ulong[] a)=>GetMap(a.Length>0?a[0]:ulong.MaxValue)?.ValueSize is int n?(ulong)n:unchecked((ulong)-1);
    private ulong ApiMapGetValue(ulong[] a){var m=GetMap(a.Length>0?a[0]:ulong.MaxValue);if(m is null||m.CurrentKey is null||a.Length<2||a[1]!=(ulong)m.ValueSize)return 0;if(!m.Values.TryGetValue(m.CurrentKey,out var v)||v.Data is null)return 0;return NewPointerHandle(v.Data);}
    private ulong ApiMapDone(ulong[] a){if(a.Length==0||a[0]>int.MaxValue||!_maps.Remove((int)a[0]))return unchecked((ulong)-1);return 0;}
    private ulong ApiDisableBytecode(ulong[] a){if(_program.Metadata.Kind!=ClamBcKind.Startup)return unchecked((ulong)-1);if(a.Length>=3&&a[2]!=0)_bytecodeDisabled=true;return _bytecodeDisabled?2UL:0UL;}
    private ulong ApiDisableJit(ulong[] a){if(_program.Metadata.Kind!=ClamBcKind.Startup)return unchecked((ulong)-1);if(a.Length>=3&&a[2]!=0)_jitDisabled=true;return _jitDisabled?1UL:0UL;}
    private int ApiVersionCompare(ulong[] a){if(a.Length<4||!TryPointer(a[0],out var l)||!TryPointer(a[2],out var r))return -1;var ln=(int)Math.Min(a[1],(ulong)Math.Max(0,l.Buffer.Length-l.Offset));var rn=(int)Math.Min(a[3],(ulong)Math.Max(0,r.Buffer.Length-r.Offset));return CompareVersionStrings(Encoding.ASCII.GetString(l.Buffer,l.Offset,ln),Encoding.ASCII.GetString(r.Buffer,r.Offset,rn));}
    private static int CompareVersionStrings(string a,string b){var i=0;var j=0;while(i<a.Length&&j<b.Length){if(char.IsDigit(a[i])&&char.IsDigit(b[j])){var ai=i;var bj=j;while(i<a.Length&&char.IsDigit(a[i]))i++;while(j<b.Length&&char.IsDigit(b[j]))j++;if(decimal.TryParse(a[ai..i],out var av)&&decimal.TryParse(b[bj..j],out var bv)&&av!=bv)return av<bv?-1:1;continue;}if(a[i]!=b[j])return a[i]<b[j]?-1:1;i++;j++;}return a.Length-i==b.Length-j?0:a.Length-i<b.Length-j?-1:1;}
    private ulong ApiCheckPlatform(ulong[] a){if(a.Length<3)return 0;var pa=PlatformA();var pb=(uint)(BitConverter.IsLittleEndian?0:1)<<28 | (uint)(IntPtr.Size<<24);var pc=0U;return CheckPlatformWord(a[0],pa,new[]{24,20,16,8,0},new[]{8,4,4,8,8})&&CheckPlatformWord(a[1],pb,new[]{28,24,16,8,0},new[]{4,4,8,8,8})&&CheckPlatformWord(a[2],pc,new[]{24,16,8,0},new[]{8,8,8,8})?1UL:0UL;}
    private static bool CheckPlatformWord(ulong q,uint v,int[] shifts,int[] widths){for(var i=0;i<shifts.Length;i++){var mask=(1u<<widths[i])-1;var qv=(uint)((q>>shifts[i])&mask);var vv=(v>>shifts[i])&mask;if(qv!=vv&&qv!=mask)return false;}return true;}
    private bool ApiJsonEnsure(){if(_jsonDocument is not null)return true;try{var text=Encoding.UTF8.GetString(_file.Span).TrimStart('\uFEFF',' ', '\t','\r','\n','\0');if(text.Length==0||(text[0]!='{'&&text[0]!='['))return false;_jsonDocument=JsonDocument.Parse(text,new JsonDocumentOptions{MaxDepth=64,AllowTrailingCommas=true});_jsonObjects[0]=_jsonDocument.RootElement;_nextJsonObject=1;return true;}catch(JsonException){return false;}}
    private bool TryJson(ulong id,out JsonElement e){e=default;return id<=int.MaxValue&&_jsonObjects.TryGetValue((int)id,out e);}
    private int NewJson(JsonElement e){var id=_nextJsonObject++;if(id>=_options.MaxApiObjects)return -1;_jsonObjects[id]=e;return id;}
    private ulong ApiJsonGetObject(ulong[] a){if(a.Length<3||!ApiJsonEnsure()||!TryPointer(a[0],out var p)||!TryJson(a[2],out var obj)||obj.ValueKind!=JsonValueKind.Object)return unchecked((ulong)-1);var n=(int)Math.Min(a[1],(ulong)Math.Max(0,p.Buffer.Length-p.Offset));var name=Encoding.UTF8.GetString(p.Buffer,p.Offset,n);return obj.TryGetProperty(name,out var child)?unchecked((ulong)(long)NewJson(child)):0UL;}
    private ulong ApiJsonGetType(ulong[] a){if(a.Length==0||!ApiJsonEnsure()||!TryJson(a[0],out var o))return unchecked((ulong)-1);return o.ValueKind switch{JsonValueKind.Null=>0UL,JsonValueKind.True or JsonValueKind.False=>1UL,JsonValueKind.Number=>o.TryGetInt64(out _)?3UL:2UL,JsonValueKind.Object=>4UL,JsonValueKind.Array=>5UL,JsonValueKind.String=>6UL,_=>unchecked((ulong)-1)};}
    private ulong ApiJsonArrayLength(ulong[] a){if(a.Length==0||!ApiJsonEnsure()||!TryJson(a[0],out var o))return unchecked((ulong)-1);return o.ValueKind==JsonValueKind.Array?(ulong)o.GetArrayLength():unchecked((ulong)(long)-2);}
    private ulong ApiJsonArrayIndex(ulong[] a){if(a.Length<2||!ApiJsonEnsure()||!TryJson(a[1],out var o)||o.ValueKind!=JsonValueKind.Array)return unchecked((ulong)(long)-2);var i=unchecked((int)a[0]);if(i<0||i>=o.GetArrayLength())return 0;return unchecked((ulong)(long)NewJson(o[i]));}
    private ulong ApiJsonStringLength(ulong[] a){if(a.Length==0||!ApiJsonEnsure()||!TryJson(a[0],out var o)||o.ValueKind!=JsonValueKind.String)return unchecked((ulong)(long)-2);return (ulong)Encoding.UTF8.GetByteCount(o.GetString()??string.Empty);}
    private ulong ApiJsonGetString(ulong[] a){if(a.Length<3||!ApiJsonEnsure()||!TryJson(a[2],out var o)||o.ValueKind!=JsonValueKind.String||!TryPointer(a[0],out var d))return unchecked((ulong)-1);var b=Encoding.UTF8.GetBytes(o.GetString()??string.Empty);var cap=(int)Math.Min(a[1],(ulong)Math.Max(0,d.Buffer.Length-d.Offset));if(cap<=0)return unchecked((ulong)-1);var n=Math.Min(b.Length,cap-1);b.AsSpan(0,n).CopyTo(d.Buffer.AsSpan(d.Offset,n));d.Buffer[d.Offset+n]=0;return (ulong)(n+1);}
    private ulong ApiJsonBoolean(ulong[] a)=>a.Length>0&&ApiJsonEnsure()&&TryJson(a[0],out var o)&&o.ValueKind is JsonValueKind.True or JsonValueKind.False?(o.GetBoolean()?1UL:0UL):unchecked((ulong)-1);
    private ulong ApiJsonInt(ulong[] a)=>a.Length>0&&ApiJsonEnsure()&&TryJson(a[0],out var o)&&o.TryGetInt32(out var v)?unchecked((ulong)(long)v):unchecked((ulong)-1);
    private void InitializePdfContext()
    {
        if (_file.Length < 5 || !_file.Span[..5].SequenceEqual("%PDF-"u8)) return;
        _pdfPhase = 1;
        var text = Encoding.Latin1.GetString(_file.Span);
        var options = RegexOptions.Multiline | RegexOptions.CultureInvariant;
        var objects = Regex.Matches(text, @"(?m)(?<id>\d+)\s+(?<gen>\d+)\s+obj\b", options);
        foreach (Match m in objects)
        {
            _token.ThrowIfCancellationRequested();
            if (!int.TryParse(m.Groups["id"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var id)) continue;
            var startOffset = m.Index;
            var endStart = text.IndexOf("endobj", m.Index + m.Length, StringComparison.Ordinal);
            if (endStart < 0) endStart = text.Length;
            else endStart = Math.Min(text.Length, endStart + 6);
            var size = Math.Max(0, endStart - startOffset);
            if (startOffset <= int.MaxValue && size <= int.MaxValue) _pdfObjects.Add(new ClamBcPdfObject(id, startOffset, size, 0));
            if (_pdfObjects.Count >= 100_000) break;
        }
    }

    private ulong ApiPdfGetObjNum() => _pdfPhase == 0 ? unchecked((ulong)-1) : (ulong)_pdfObjects.Count;
    private ulong ApiPdfGetFlags() => _pdfPhase == 0 ? unchecked((ulong)-1) : unchecked((ulong)(long)_pdfFlags);
    private ulong ApiPdfSetFlags(ulong[] a){if(_pdfPhase==0||a.Length==0)return unchecked((ulong)-1);_pdfFlags=unchecked((int)a[0]);return 0;}
    private ulong ApiPdfLookup(ulong[] a){if(_pdfPhase==0||a.Length==0)return unchecked((ulong)-1);var id=unchecked((int)a[0]);for(var i=0;i<_pdfObjects.Count;i++)if(_pdfObjects[i].Id==id)return (ulong)i;return unchecked((ulong)-1);}
    private ulong ApiPdfGetObjSize(ulong[] a){if(_pdfPhase==0||a.Length==0)return 0;var i=unchecked((int)a[0]);return (uint)i<_pdfObjects.Count?(ulong)_pdfObjects[i].Size:0UL;}
    private ulong ApiPdfGetObj(ulong[] a){if(_pdfPhase==0||a.Length<2)return 0;var i=unchecked((int)a[0]);var amount=checked((int)Math.Min(a[1],(ulong)int.MaxValue));if((uint)i>=_pdfObjects.Count||amount<0||amount>(int)_pdfObjects[i].Size)return 0;var o=_pdfObjects[i];if(o.Offset<0||o.Offset+amount>_file.Length)return 0;var copy=_file.Span.Slice(o.Offset,amount).ToArray();return NewPointerHandle(copy);}
    private ulong ApiPdfGetObjId(ulong[] a)=>_pdfPhase==0||a.Length==0||(uint)unchecked((int)a[0])>=_pdfObjects.Count?unchecked((ulong)-1):(ulong)(uint)_pdfObjects[unchecked((int)a[0])].Id;
    private ulong ApiPdfGetObjFlags(ulong[] a)=>_pdfPhase==0||a.Length==0||(uint)unchecked((int)a[0])>=_pdfObjects.Count?unchecked((ulong)-1):unchecked((ulong)(long)_pdfObjects[unchecked((int)a[0])].Flags);
    private ulong ApiPdfSetObjFlags(ulong[] a){if(_pdfPhase==0||a.Length<2||(uint)unchecked((int)a[0])>=_pdfObjects.Count)return unchecked((ulong)-1);_pdfObjects[unchecked((int)a[0])].Flags=unchecked((int)a[1]);return 0;}
    private ulong ApiPdfGetOffset(ulong[] a)=>_pdfPhase==0||a.Length==0||(uint)unchecked((int)a[0])>=_pdfObjects.Count?unchecked((ulong)-1):(ulong)(uint)_pdfObjects[unchecked((int)a[0])].Offset;
    private ulong ApiMatchIcon(ulong[] a)
    {
        if (a.Length < 4 || !TryPointer(a[0], out var needle) || !TryPointer(a[2], out var path)) return unchecked((ulong)-1);
        var n = Math.Min(checked((int)Math.Min(a[1], (ulong)int.MaxValue)), needle.Buffer.Length - needle.Offset);
        var p = Math.Min(checked((int)Math.Min(a[3], (ulong)int.MaxValue)), path.Buffer.Length - path.Offset);
        if (n <= 0 || p <= 0) return 0;
        return needle.Buffer.AsSpan(needle.Offset,n).SequenceEqual(path.Buffer.AsSpan(path.Offset,p)) ? 1UL : 0UL;
    }

    private ulong ApiInputSwitch(ulong[] a)
    {
        if (!_extractedReady || _extractBuffer.Length == 0) { _file = _originalFile; _fileOffset = 0; return unchecked((ulong)-1); }
        if (a.Length == 0 || a[0] == 0) _file = _originalFile;
        else { _file = _extractBuffer.ToArray(); _fileOffset = 0; }
        return 0;
    }

    private ulong ApiGetEnvironment(ulong[] a)
    {
        if (a.Length < 2 || !TryPointer(a[0], out var dst)) return unchecked((ulong)-1);
        var requested = checked((int)Math.Min(a[1], (ulong)dst.Buffer.Length - (ulong)dst.Offset));
        if (requested <= 0) return unchecked((ulong)-1);
        var env = new byte[Math.Min(requested, 492)];
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(0,4), PlatformA());
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(4,4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(8,4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(12,4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(16,4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(20,4), (uint)_options.EngineFunctionalityLevel);
        BinaryPrimitives.WriteUInt32LittleEndian(env.AsSpan(24,4), 0);
        WriteFixedString(env, 28, 65, Environment.Version.ToString());
        WriteFixedString(env, 93, 65, System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier);
        WriteFixedString(env, 158, 65, System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString());
        WriteFixedString(env, 223, 65, Environment.OSVersion.Platform.ToString());
        WriteFixedString(env, 288, 65, Environment.OSVersion.Version.ToString());
        WriteFixedString(env, 353, 65, Environment.OSVersion.VersionString);
        WriteFixedString(env, 418, 65, System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString());
        if (env.Length >= 492)
        {
            env[483] = BitConverter.IsLittleEndian ? (byte)0 : (byte)1;
            env[484] = (byte)IntPtr.Size;
            env[485] = (byte)Math.Min(255, PlatformArchitectureCode());
            env[486] = (byte)Math.Min(255, OperatingSystemCategory());
            env[487] = (byte)Math.Min(255, OperatingSystemCode());
            env[488] = 7; // CLAMBC compiler enum: other/managed
            env[489] = 0; // JIT compiled flag is false for the managed interpreter
            env[490] = 0; // os_features; no native host feature probe is exposed
            env[491] = 0;
        }
        var baseOffset = 0;
        env.AsSpan(baseOffset).CopyTo(dst.Buffer.AsSpan(dst.Offset, env.Length));
        return 0;
    }

    private static void WriteFixedString(byte[] dst,int offset,int width,string value){if(offset>=dst.Length)return;value??=string.Empty;var text=value.Length>width-1?value[..(width-1)]:value;var bytes=Encoding.ASCII.GetBytes(text);var n=Math.Min(bytes.Length,Math.Min(width-1,dst.Length-offset));bytes.AsSpan(0,n).CopyTo(dst.AsSpan(offset,n));if(offset+n<dst.Length)dst[offset+n]=0;}
    private uint PlatformA()
    {
        var os = OperatingSystem.IsWindows() ? (OperatingSystem.IsWindowsVersionAtLeast(10) ? 16U : 15U) : OperatingSystem.IsMacOS() ? 4U : OperatingSystem.IsLinux() ? 10U : 17U;
        var arch = (uint)PlatformArchitectureCode();
        var compiler = 7U;
        var level=(uint)Math.Clamp(_options.EngineFunctionalityLevel,0,255);
        return (os<<24)|(arch<<20)|(compiler<<16)|(level<<8)|level;
    }
    private int PlatformArchitectureCode() => System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture switch { System.Runtime.InteropServices.Architecture.X64=>2, System.Runtime.InteropServices.Architecture.X86=>1, System.Runtime.InteropServices.Architecture.Arm=>5, System.Runtime.InteropServices.Architecture.Arm64=>5, _=>0 };
    private int OperatingSystemCategory() => OperatingSystem.IsWindows() ? 1 : OperatingSystem.IsMacOS() ? 2 : OperatingSystem.IsLinux() ? 3 : 0;
    private int OperatingSystemCode() => OperatingSystem.IsWindows() ? 1 : OperatingSystem.IsMacOS() ? 2 : OperatingSystem.IsLinux() ? 3 : 0;

    private ulong ApiGetPeSection(ulong[] a)
    {
        if (a.Length < 2 || !TryPointer(a[0], out var dst) || a[1] > 65535) return unchecked((ulong)-1);
        if (!TryParsePeSections(_file.Span, out var sections) || a[1] >= (ulong)sections.Count) return unchecked((ulong)-1);
        var s = sections[(int)a[1]];
        if (dst.Buffer.Length - dst.Offset < 36) return unchecked((ulong)-1);
        var span = dst.Buffer.AsSpan(dst.Offset,36);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0..4],s.Rva);
        BinaryPrimitives.WriteUInt32LittleEndian(span[4..8],s.Vsz);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..12],s.Raw);
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..16],s.Rsz);
        BinaryPrimitives.WriteUInt32LittleEndian(span[16..20],s.Chr);
        BinaryPrimitives.WriteUInt32LittleEndian(span[20..24],s.Rva);
        BinaryPrimitives.WriteUInt32LittleEndian(span[24..28],s.Vsz);
        BinaryPrimitives.WriteUInt32LittleEndian(span[28..32],s.Raw);
        BinaryPrimitives.WriteUInt32LittleEndian(span[32..36],s.Rsz);
        return 0;
    }

    private ulong ApiPeRawAddr(ulong[] a)
    {
        if (a.Length == 0) return unchecked((ulong)-1);
        if (!TryParsePeSections(_file.Span, out var sections)) return unchecked((ulong)-1);
        var rva = a[0];
        foreach (var s in sections)
        {
            var span = Math.Max(s.Vsz, s.Rsz);
            if (rva >= s.Rva && rva - s.Rva < span)
            {
                var raw = s.Raw + (rva - s.Rva);
                return raw <= uint.MaxValue && raw < (ulong)_file.Length ? raw : unchecked((ulong)-1);
            }
        }
        return unchecked((ulong)-1);
    }

    private static bool TryParsePeSections(ReadOnlySpan<byte> data,out List<ClamBcPeSection> sections)
    {
        sections=[]; if(data.Length<0x40||data[0]!='M'||data[1]!='Z')return false;var peOff=BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3c,4));if(peOff<0||peOff>data.Length-24||BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(peOff,4))!=0x4550)return false;var num=BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(peOff+6,2));var optSize=BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(peOff+20,2));var table=peOff+24+optSize; if(table<0||table>data.Length||num>96||table+(long)num*40>data.Length)return false; for(var i=0;i<num;i++){var o=table+i*40;sections.Add(new ClamBcPeSection(BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o+12,4)),BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o+8,4)),BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o+20,4)),BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o+16,4)),BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(o+36,4))));} return true;
    }

    private ulong PtrDiff32(ulong l,ulong r){var lIsPtr=TryPointer(l,out var lp);var rIsPtr=TryPointer(r,out var rp);if(lIsPtr&&rIsPtr&&!ReferenceEquals(lp!.Buffer,rp!.Buffer))return 0x40000000UL;var lo=lIsPtr?lp!.Offset:unchecked((int)l);var ro=rIsPtr?rp!.Offset:unchecked((int)r);return unchecked((ulong)(int)(lo-ro));}
    private ulong PtrToInt64(ulong v)=>TryPointer(v,out var p)?unchecked((ulong)(long)p.Offset):v;

    private ulong Get(ClamBcOperand operand, Dictionary<int, ulong> locals)
    {
        if (operand.IsConstant) return operand.Constant;
        if (operand.IsGlobal) return GetGlobal(operand.GlobalId);
        return locals.GetValueOrDefault(operand.Index);
    }

    private ulong GetGlobal(int id)
    {
        return id switch
        {
            0x8000 => 0, // match-count table is exposed only through full logical-hook support
            0x8001 => (ulong)_program.Metadata.Kind,
            0x8002 => 0, // virus-name table requires the native hook ABI
            0x8003 => 0, // PE hook data is not exposed by the managed core
            0x8004 => (ulong)_file.Length,
            0x8005 => _matchOffset is null ? 0UL : (ulong)_matchOffset.Value,
            _ => 0
        };
    }

    private ulong UDiv(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = Get(inst.Operands[0], locals); var b = Get(inst.Operands[1], locals);
        if (b == 0) throw new InvalidOperationException("bytecode attempted to execute udiv#0");
        return a / b;
    }

    private ulong SDiv(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = unchecked((long)Get(inst.Operands[0], locals)); var b = unchecked((long)Get(inst.Operands[1], locals));
        if (b == 0 || (a == long.MinValue && b == -1)) throw new InvalidOperationException("bytecode attempted to execute sdiv#0/overflow");
        return unchecked((ulong)(a / b));
    }

    private ulong URem(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = Get(inst.Operands[0], locals); var b = Get(inst.Operands[1], locals);
        if (b == 0) throw new InvalidOperationException("bytecode attempted to execute urem#0");
        return a % b;
    }

    private ulong SRem(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = unchecked((long)Get(inst.Operands[0], locals)); var b = unchecked((long)Get(inst.Operands[1], locals));
        if (b == 0 || (a == long.MinValue && b == -1)) throw new InvalidOperationException("bytecode attempted to execute srem#0/overflow");
        return unchecked((ulong)(a % b));
    }

    private ulong ShiftLeft(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = Get(inst.Operands[0], locals); var b = Get(inst.Operands[1], locals);
        var width = Math.Clamp(inst.Type, 1, 64);
        if (b >= (ulong)width) throw new InvalidOperationException("bytecode attempted invalid shl");
        return Truncate(a << (int)b, width);
    }

    private ulong ShiftRightLogical(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = Get(inst.Operands[0], locals); var b = Get(inst.Operands[1], locals);
        var width = Math.Clamp(inst.Type, 1, 64);
        if (b >= (ulong)width) throw new InvalidOperationException("bytecode attempted invalid lshr");
        return Truncate(a >> (int)b, width);
    }

    private ulong ShiftRightArithmetic(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        var a = Get(inst.Operands[0], locals); var b = Get(inst.Operands[1], locals);
        var width = Math.Clamp(inst.Type, 1, 64);
        if (b >= (ulong)width) throw new InvalidOperationException("bytecode attempted invalid ashr");
        var signed = SignExtend(a, width);
        return Truncate(unchecked((ulong)((long)signed >> (int)b)), width);
    }

    private ulong Bin(ClamBcInstruction inst, Dictionary<int, ulong> locals, Func<ulong, ulong, ulong> op)
        => op(Get(inst.Operands[0], locals), Get(inst.Operands[1], locals));

    private ulong Compare(ClamBcInstruction inst, Dictionary<int, ulong> locals, Func<ulong, ulong, bool> op)
        => op(Get(inst.Operands[0], locals), Get(inst.Operands[1], locals)) ? 1UL : 0UL;

    private ulong Truncate(ulong value, int type)
    {
        var width = Math.Clamp(type, 1, 64);
        return width == 64 ? value : value & ((1UL << width) - 1);
    }

    private ulong SignExtend(ulong value, int type)
    {
        var width = Math.Clamp(type, 1, 64);
        if (width == 64) return value;
        var mask = (1UL << width) - 1;
        value &= mask;
        var sign = 1UL << (width - 1);
        return (value & sign) != 0 ? value | ~mask : value;
    }

    private ulong GEP(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        if (inst.Operands.Count < 2 || !TryPointer(Get(inst.Operands[0], locals), out var ptr)) return 0;
        long delta = 0;
        if (inst.Opcode == 37 && inst.Operands.Count > 2)
        {
            for (var i = 1; i < inst.Operands.Count; i++)
            {
                var index = unchecked((long)Get(inst.Operands[i], locals));
                delta = checked(delta + checked(index * Math.Max(1, inst.GepScale)));
            }
        }
        else
        {
            var index = unchecked((long)Get(inst.Operands[1], locals));
            delta = checked(index * Math.Max(1, inst.GepScale));
        }
        var newOffset = checked((long)ptr.Offset + delta);
        if (newOffset < 0 || newOffset > ptr.Buffer.Length) return 0;
        var id = _nextPointer++;
        _pointers[id] = ptr with { Offset = (int)newOffset };
        return id;
    }

    private void Store(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        if (inst.Operands.Count < 2 || !TryPointer(Get(inst.Operands[0], locals), out var ptr)) return;
        var width = Math.Clamp((inst.Type + 7) / 8, 1, 8);
        WriteUInt(ptr.Buffer, ptr.Offset, Get(inst.Operands[1], locals), width);
    }

    private ulong Load(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        if (inst.Operands.Count == 0 || !TryPointer(Get(inst.Operands[0], locals), out var ptr)) return 0;
        var width = Math.Clamp((inst.Type + 7) / 8, 1, 8);
        return ReadUInt(ptr.Buffer, ptr.Offset, width);
    }

    private void Memset(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        if (inst.Operands.Count < 3 || !TryPointer(Get(inst.Operands[0], locals), out var ptr)) return;
        var len = Math.Clamp((int)Get(inst.Operands[2], locals), 0, ptr.Buffer.Length - ptr.Offset);
        ptr.Buffer.AsSpan(ptr.Offset, len).Fill((byte)Get(inst.Operands[1], locals));
    }

    private void Memcpy(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        if (inst.Operands.Count < 3 || !TryPointer(Get(inst.Operands[0], locals), out var dst) || !TryPointer(Get(inst.Operands[1], locals), out var src)) return;
        var len = Math.Min((int)Get(inst.Operands[2], locals), Math.Min(dst.Buffer.Length - dst.Offset, src.Buffer.Length - src.Offset));
        if (len > 0) src.Buffer.AsSpan(src.Offset, len).CopyTo(dst.Buffer.AsSpan(dst.Offset, len));
    }

    private ulong Memcmp(ClamBcInstruction inst, Dictionary<int, ulong> locals)
    {
        if (inst.Operands.Count < 3 || !TryPointer(Get(inst.Operands[0], locals), out var a) || !TryPointer(Get(inst.Operands[1], locals), out var b)) return 1;
        var len = Math.Min((int)Get(inst.Operands[2], locals), Math.Min(a.Buffer.Length - a.Offset, b.Buffer.Length - b.Offset));
        return len >= 0 && a.Buffer.AsSpan(a.Offset, len).SequenceEqual(b.Buffer.AsSpan(b.Offset, len)) ? 0UL : 1UL;
    }

    private bool TryPointer(ulong handle, out ClamBcPointer pointer) => _pointers.TryGetValue(handle, out pointer!);

    private bool TryReadString(ulong handle, out string value)
    {
        value = string.Empty;
        if (!TryPointer(handle, out var ptr) || ptr.Offset < 0 || ptr.Offset > ptr.Buffer.Length) return false;
        var span = ptr.Buffer.AsSpan(ptr.Offset);
        var end = span.IndexOf((byte)0);
        if (end < 0) end = span.Length;
        value = Encoding.UTF8.GetString(span[..end]);
        return true;
    }

    private static void WriteUInt(byte[] buffer, int offset, ulong value, int width)
    {
        if (offset < 0 || width <= 0 || offset + width > buffer.Length) return;
        for (var i = 0; i < width; i++) buffer[offset + i] = (byte)(value >> (i * 8));
    }

    private static ulong ReadUInt(byte[] buffer, int offset, int width)
    {
        if (offset < 0 || width <= 0 || offset + width > buffer.Length) return 0;
        ulong value = 0;
        for (var i = 0; i < width; i++) value |= (ulong)buffer[offset + i] << (i * 8);
        return value;
    }
}

internal sealed record ClamBcPointer(byte[] Buffer, int Offset);

internal sealed class ClamBcMapState
{
    public ClamBcMapState(int keySize, int valueSize) { KeySize = keySize; ValueSize = valueSize; }
    public int KeySize { get; }
    public int ValueSize { get; }
    public string? CurrentKey { get; set; }
    public Dictionary<string, ClamBcMapValue> Values { get; } = new(StringComparer.Ordinal);
}

internal sealed record ClamBcMapValue(byte[]? Data = null);
internal sealed class ClamBcBufferState
{
    public ClamBcBufferState(byte[]? data, long readCursor, int writeCursor, bool fileBacked)
    { Data = data; ReadCursor = readCursor; WriteCursor = writeCursor; FileBacked = fileBacked; }
    public byte[]? Data { get; }
    public long ReadCursor { get; set; }
    public int WriteCursor { get; set; }
    public bool FileBacked { get; }
}
internal sealed class ClamBcInflateState
{
    public ClamBcInflateState(int from, int to, int windowBits, bool done) { From = from; To = to; WindowBits = windowBits; Done = done; }
    public int From { get; }
    public int To { get; }
    public int WindowBits { get; }
    public bool Done { get; set; }
}

internal sealed class ClamBcPdfObject
{
    public ClamBcPdfObject(int id,int offset,int size,int flags){Id=id;Offset=offset;Size=size;Flags=flags;}
    public int Id { get; }
    public int Offset { get; }
    public int Size { get; }
    public int Flags { get; set; }
}
internal readonly record struct ClamBcPeSection(uint Rva,uint Vsz,uint Raw,uint Rsz,uint Chr);
