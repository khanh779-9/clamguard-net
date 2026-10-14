using System.Text;
using System.Text.RegularExpressions;

namespace ClamGuard.Bytecode;

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
        // A malformed .cbc must not force an unbounded allocation here; real
        // ClamAV bytecode functions use far fewer locals than this ceiling.
        if (locals is < 0 or > 65536) throw new FormatException("Unsafe function locals count");
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
