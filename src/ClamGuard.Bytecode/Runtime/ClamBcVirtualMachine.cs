using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ClamGuard.Bytecode;

internal sealed partial class ClamBcVirtualMachine
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

    public ClamBcVirtualMachine(ClamBcProgram program, ReadOnlyMemory<byte> file, BytecodeScanOptions options, CancellationToken token)
    {
        _program = program;
        // The file is only ever read (all pointer writes target fresh copies),
        // so the scan buffer is shared across programs instead of copied.
        _file = file;
        _originalFile = file;
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
        catch (BytecodeBudgetExceededException ex)
        {
            // A program that exhausts its fuel/runtime budget must be skipped,
            // not mistaken for user cancellation (which would abort the whole
            // file scan).
            return (false, null, null, 0, $"bytecode skipped: {ex.Message}");
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
                if (++_executed > _options.MaxInstructions) throw new BytecodeBudgetExceededException("instruction budget exceeded");
                if ((_executed & 1023) == 0 && _runtime.Elapsed > _options.MaxRuntime) throw new BytecodeBudgetExceededException("runtime budget exceeded");
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
    {
        // LLVM semantics: arithmetic/bitwise results wrap to the instruction's
        // integer width (ClamAV's VM stores typed values, e.g. i32 add wraps).
        var value = op(Get(inst.Operands[0], locals), Get(inst.Operands[1], locals));
        return inst.Type is 8 or 16 or 32 or 64 ? Truncate(value, inst.Type) : value;
    }

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
