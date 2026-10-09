using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClamGuard.Bytecode;

internal sealed partial class ClamBcVirtualMachine
{
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
}
