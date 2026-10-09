namespace ClamGuard.Database.Update;

/// <summary>Applies a ClamAV incremental database patch.</summary>
public sealed class CdiffPatchApplier
{
    private readonly string? _certsDirectory;

    public CdiffPatchApplier(string? certsDirectory = null) => _certsDirectory = certsDirectory;
    private const int MaxPatchFileBytes = 64 * 1024 * 1024;
    private const int MaxScriptBytes = 32 * 1024 * 1024;
    private const int MaxCommands = 250_000;
    private const int MaxLineBytes = 2 * 1024 * 1024;
    private static readonly byte[] HeaderPrefix = "ClamAV-Diff:"u8.ToArray();

    public async Task ApplyAsync(string patchFile, string workingDirectory, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(patchFile);
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        if (!File.Exists(patchFile)) throw new FileNotFoundException("CDIFF patch not found.", patchFile);
        if (!Directory.Exists(workingDirectory)) throw new DirectoryNotFoundException(workingDirectory);

        var fileInfo = new FileInfo(patchFile);
        if (fileInfo.Length <= 0 || fileInfo.Length > MaxPatchFileBytes)
            throw new InvalidDataException("CDIFF patch size is outside the supported range.");

        var patch = await File.ReadAllBytesAsync(patchFile, cancellationToken);
        var parsed = ParsePatch(patch);
        if (!ClamGuard.Database.ClamAvSignatureVerifier.VerifyCdiffSha256Pss2(parsed.PayloadDigest, parsed.DigitalSignature))
            throw new InvalidDataException("CDIFF digital signature verification failed.");

        ApplyCommands(parsed.Script, Path.GetFullPath(workingDirectory), cancellationToken);
    }

    private static ParsedPatch ParsePatch(byte[] patch)
    {
        var headerEnd = FindThirdColon(patch);
        if (headerEnd < 0 || headerEnd + 1 >= patch.Length)
            throw new InvalidDataException("Malformed CDIFF header.");

        var headerText = System.Text.Encoding.ASCII.GetString(patch, 0, headerEnd + 1);
        var fields = headerText.TrimEnd(':').Split(':');
        if (fields.Length != 3 || fields[0] != "ClamAV-Diff")
            throw new InvalidDataException("Malformed CDIFF header.");
        if (!uint.TryParse(fields[1], out var version) || version == 0)
            throw new InvalidDataException("Invalid CDIFF version.");
        if (!uint.TryParse(fields[2], out var expectedScriptBytes))
            throw new InvalidDataException("Invalid CDIFF uncompressed length.");

        var footerColon = Array.LastIndexOf(patch, (byte)':');
        if (footerColon <= headerEnd || footerColon + 1 >= patch.Length)
            throw new InvalidDataException("CDIFF signature footer is missing.");
        var signature = System.Text.Encoding.ASCII.GetString(patch, footerColon + 1, patch.Length - footerColon - 1).Trim();
        if (signature.Length == 0 || signature.Length > 700)
            throw new InvalidDataException("Malformed CDIFF signature.");

        using var compressed = new MemoryStream(patch, headerEnd + 1, footerColon - headerEnd - 1, writable: false);
        using var gzip = new System.IO.Compression.GZipStream(compressed, System.IO.Compression.CompressionMode.Decompress, leaveOpen: false);
        using var output = new MemoryStream((int)Math.Min((long)expectedScriptBytes, MaxScriptBytes));
        gzip.CopyTo(output, 64 * 1024);
        if (output.Length > MaxScriptBytes || output.Length != expectedScriptBytes)
            throw new InvalidDataException("CDIFF decompressed script length does not match the header.");

        var script = output.ToArray();
        var digest = System.Security.Cryptography.SHA256.HashData(patch.AsSpan(0, footerColon));
        return new ParsedPatch(version, script, digest, signature);
    }

    private static int FindThirdColon(byte[] patch)
    {
        if (patch.Length < HeaderPrefix.Length || !patch.AsSpan(0, HeaderPrefix.Length).SequenceEqual(HeaderPrefix))
            return -1;
        var count = 0;
        for (var i = 0; i < patch.Length; i++)
        {
            if (patch[i] != (byte)':') continue;
            if (++count == 3) return i;
        }
        return -1;
    }

    private static void ApplyCommands(byte[] script, string workingDirectory, CancellationToken cancellationToken)
    {
        var context = new Context(workingDirectory);
        using var reader = new StringReader(System.Text.Encoding.UTF8.GetString(script));
        string? line;
        var lineNo = 0;
        var commandCount = 0;
        while ((line = reader.ReadLine()) is not null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (++commandCount > MaxCommands) throw new InvalidDataException("CDIFF contains too many commands.");
            lineNo++;
            if (System.Text.Encoding.UTF8.GetByteCount(line) > MaxLineBytes)
                throw new InvalidDataException($"CDIFF line {lineNo} is too large.");
            if (line.StartsWith('#')) continue;
            ExecuteCommand(context, line, lineNo);
        }
        if (context.OpenDatabase is not null)
            throw new InvalidDataException($"CDIFF ended with database '{context.OpenDatabase}' still open.");
    }

    private static readonly System.Text.UTF8Encoding strictUtf8Fallback = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static void ExecuteCommand(Context ctx, string line, int lineNo)
    {
        var split = line.IndexOf(' ');
        var command = split < 0 ? line : line[..split];
        var arg = split < 0 ? null : line[(split + 1)..];
        switch (command)
        {
            case "OPEN": Open(ctx, arg, lineNo); break;
            case "ADD": Add(ctx, arg, lineNo); break;
            case "DEL": ApplyEdit(ctx, arg, false, lineNo); break;
            case "XCHG": ApplyEdit(ctx, arg, true, lineNo); break;
            case "MOVE": Move(ctx, arg, lineNo); break;
            case "CLOSE": Close(ctx, lineNo); break;
            case "UNLINK": Unlink(ctx, arg, lineNo); break;
            default: throw Error(lineNo, "Unsupported CDIFF command.");
        }
    }

    private static void Open(Context ctx, string? arg, int lineNo)
    {
        if (string.IsNullOrWhiteSpace(arg)) throw Error(lineNo, "OPEN requires a database name.");
        if (ctx.OpenDatabase is not null) throw Error(lineNo, "OPEN requires the previous database to be closed.");
        ctx.OpenDatabase = ValidateName(arg, lineNo);
        ctx.Edits.Clear();
        ctx.Additions.Clear();
    }

    private static void Add(Context ctx, string? arg, int lineNo)
    {
        if (ctx.OpenDatabase is null) throw Error(lineNo, "ADD requires an open database.");
        if (arg is null) throw Error(lineNo, "ADD requires a line.");
        ctx.Additions.Add(arg);
    }

    private static void ApplyEdit(Context ctx, string? arg, bool exchange, int lineNo)
    {
        if (ctx.OpenDatabase is null) throw Error(lineNo, $"{(exchange ? "XCHG" : "DEL")} requires an open database.");
        if (arg is null) throw Error(lineNo, "Missing edit arguments.");
        var parts = arg.Split(' ', exchange ? 3 : 2);
        if (parts.Length < (exchange ? 3 : 2) || !ulong.TryParse(parts[0], out var lineNumber) || lineNumber is 0 or > int.MaxValue)
            throw Error(lineNo, "Invalid edit line number.");
        var original = parts[1];
        string? replacement = exchange ? parts[2] : null;
        ctx.Edits[(int)lineNumber] = new Edit((int)lineNumber, original, replacement);
    }

    private static void Close(Context ctx, int lineNo)
    {
        var name = ctx.OpenDatabase ?? throw Error(lineNo, "CLOSE requires an open database.");
        var path = SafeCombine(ctx.WorkingDirectory, name, lineNo);
        if (!File.Exists(path) && ctx.Edits.Count > 0)
            throw Error(lineNo, $"Database file '{name}' does not exist for DEL/XCHG.");

        if (ctx.Edits.Count > 0)
        {
            var source = File.ReadAllLines(path, strictUtf8Fallback);
            var temp = path + $".{Guid.NewGuid():N}.tmp";
            try
            {
                using var writer = new StreamWriter(temp, false, new System.Text.UTF8Encoding(false));
                var editIndex = 0;
                var ordered = ctx.Edits.Values.OrderBy(x => x.LineNumber).ToArray();
                foreach (var (line, index) in source.Select((value, index) => (value, index + 1)))
                {
                    if (editIndex < ordered.Length && ordered[editIndex].LineNumber == index)
                    {
                        var edit = ordered[editIndex++];
                        if (!line.StartsWith(edit.Original, StringComparison.Ordinal))
                            throw Error(lineNo, $"Edit pattern did not match line {index} in '{name}'.");
                        if (edit.Replacement is not null) writer.WriteLine(edit.Replacement);
                    }
                    else
                    {
                        writer.WriteLine(line);
                    }
                }
                if (editIndex != ordered.Length)
                    throw Error(lineNo, $"Not all edits for '{name}' were applied.");
                writer.Flush();
                ReplaceFile(temp, path);
            }
            catch
            {
                TryDelete(temp);
                throw;
            }
        }

        if (ctx.Additions.Count > 0)
            File.AppendAllLines(path, ctx.Additions, new System.Text.UTF8Encoding(false));
        ctx.OpenDatabase = null;
        ctx.Edits.Clear();
        ctx.Additions.Clear();
    }

    private static void Move(Context ctx, string? arg, int lineNo)
    {
        if (ctx.OpenDatabase is not null) throw Error(lineNo, "MOVE requires no database to be open.");
        if (arg is null) throw Error(lineNo, "MOVE requires six arguments.");
        var parts = arg.Split(' ', 6);
        if (parts.Length != 6 || !int.TryParse(parts[2], out var start) || !int.TryParse(parts[4], out var end) || start <= 0 || end < start)
            throw Error(lineNo, "Invalid MOVE arguments.");

        var srcName = ValidateName(parts[0], lineNo);
        var dstName = ValidateName(parts[1], lineNo);
        var src = SafeCombine(ctx.WorkingDirectory, srcName, lineNo);
        var dst = SafeCombine(ctx.WorkingDirectory, dstName, lineNo);
        if (!File.Exists(src) || !File.Exists(dst)) throw Error(lineNo, "MOVE source or destination does not exist.");

        var lines = File.ReadAllLines(src, strictUtf8Fallback);
        if (start > lines.Length || end > lines.Length) throw Error(lineNo, "MOVE range exceeds source file.");
        if (!lines[start - 1].StartsWith(parts[3], StringComparison.Ordinal) || !lines[end - 1].StartsWith(parts[5], StringComparison.Ordinal))
            throw Error(lineNo, "MOVE boundary pattern did not match.");

        File.AppendAllLines(dst, lines.Skip(start - 1).Take(end - start + 1), new System.Text.UTF8Encoding(false));
        var temp = src + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllLines(temp, lines.Take(start - 1).Concat(lines.Skip(end)), new System.Text.UTF8Encoding(false));
            ReplaceFile(temp, src);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
    }

    private static void Unlink(Context ctx, string? arg, int lineNo)
    {
        if (ctx.OpenDatabase is not null) throw Error(lineNo, "UNLINK requires no database to be open.");
        if (arg is null) throw Error(lineNo, "UNLINK requires a database name.");
        var name = ValidateName(arg, lineNo);
        var path = SafeCombine(ctx.WorkingDirectory, name, lineNo);
        if (!File.Exists(path)) throw Error(lineNo, $"Database file '{name}' does not exist.");
        File.Delete(path);
    }

    private static string ValidateName(string name, int lineNo)
    {
        if (name.Length > 255 || name.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '.' or '_')))
            throw Error(lineNo, $"Unsafe database name '{name}'.");
        return name;
    }

    private static string SafeCombine(string root, string name, int lineNo)
    {
        var full = Path.GetFullPath(Path.Combine(root, name));
        if (!full.StartsWith(root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw Error(lineNo, "CDIFF path escapes the working directory.");
        return full;
    }

    private static void ReplaceFile(string temp, string destination)
    {
        if (OperatingSystem.IsWindows() && File.Exists(destination))
        {
            var backup = destination + ".cdiff-old";
            try
            {
                File.Replace(temp, destination, backup, ignoreMetadataErrors: true);
                TryDelete(backup);
                return;
            }
            catch (PlatformNotSupportedException) { TryDelete(backup); }
        }
        File.Move(temp, destination, true);
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static InvalidDataException Error(int line, string message) => new($"CDIFF line {line}: {message}");

    private sealed class Context(string workingDirectory)
    {
        public string WorkingDirectory { get; } = workingDirectory;
        public string? OpenDatabase { get; set; }
        public Dictionary<int, Edit> Edits { get; } = [];
        public List<string> Additions { get; } = [];
    }

    private sealed record Edit(int LineNumber, string Original, string? Replacement);
    private sealed record ParsedPatch(uint Version, byte[] Script, byte[] PayloadDigest, string DigitalSignature);
}
