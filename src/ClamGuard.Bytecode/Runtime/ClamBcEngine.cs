using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

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
        try
        {
            var program = ClamBcParser.Parse(text, source, options);
            return new ClamBcEngine(program is null ? Array.Empty<ClamBcProgram>() : [program]);
        }
        catch (FormatException)
        {
            // Skip malformed/incompatible bytecode safely, matching LoadDirectory.
        }
        catch (OverflowException)
        {
            // Skip integer-overflowing bytecode safely, matching LoadDirectory.
        }
        catch (IndexOutOfRangeException)
        {
            // Skip structurally truncated bytecode safely, matching LoadDirectory.
        }
        catch (ArgumentException)
        {
            // Skip malformed argument encodings safely, matching LoadDirectory.
        }
        return new ClamBcEngine([]);
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
