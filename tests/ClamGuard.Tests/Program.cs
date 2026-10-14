global using System.Buffers.Binary;
global using System.Diagnostics;
global using System.Formats.Tar;
global using System.IO.Compression;
global using System.Text;
global using ClamGuard.Core;
global using ClamGuard.Signatures;
global using ClamGuard.Database;
global using ClamGuard.Scanner;
global using ClamGuard.Signatures.Parsing;
global using ClamGuard.Signatures.Patterns;

internal static partial class Program
{
    private static async Task<int> Main(string[] args)
    {
        string? needle = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--filter", StringComparison.OrdinalIgnoreCase))
                continue;
            var value = args[i]["--filter".Length..].TrimStart('=', ':');
            if (string.IsNullOrEmpty(value) && i + 1 < args.Length)
                value = args[i + 1];
            needle = value;
        }

        var suites = new (string Name, Func<Task> Run)[]
        {
            ("ScanHostSmoke", () => ScanHostSmokeAsync()),
            ("SpecializedHandlersSmoke", () => SpecializedHandlersSmokeAsync()),
            ("NativeSpecializedSmoke", () => NativeSpecializedSmokeAsync()),
            ("SpecialDatabaseLoadSmoke", () => Task.Run(SpecialDatabaseLoadSmoke)),
            ("ScanPipelineFileTypeSmoke", () => ScanPipelineFileTypeSmokeAsync()),
            ("DatabaseAndCvd", () => Task.Run(DatabaseAndCvdTests)),
            ("CompiledMatcher", () => Task.Run(CompiledMatcherTestsAsync)),
            ("SignatureParsing", () => Task.Run(SignatureParsingTests)),
            ("NdbAndPolicy", () => Task.Run(NdbAndPolicyTests)),
            ("ContainerLayer", () => Task.Run(ContainerLayerTests)),
            ("ExecutableFormat", () => Task.Run(ExecutableFormatTests)),
            ("LdbSignatureParity", () => Task.Run(LdbSignatureParityTests)),
            ("ArchiveDocument", () => Task.Run(ArchiveDocumentTests)),
            ("YaraAndBytecode", () => YaraAndBytecodeTestsAsync()),
            ("SelfProtectionAndMetadata", () => SelfProtectionAndMetadataTestsAsync()),
            ("ScanOptionsBehavior", () => Task.Run(ScanOptionsBehaviorTests)),
        };

        var selected = string.IsNullOrWhiteSpace(needle)
            ? suites
            : suites.Where(s => s.Name.Contains(needle, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (selected.Length == 0)
        {
            Console.Error.WriteLine($"No suite matches filter '{needle}'.");
            return 2;
        }

        var passed = 0;
        var failed = new List<string>();
        var stopwatch = Stopwatch.StartNew();
        foreach (var (name, run) in selected)
        {
            var suiteWatch = Stopwatch.StartNew();
            try
            {
                await run();
                Interlocked.Increment(ref passed);
                Console.WriteLine($"SUITE OK   {name} ({suiteWatch.ElapsedMilliseconds} ms)");
            }
            catch (OperationCanceledException)
            {
                failed.Add($"{name}: cancelled");
                Console.WriteLine($"SUITE SKIP {name}: cancelled");
            }
            catch (Exception ex)
            {
                // Failure isolation: one failing suite must not hide the result
                // of every suite after it.
                failed.Add($"{name}: {ex.Message}");
                Console.WriteLine($"SUITE FAIL {name} ({suiteWatch.ElapsedMilliseconds} ms): {ex.Message}");
            }
        }

        stopwatch.Stop();
        Console.WriteLine($"Suites: {passed}/{selected.Length} passed, {failed.Count} failed in {stopwatch.Elapsed.TotalSeconds:F1}s.");
        if (failed.Count > 0)
        {
            foreach (var failure in failed)
                Console.Error.WriteLine("FAILED: " + failure);
            return 1;
        }

        Console.WriteLine("All tests passed.");
        return 0;
    }
}
