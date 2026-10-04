using System.Text.Json;
using ClamGuard.Database;
using ClamGuard.Scanner;
using ClamGuard.Update;

static void Usage()
{
    Console.WriteLine("ClamGuard.NET\n");
    Console.WriteLine("Commands:");
    Console.WriteLine("  db info <file>");
    Console.WriteLine("  db verify <file.cvd> [certs-directory]");
    Console.WriteLine("  db load <directory>");
    Console.WriteLine("  db cdiff <patch.cdiff> <directory>");
    Console.WriteLine("  scan <file> --db <directory> [--yara <directory>] [--bytecode <directory>] [--json]");
    Console.WriteLine("  update <directory> [--base <url>]");
}

if (args.Length == 0) { Usage(); return; }

try
{
    switch (args[0].ToLowerInvariant())
    {
        case "db" when args.Length >= 3 && args[1].Equals("info", StringComparison.OrdinalIgnoreCase):
            var info = DatabaseLoader.ReadInfo(args[2]);
            Console.WriteLine($"Database        : {info.Name}");
            Console.WriteLine($"Format          : {info.Format}");
            Console.WriteLine($"Version         : {info.Version}");
            Console.WriteLine($"Signature Count : {info.SignatureCount}");
            Console.WriteLine($"Functionality   : {info.FunctionalityLevel}");
            Console.WriteLine($"Builder         : {info.Builder ?? "n/a"}");
            break;

        case "db" when args.Length >= 3 && args[1].Equals("verify", StringComparison.OrdinalIgnoreCase):
            var certsDirectory = args.Length >= 4 ? args[3] : null;
            var verification = DatabaseVerifier.VerifyCvd(args[2], certsDirectory);
            Console.WriteLine($"Status          : {verification.Status}");
            Console.WriteLine($"Signer          : {verification.Signer ?? "n/a"}");
            Console.WriteLine($"Verified files  : {verification.VerifiedFiles}/{verification.TotalListedFiles}");
            Console.WriteLine($"Message         : {verification.Message}");
            if (verification.Status != DatabaseVerificationStatus.Verified) Environment.ExitCode = 2;
            break;

        case "db" when args.Length >= 4 && args[1].Equals("cdiff", StringComparison.OrdinalIgnoreCase):
            await new CdiffPatchApplier().ApplyAsync(args[2], args[3]);
            Console.WriteLine("CDIFF           : applied successfully");
            break;

        case "db" when args.Length >= 3 && args[1].Equals("load", StringComparison.OrdinalIgnoreCase):
            var loaded = new DatabaseLoader().LoadDirectory(args[2]);
            Console.WriteLine($"Database files  : {loaded.Files.Count}");
            Console.WriteLine($"Signatures      : {loaded.SignatureCount}");
            foreach (var dbFile in loaded.Files) Console.WriteLine($"  {dbFile.Name} => {dbFile.SignatureCount}");
            break;

        case "scan":
            var file = args.Length >= 2 ? args[1] : throw new ArgumentException("A file path is required.");
            var dbIndex = Array.FindIndex(args, x => x.Equals("--db", StringComparison.OrdinalIgnoreCase));
            if (dbIndex < 0 || dbIndex + 1 >= args.Length) throw new ArgumentException("Use --db <directory>.");
            var manager = new DatabaseManager();
            _ = manager.LoadAndCompile(args[dbIndex + 1]);
            var yaraIndex = Array.FindIndex(args, x => x.Equals("--yara", StringComparison.OrdinalIgnoreCase));
            var yaraDirectory = yaraIndex >= 0 && yaraIndex + 1 < args.Length ? args[yaraIndex + 1] : null;
            var bytecodeIndex = Array.FindIndex(args, x => x.Equals("--bytecode", StringComparison.OrdinalIgnoreCase));
            var bytecodeDirectory = bytecodeIndex >= 0 && bytecodeIndex + 1 < args.Length ? args[bytecodeIndex + 1] : null;
            var result = await new ScannerEngine(manager).ScanAsync(file, new ClamGuard.Core.ScanOptions
            {
                YaraRuleDirectory = yaraDirectory,
                BytecodeDirectory = bytecodeDirectory
            });
            if (args.Contains("--json", StringComparer.OrdinalIgnoreCase))
                Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            else
            {
                Console.WriteLine($"File       : {result.FilePath}");
                Console.WriteLine($"Type       : {result.FileType}");
                Console.WriteLine($"Verdict    : {result.Verdict}");
                Console.WriteLine($"Bytes      : {result.BytesScanned}");
                foreach (var detection in result.Detections)
                    Console.WriteLine($"Detection  : {detection.Name} [{detection.Type}] @ {detection.Offset?.ToString() ?? "n/a"}");
            }
            break;

        case "update":
            var directory = args.Length >= 2 ? args[1] : throw new ArgumentException("A database directory is required.");
            var cdiffIndex = Array.FindIndex(args, x => x.Equals("--cdiff", StringComparison.OrdinalIgnoreCase));
            if (cdiffIndex >= 0 && cdiffIndex + 1 < args.Length)
            {
                await new CdiffPatchApplier().ApplyAsync(args[cdiffIndex + 1], directory);
                Console.WriteLine("CDIFF   : applied successfully");
                break;
            }
            var baseIndex = Array.FindIndex(args, x => x.Equals("--base", StringComparison.OrdinalIgnoreCase));
            var baseUri = baseIndex >= 0 && baseIndex + 1 < args.Length ? new Uri(args[baseIndex + 1]) : new Uri("https://database.clamav.net/");
            var update = await new DatabaseUpdater(options: new ClamGuard.Core.UpdateOptions { BaseUri = baseUri }).UpdateCvdAsync(directory);
            Console.WriteLine($"Status  : {update.Status}");
            Console.WriteLine($"Local   : {update.LocalVersion?.ToString() ?? "none"}");
            Console.WriteLine($"Remote  : {update.RemoteVersion?.ToString() ?? "unknown"}");
            Console.WriteLine($"Message : {update.Message}");
            break;

        default:
            Usage();
            break;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    Environment.ExitCode = 2;
}
