internal static partial class Program
{
    private static void ExecutableFormatTests()
    {
        // PE section/import specialized signatures and 32-bit/64-bit parsing.
        var peHashDbDir = Path.Combine(Path.GetTempPath(), "clamguard-pe-specialized-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(peHashDbDir);
        var pe32Special = BuildPeWithImport(false);
        var pe64Special = BuildPeWithImport(true);
        var sectionMd5 = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(pe32Special.AsSpan(0x200, 0x400))).ToLowerInvariant();
        var sectionSha1 = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(pe64Special.AsSpan(0x200, 0x400))).ToLowerInvariant();
        var importInput = "kernel32.createfilea";
        var importHash = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(Encoding.ASCII.GetBytes(importInput))).ToLowerInvariant();
        var peHashPath = Path.Combine(peHashDbDir, "specialized.mdb");
        File.WriteAllText(peHashPath, $"1024:{sectionMd5}:PE.SectionMD5\n");
        File.WriteAllText(Path.Combine(peHashDbDir, "specialized.msb"), $"1024:{sectionSha1}:PE.SectionSHA1\n");
        File.WriteAllText(Path.Combine(peHashDbDir, "specialized.imp"), $"{importHash}:{importInput.Length}:PE.ImportHash\n");
        var peHashManager = new DatabaseManager();
        peHashManager.LoadAndCompile(peHashDbDir, true);
        var peHashScanner = new ClamGuard.Scanner.ScannerEngine(peHashManager);
        var pe32Path = Path.Combine(Path.GetTempPath(), "specialized-32.exe");
        var pe64Path = Path.Combine(Path.GetTempPath(), "specialized-64.exe");
        File.WriteAllBytes(pe32Path, pe32Special);
        File.WriteAllBytes(pe64Path, pe64Special);
        var pe32Result = peHashScanner.Scan(pe32Path, new ScanOptions { CollectAllMatches = true });
        var pe64Result = peHashScanner.Scan(pe64Path, new ScanOptions { CollectAllMatches = true });
        Assert(pe32Result.Detections.Any(x => x.Name == "PE.SectionMD5"), "PE32 section MD5 signature matches raw section bytes");
        Assert(pe32Result.Detections.Any(x => x.Name == "PE.ImportHash"), "PE32 import hash signature matches normalized imports");
        Assert(pe64Result.Detections.Any(x => x.Name == "PE.SectionSHA1"), "PE32+ section SHA-1 signature matches raw section bytes");
        Assert(pe64Result.Detections.Any(x => x.Name == "PE.ImportHash"), "PE32+ import hash signature matches 64-bit thunk parsing");

        // ClamAV import-name normalization parity: the FIRST dot is significant.
        var dottedPe = BuildPeWithImport(false, "foo.bar.dll");
        var dottedImport = "foo.bar.dll.createfilea";
        var dottedHash = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(Encoding.ASCII.GetBytes(dottedImport))).ToLowerInvariant();
        var dottedDbDir = Path.Combine(Path.GetTempPath(), "clamguard-pe-dotted-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dottedDbDir);
        File.WriteAllText(Path.Combine(dottedDbDir, "dotted.imp"), $"{dottedHash}:{dottedImport.Length}:PE.DottedImport\n");
        var dottedManager = new DatabaseManager();
        dottedManager.LoadAndCompile(dottedDbDir, true);
        var dottedScanner = new ClamGuard.Scanner.ScannerEngine(dottedManager);
        var dottedPath = Path.Combine(Path.GetTempPath(), "dotted.exe");
        File.WriteAllBytes(dottedPath, dottedPe);
        Assert(dottedScanner.Scan(dottedPath).Detections.Any(x => x.Name == "PE.DottedImport"), "PE import hash preserves multi-dot library names like ClamAV");

        // ClamAV falls back from an invalid OriginalFirstThunk RVA to a valid FirstThunk RVA.
        dottedPe.AsSpan(0x300, 4).Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(dottedPe.AsSpan(0x300), 0xDEAD);
        File.WriteAllBytes(dottedPath, dottedPe);
        Assert(dottedScanner.Scan(dottedPath).Detections.Any(x => x.Name == "PE.DottedImport"), "PE import hash falls back from invalid OriginalFirstThunk");

        // ELF32 executable-relative target.
        var elfDbDir = Path.Combine(Path.GetTempPath(), "clamguard-elf-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(elfDbDir);
        var elfDbPath = Path.Combine(elfDbDir, "elf.ndb");
        File.WriteAllText(elfDbPath, "ELF.Entry:6:EP+0:7f454c46\n");
        var elfManager = new DatabaseManager();
        elfManager.LoadAndCompile(elfDbDir, true);
        var elfScanner = new ClamGuard.Scanner.ScannerEngine(elfManager);
        var elfPath = Path.Combine(Path.GetTempPath(), "minimal-32.elf");
        File.WriteAllBytes(elfPath, BuildMinimalElf32());
        Assert(elfScanner.Scan(elfPath).Detections.Any(x => x.Name == "ELF.Entry"), "ELF32 entry-point-relative matching resolves safely");

        // Universal Mach-O: LDB offsets are rebased to the selected architecture slice.
        var machoDbDir = Path.Combine(Path.GetTempPath(), "clamguard-macho-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(machoDbDir);
        var machoDbPath = Path.Combine(machoDbDir, "macho.ldb");
        File.WriteAllText(machoDbPath, "MachO.Slice;Engine:81-255,Target:9;0;feedfacf\n");
        var machoManager = new DatabaseManager();
        machoManager.LoadAndCompile(machoDbDir, true);
        var machoScanner = new ClamGuard.Scanner.ScannerEngine(machoManager);
        var machoPath = Path.Combine(Path.GetTempPath(), "universal-macho.bin");
        File.WriteAllBytes(machoPath, BuildMachOFat32());
        Assert(machoScanner.Scan(machoPath).Detections.Any(x => x.Name == "MachO.Slice"), "Universal Mach-O LDB target scans the selected architecture slice");

        var machoAllDbDir = Path.Combine(Path.GetTempPath(), "clamguard-macho-all-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(machoAllDbDir);
        File.WriteAllText(Path.Combine(machoAllDbDir, "all.ldb"), "MachO.SecondSlice;Engine:81-255,Target:9;0;deadbeef\n");
        var machoAllManager = new DatabaseManager();
        machoAllManager.LoadAndCompile(machoAllDbDir, true);
        var machoAllScanner = new ClamGuard.Scanner.ScannerEngine(machoAllManager);
        var machoAllPath = Path.Combine(Path.GetTempPath(), "universal-macho-two.bin");
        File.WriteAllBytes(machoAllPath, BuildMachOFat32TwoSlices());
        Assert(machoAllScanner.Scan(machoAllPath).Detections.Any(x => x.Name == "MachO.SecondSlice"), "Universal Mach-O scans signatures from every valid architecture slice");

        var macho64DbDir = Path.Combine(Path.GetTempPath(), "clamguard-macho64-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(macho64DbDir);
        File.WriteAllText(Path.Combine(macho64DbDir, "macho64.ldb"),
            "MachO.Section64;Engine:81-255,Target:9;0;SL+0:4d414348\n");
        var macho64Manager = new DatabaseManager();
        macho64Manager.LoadAndCompile(macho64DbDir, true);
        var macho64Scanner = new ClamGuard.Scanner.ScannerEngine(macho64Manager);
        var macho64Path = Path.Combine(Path.GetTempPath(), "mach64.bin");
        File.WriteAllBytes(macho64Path, BuildMachO64WithSection());
        Assert(macho64Scanner.Scan(macho64Path).Detections.Any(x => x.Name == "MachO.Section64"), "Mach-O 64-bit section virtual address/offset metadata is parsed correctly");

        File.Delete(peHashPath);
        File.Delete(Path.Combine(peHashDbDir, "specialized.msb"));
        File.Delete(Path.Combine(peHashDbDir, "specialized.imp"));
        Directory.Delete(peHashDbDir, true);
        File.Delete(pe32Path);
        File.Delete(pe64Path);
        Directory.Delete(dottedDbDir, true);
        File.Delete(dottedPath);
        Directory.Delete(elfDbDir, true);
        File.Delete(elfPath);
        Directory.Delete(machoDbDir, true);
        File.Delete(machoPath);
        Directory.Delete(machoAllDbDir, true);
        File.Delete(machoAllPath);
        File.Delete(macho64Path);
    }
}
