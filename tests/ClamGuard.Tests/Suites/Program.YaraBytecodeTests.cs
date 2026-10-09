internal static partial class Program
{
    private static async Task YaraAndBytecodeTestsAsync()
    {
        // YARA project integration: rules are loaded from the dedicated ClamGuard.Yara assembly.
        var yara = ClamGuard.Yara.YaraEngine.LoadText("rule ClamGuard_Yara_Integration {\n  strings:\n    $mz = { 4D 5A }\n    $hello = \"hello yara\" nocase\n  condition:\n    $mz and $hello\n}", "inline.yar");
        var yaraHits = yara.Scan(Encoding.ASCII.GetBytes("MZ....HELLO YARA"));
        Assert(yaraHits.Any(x => x.RuleName == "ClamGuard_Yara_Integration" && x.StringIdentifier == "$hello"), "YARA engine parses and evaluates a managed rule");

        // YARA nested-scan integration is exercised through ScanOptions in the scanner path.
        var yaraDir = Path.Combine(Path.GetTempPath(), "clamguard-yara-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(yaraDir);
        File.WriteAllText(Path.Combine(yaraDir, "integration.yar"), "rule NestedYara { strings: $x = \"NESTED-YARA\" condition: $x }");
        var nestedDb = Path.Combine(Path.GetTempPath(), "clamguard-yara-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(nestedDb);
        File.WriteAllText(Path.Combine(nestedDb, "dummy.ndb"), "Dummy.Ndb;Engine:81-255,Target:0;0;");
        var nestedZipPath = Path.Combine(Path.GetTempPath(), "nested-yara.zip");
        File.WriteAllBytes(nestedZipPath, CreateZipEntry("inside.txt", Encoding.ASCII.GetBytes("NESTED-YARA")));
        var nestedManager = new DatabaseManager();
        nestedManager.LoadAndCompile(nestedDb, true);
        var nestedResult = await new ClamGuard.Scanner.ScannerEngine(nestedManager).ScanAsync(nestedZipPath, new ScanOptions { YaraRuleDirectory = yaraDir });
        Assert(nestedResult.Detections.Any(x => x.Type == SignatureType.Yara && x.Name == "NestedYara"), "YARA scans nested archive children through scanner orchestration");
        Directory.Delete(yaraDir, true); Directory.Delete(nestedDb, true); File.Delete(nestedZipPath);

        // Minimal valid ClamBC program: format 7, one function, one RET constant.

        var cbcHeader = "ClamBC" + BcNumber(7) + BcNumber(0) + BcString("ClamGuard") + BcNumber(0) + BcNumber(0) + BcNumber(0) + BcNumber(0) + BcNumber(0) + BcString("ClamGuard.Bytecode") + BcNumber(69) + BcNumber(1) + BcNumber(0x53e5493e9f3d1c30UL) + BcFixed(42, 2) + ":1";
        var cbcText = cbcHeader + "\nBytecode.Integration;\nT" + BcFixed(69, 2) + "\nE" + BcNumber(0) + BcNumber(0) + "\nG" + BcNumber(0) + BcNumber(0) + "\nA" + BcFixed(0, 1) + BcNumber(64) + "L" + BcNumber(0) + "F" + BcNumber(1) + BcNumber(1) + "\nB" + BcNumber(64) + BcNumber(0) + BcFixed(19, 2) + BcNumber(64) + BcConstant64(0x1234f00d) + BcFixed(8, 1) + "T";
        var bytecodeEngine = ClamGuard.Bytecode.ClamBcEngine.LoadText(cbcText, "inline.cbc");
        var bytecodeHits = bytecodeEngine.Scan(ReadOnlySpan<byte>.Empty);
        Assert(bytecodeHits.Any(x => x.ReturnValue == 0x1234f00d), "ClamBC managed VM executes arithmetic/return bytecode");

        var malformedBytecode = ClamGuard.Bytecode.ClamBcEngine.LoadText("not-a-cbc", "invalid.cbc");
        Assert(malformedBytecode.Scan(ReadOnlySpan<byte>.Empty).Count == 0, "ClamBC loader safely ignores malformed bytecode");

        var invalidByteComparePath = Path.Combine(Path.GetTempPath(), "clamguard-bcomp-invalid.ldb");
        File.WriteAllText(invalidByteComparePath, "Invalid.ByteCompare;Engine:101-255,Target:0;0&1;4142;0(>>0#hb4#=16)\n");
        var zeroShiftRejected = false;
        try { _ = SignatureParser.ParseLdbFile(invalidByteComparePath).ToArray(); }
        catch (FormatException) { zeroShiftRejected = true; }
        Assert(zeroShiftRejected, "LDB byte-compare rejects a zero-byte offset");

        File.Delete(invalidByteComparePath);
    }
}
