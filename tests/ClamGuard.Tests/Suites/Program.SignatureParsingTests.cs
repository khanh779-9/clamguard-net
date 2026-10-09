internal static partial class Program
{
    private static void SignatureParsingTests()
    {
        // HandlerType must perform a full child-layer rescan, not only an LDB pass.
        var handlerTypePath = Path.Combine(Path.GetTempPath(), "clamguard-handler-type.ldb");
        File.WriteAllText(handlerTypePath,
            "Handler.Rescan;Engine:81-255,Target:0,HandlerType:PE;0;4141\n");
        var handlerTypeDir = Path.Combine(Path.GetTempPath(), "clamguard-handler-type-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(handlerTypeDir);
        File.Copy(handlerTypePath, Path.Combine(handlerTypeDir, "handler.ldb"));
        File.WriteAllText(Path.Combine(handlerTypeDir, "child.ndb"),
            "Handler.RescannedPE:1:*:4d5a\n");
        var handlerTypeManager = new DatabaseManager();
        handlerTypeManager.LoadAndCompile(handlerTypeDir, true);
        var handlerTypeScanner = new ClamGuard.Scanner.ScannerEngine(handlerTypeManager);
        var handlerTypeFile = Path.Combine(Path.GetTempPath(), "clamguard-handler-type.bin");
        File.WriteAllBytes(handlerTypeFile, "AA"u8.ToArray().Concat("MZ"u8.ToArray()).ToArray());
        var handlerResult = handlerTypeScanner.Scan(handlerTypeFile);
        Assert(handlerResult.Detections.Any(x => x.Name == "Handler.RescannedPE"),
            "LDB HandlerType performs a full retyped NDB scan");
        Assert(!handlerResult.Detections.Any(x => x.Name == "Handler.Rescan"),
            "HandlerType signature remains a retyping rule on the parent layer");

        var idb = Path.Combine(Path.GetTempPath(), "clamguard-test.idb");
        File.WriteAllText(idb, "Test.Icon:GROUP-A:GROUP-B:100620a0b05b0307055060b0350a0b0480307051060b8407008402058308058000008104098109096d020b6b0a046306031800001f040035080000000000\n");
        var iconDb = SignatureParser.ParseIdbFile(idb).Entries.Single();
        Assert(iconDb.Metric.Side == 16 && iconDb.Group1 == "GROUP-A" && iconDb.Group2 == "GROUP-B", "IDB icon metric is parsed for LDB icon matching");

        var ldbDistinctPath = Path.Combine(Path.GetTempPath(), "clamguard-distinct.ldb");
        File.WriteAllText(ldbDistinctPath,
            "Logic.Distinct;Engine:81-255,Target:0;(0|1)>2,2;4141;4242\n");
        var distinctLdb = SignatureParser.ParseLdbFile(ldbDistinctPath).Single();
        Assert(distinctLdb.Target!.Target == 0, "LDB target description parsed");
        Assert(distinctLdb.Expression == "(0|1)>2,2", "LDB logical expression is preserved");

        // A failed boolean block must contribute zero to an outer count modifier.
        var ldbFailedBlockPath = Path.Combine(Path.GetTempPath(), "clamguard-failed-block.ldb");
        File.WriteAllText(ldbFailedBlockPath,
            "Logic.FailedBlock;Engine:81-255,Target:0;(0&1)>0;4141;4242\n");
        var ldbFailedBlockDir = Path.Combine(Path.GetTempPath(), "clamguard-failed-block-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ldbFailedBlockDir);
        File.Copy(ldbFailedBlockPath, Path.Combine(ldbFailedBlockDir, "failed-block.ldb"));
        var ldbFailedBlockManager = new DatabaseManager();
        ldbFailedBlockManager.LoadAndCompile(ldbFailedBlockDir, true);
        var ldbFailedBlockScanner = new ClamGuard.Scanner.ScannerEngine(ldbFailedBlockManager);
        var ldbFailedBlockFile = Path.Combine(Path.GetTempPath(), "clamguard-failed-block.bin");
        File.WriteAllBytes(ldbFailedBlockFile, "AA"u8.ToArray());
        Assert(!ldbFailedBlockScanner.Scan(ldbFailedBlockFile).Detections.Any(x => x.Name == "Logic.FailedBlock"),
            "LDB failed boolean block does not leak count into outer modifier");

        var ldbFailedComparisonPath = Path.Combine(Path.GetTempPath(), "clamguard-failed-comparison.ldb");
        File.WriteAllText(ldbFailedComparisonPath,
            "Logic.FailedComparison;Engine:81-255,Target:0;(0=2)>0;4141\n");
        var ldbFailedComparisonDir = Path.Combine(Path.GetTempPath(), "clamguard-failed-comparison-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ldbFailedComparisonDir);
        File.Copy(ldbFailedComparisonPath, Path.Combine(ldbFailedComparisonDir, "failed-comparison.ldb"));
        var ldbFailedComparisonManager = new DatabaseManager();
        ldbFailedComparisonManager.LoadAndCompile(ldbFailedComparisonDir, true);
        var ldbFailedComparisonScanner = new ClamGuard.Scanner.ScannerEngine(ldbFailedComparisonManager);
        var ldbFailedComparisonFile = Path.Combine(Path.GetTempPath(), "clamguard-failed-comparison.bin");
        File.WriteAllBytes(ldbFailedComparisonFile, "AA"u8.ToArray());
        Assert(!ldbFailedComparisonScanner.Scan(ldbFailedComparisonFile).Detections.Any(x => x.Name == "Logic.FailedComparison"),
            "LDB failed comparison does not leak count into outer modifier");

        var macroNdbPath = Path.Combine(Path.GetTempPath(), "clamguard-macro.ndb");
        var macroLdbPath = Path.Combine(Path.GetTempPath(), "clamguard-macro.ldb");
        File.WriteAllText(macroNdbPath,
            "MacroA:0:$12$:626262\n" +
            "MacroB:0:$12$:636363\n");
        File.WriteAllText(macroLdbPath,
            "Logic.Macro;Engine:51-255,Target:0;0&1;616161;${3-4}12$\n");
        var macroNdb = SignatureParser.ParseNdbFile(macroNdbPath).ToArray();
        var macroLdb = SignatureParser.ParseLdbFile(macroLdbPath).Single();
        Assert(macroNdb.All(x => x.MacroGroup == 12), "NDB macro group membership is parsed");
        Assert(macroLdb.MacroSubSignatures is { Count: 1 } && macroLdb.MacroSubSignatures.ContainsKey(1), "LDB macro subsignature is parsed");

        var macroDbDir = Path.Combine(Path.GetTempPath(), "clamguard-macro-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(macroDbDir);
        File.Copy(macroNdbPath, Path.Combine(macroDbDir, "macro.ndb"));
        File.Copy(macroLdbPath, Path.Combine(macroDbDir, "macro.ldb"));
        var macroManager = new DatabaseManager();
        macroManager.LoadAndCompile(macroDbDir, true);
        var macroScanner = new ClamGuard.Scanner.ScannerEngine(macroManager);
        var macroFile = Path.Combine(Path.GetTempPath(), "macro.bin");
        File.WriteAllBytes(macroFile, new byte[] { 0x61, 0x61, 0x61, 0x62, 0x62, 0x62 });
        var macroResult = macroScanner.Scan(macroFile);
        Assert(macroResult.Detections.Any(x => x.Name == "Logic.Macro"), "LDB macro logical signature matches an NDB macro group");

        var lineBoundary = HexPatternParser.Parse("(L)4142");
        Assert(lineBoundary.Matches("AB"u8, 0, out _), "line-boundary class also matches the start of the file");
        Assert(lineBoundary.Matches("\r\nAB"u8, 2, out _), "line-boundary class matches after CRLF");

        var wideGap = HexPatternParser.Parse("68{1-2}6f").ToWideVariant();
        Assert(wideGap.Matches("h\0e\0o\0"u8, 0, out _), "wide modifier doubles bounded gap distances");

        var regexPath = Path.Combine(Path.GetTempPath(), "clamguard-regex.ldb");
        File.WriteAllText(regexPath,
            "Logic.Regex;Engine:81-255,Target:0;0&1;61;0:0/aB/i\n");
        var regexSig = SignatureParser.ParseLdbFile(regexPath).Single();
        Assert(regexSig.RegexSubSignatures is { Count: 1 } && regexSig.RegexSubSignatures[1].Trigger == "0" &&
               regexSig.RegexSubSignatures[1].Pattern == "aB" && regexSig.RegexSubSignatures[1].Flags == "i",
               "LDB PCRE trigger, pattern and flags parse");

        var regexDbDir = Path.Combine(Path.GetTempPath(), "clamguard-regex-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(regexDbDir);
        File.Copy(regexPath, Path.Combine(regexDbDir, "regex.ldb"));
        var regexManager = new DatabaseManager();
        regexManager.LoadAndCompile(regexDbDir, true);
        var regexScanner = new ClamGuard.Scanner.ScannerEngine(regexManager);
        var regexFile = Path.Combine(Path.GetTempPath(), "regex.bin");
        File.WriteAllBytes(regexFile, "aB"u8.ToArray());
        var regexResult = regexScanner.Scan(regexFile);
        Assert(regexResult.Detections.Any(x => x.Name == "Logic.Regex"), "LDB PCRE subsignature executes after its trigger");

        var byteComparePath = Path.Combine(Path.GetTempPath(), "clamguard-bcomp.ldb");
        File.WriteAllText(byteComparePath,
            "Logic.ByteCompare;Engine:101-255,Target:0;0&1;4142;0(>>2#hb4#=16)\n");
        var byteCompareSig = SignatureParser.ParseLdbFile(byteComparePath).Single();
        Assert(byteCompareSig.ByteCompareSubSignatures is { Count: 1 } &&
               byteCompareSig.ByteCompareSubSignatures[1].ReferenceSubSignature == 0 &&
               byteCompareSig.ByteCompareSubSignatures[1].Shift == 2 &&
               byteCompareSig.ByteCompareSubSignatures[1].ByteLength == 4,
               "LDB byte-compare fields parse");

        var byteCompareDbDir = Path.Combine(Path.GetTempPath(), "clamguard-bcomp-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(byteCompareDbDir);
        File.Copy(byteComparePath, Path.Combine(byteCompareDbDir, "bcomp.ldb"));
        var byteCompareManager = new DatabaseManager();
        byteCompareManager.LoadAndCompile(byteCompareDbDir, true);
        var byteCompareScanner = new ClamGuard.Scanner.ScannerEngine(byteCompareManager);
        var byteCompareFile = Path.Combine(Path.GetTempPath(), "bcomp.bin");
        File.WriteAllBytes(byteCompareFile, "AB0010"u8.ToArray());
        var byteCompareResult = byteCompareScanner.Scan(byteCompareFile);
        Assert(byteCompareResult.Detections.Any(x => x.Name == "Logic.ByteCompare"), "LDB byte-compare subsignature evaluates its referenced match");

        File.Delete(handlerTypePath);
        Directory.Delete(handlerTypeDir, true);
        File.Delete(handlerTypeFile);
        File.Delete(idb);
        File.Delete(ldbDistinctPath);
        File.Delete(macroNdbPath);
        File.Delete(macroLdbPath);
        File.Delete(macroFile);
        Directory.Delete(macroDbDir, true);
        File.Delete(ldbFailedBlockPath);
        File.Delete(ldbFailedBlockFile);
        Directory.Delete(ldbFailedBlockDir, true);
        File.Delete(ldbFailedComparisonPath);
        File.Delete(ldbFailedComparisonFile);
        Directory.Delete(ldbFailedComparisonDir, true);
        File.Delete(regexPath);
        File.Delete(regexFile);
        Directory.Delete(regexDbDir, true);
        File.Delete(byteComparePath);
        File.Delete(byteCompareFile);
        Directory.Delete(byteCompareDbDir, true);
    }
}
