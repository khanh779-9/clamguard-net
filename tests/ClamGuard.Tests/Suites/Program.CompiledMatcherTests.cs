internal static partial class Program
{
    private static async Task CompiledMatcherTestsAsync()
    {
        var compiled = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        compiled.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.Pattern",
            SignatureType.Content,
            "test.db",
            HexPatternParser.Parse("6d616c77617265")));
        compiled.Build();
        var hits = compiled.Match("xxmalwareyy"u8, "test.db");
        Assert(hits.Count == 1 && hits[0].Name == "Demo.Pattern", "compiled content matcher detects a fixed pattern");

        compiled.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.Range",
            SignatureType.Content,
            "test.db",
            HexPatternParser.Parse("68{1-3}6f")));
        compiled.Build();
        var rangeHits = compiled.Match("hello"u8, "test.db");
        Assert(rangeHits.Any(x => x.Name == "Demo.Range"), "compiled matcher detects a bounded-gap pattern");

        var trustedFile = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        var fpHash = System.Security.Cryptography.MD5.HashData("hello"u8);
        trustedFile.Add(new ClamGuard.Signatures.HashSignature("FP.Hello", SignatureType.Trust, "test.fp", HashAlgorithmKind.Md5, fpHash, 5));
        trustedFile.Build();
        Assert(trustedFile.MatchesFalsePositive("hello"u8), "false-positive hash is treated as trust data");

        var fpSuppressSet = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        fpSuppressSet.Add(new ClamGuard.Signatures.ContentSignature(
            "FP.Suppress.Me", SignatureType.Content, "test.db", HexPatternParser.Parse("68656c6c6f")));
        fpSuppressSet.Add(new ClamGuard.Signatures.HashSignature(
            "FP.Trust.Hello", SignatureType.Trust, "test.fp", HashAlgorithmKind.Md5, fpHash, 5));
        fpSuppressSet.Build();
        var suppressedDirectHits = fpSuppressSet.Match("hello"u8, "test.db");
        Assert(suppressedDirectHits.Count == 1 && suppressedDirectHits[0].Name == "FP.Suppress.Me",
            "direct matcher leaves verdict suppression to its caller-facing FP check");
        await using var fpSuppressStream = new MemoryStream("hello"u8.ToArray());
        var fpStreamResult = await fpSuppressSet.MatchStreamAsync(fpSuppressStream, 2, 64, "test.db", collectAllMatches: false);
        Assert(fpStreamResult.Trusted && fpStreamResult.Detections.Count == 0 && fpStreamResult.BytesRead == 5,
            "streaming FP suppresses an early alert after completing the whole-file hash");

        var streamCompiled = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        streamCompiled.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.StreamSplit",
            SignatureType.Content,
            "test.db",
            HexPatternParser.Parse("6d616c77617265")));
        streamCompiled.Build();
        await using var splitStream = new MemoryStream(new byte[] { 0x78, 0x79, 0x6d, 0x61, 0x6c, 0x77, 0x61, 0x72, 0x65, 0x7a });
        var streamResult = await streamCompiled.MatchStreamAsync(splitStream, 4, 64, "test.db");
        Assert(streamResult.Detections.Any(x => x.Name == "Demo.StreamSplit"), "streaming matcher detects patterns across chunk boundaries");

        var allMatchSet = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        allMatchSet.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.FirstAlert", SignatureType.Content, "test.db", HexPatternParser.Parse("6d616c")));
        allMatchSet.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.SecondAlert", SignatureType.Content, "test.db", HexPatternParser.Parse("6d616c")));
        allMatchSet.Build();
        var firstOnly = allMatchSet.Match("malware"u8, "test.db", collectAllMatches: false);
        var allHits = allMatchSet.Match("malware"u8, "test.db", collectAllMatches: true);
        Assert(firstOnly.Count == 1, "compiled matcher stops after the first alert when all-match is disabled");
        Assert(allHits.Count == 2, "compiled matcher keeps all alerts when all-match is enabled");

        await using var firstOnlyStream = new MemoryStream("malware"u8.ToArray());
        var firstOnlyStreamResult = await allMatchSet.MatchStreamAsync(firstOnlyStream, 4, 64, "test.db", collectAllMatches: false);
        await using var allStream = new MemoryStream("malware"u8.ToArray());
        var allStreamResult = await allMatchSet.MatchStreamAsync(allStream, 4, 64, "test.db", collectAllMatches: true);
        Assert(firstOnlyStreamResult.Detections.Count == 1, "streaming matcher stops after the first alert when all-match is disabled");
        Assert(allStreamResult.Detections.Count == 2, "streaming matcher keeps all alerts when all-match is enabled");

        var allMatchScanRoot = Path.Combine(Path.GetTempPath(), "clamguard-allmatch-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(allMatchScanRoot);
        File.WriteAllText(Path.Combine(allMatchScanRoot, "allmatch.db"),
            "Demo.ScanFirst=6d616c\nDemo.ScanSecond=6d616c\n");
        var allMatchScanFile = Path.Combine(Path.GetTempPath(), "clamguard-allmatch-file-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(allMatchScanFile, "malware"u8.ToArray());
        var allMatchManager = new DatabaseManager();
        allMatchManager.LoadAndCompile(allMatchScanRoot, true);
        var allMatchScanner = new ClamGuard.Scanner.ScannerEngine(allMatchManager);
        var scannerFirstOnly = allMatchScanner.Scan(allMatchScanFile);
        var scannerAll = allMatchScanner.Scan(allMatchScanFile, new ScanOptions { CollectAllMatches = true });
        Assert(scannerFirstOnly.Detections.Count == 1, "scanner returns the first alert when CollectAllMatches is disabled");
        Assert(scannerAll.Detections.Count == 2, "scanner returns all alerts when CollectAllMatches is enabled");
        Directory.Delete(allMatchScanRoot, true);
        File.Delete(allMatchScanFile);

        var fpScanRoot = Path.Combine(Path.GetTempPath(), "clamguard-fp-scan-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fpScanRoot);
        var fpScanFile = Path.Combine(Path.GetTempPath(), "clamguard-fp-scan-file-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(fpScanFile, "hello"u8.ToArray());
        var fpScanHash = System.Security.Cryptography.MD5.HashData("hello"u8);
        File.WriteAllText(Path.Combine(fpScanRoot, "01-malware.db"), "Root.Malware=68656c6c6f\n");
        File.WriteAllText(Path.Combine(fpScanRoot, "02-clean.fp"), $"{Convert.ToHexString(fpScanHash).ToLowerInvariant()}:5:Root.FP\n");
        var fpScanManager = new DatabaseManager();
        fpScanManager.LoadAndCompile(fpScanRoot, true);
        var fpScanner = new ClamGuard.Scanner.ScannerEngine(fpScanManager);
        var fpScanResult = fpScanner.Scan(fpScanFile);
        Assert(fpScanResult.Verdict == ScanVerdict.Trusted && fpScanResult.Detections.Count == 0,
            "scanner converts a root FP hash match to Trusted and suppresses evidence");
        Directory.Delete(fpScanRoot, true);
        File.Delete(fpScanFile);

        var fpArchiveDb = Path.Combine(Path.GetTempPath(), "clamguard-fp-archive-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fpArchiveDb);
        var fpArchivePath = Path.Combine(Path.GetTempPath(), "clamguard-fp-child-" + Guid.NewGuid().ToString("N") + ".zip");
        var fpArchiveChild = "hello"u8.ToArray();
        var fpArchiveChildHash = System.Security.Cryptography.MD5.HashData(fpArchiveChild);
        File.WriteAllText(Path.Combine(fpArchiveDb, "01-malware.db"), "Child.Malware=68656c6c6f\n");
        File.WriteAllText(Path.Combine(fpArchiveDb, "02-child.fp"), $"{Convert.ToHexString(fpArchiveChildHash).ToLowerInvariant()}:5:Child.FP\n");
        using (var archiveFile = File.Create(fpArchivePath))
        using (var archive = new System.IO.Compression.ZipArchive(archiveFile, System.IO.Compression.ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("child.bin");
            using var entryStream = entry.Open();
            entryStream.Write(fpArchiveChild, 0, fpArchiveChild.Length);
        }
        var fpArchiveManager = new DatabaseManager();
        fpArchiveManager.LoadAndCompile(fpArchiveDb, true);
        var fpArchiveScanner = new ClamGuard.Scanner.ScannerEngine(fpArchiveManager);
        var fpArchiveResult = fpArchiveScanner.Scan(fpArchivePath);
        Assert(fpArchiveResult.Detections.Count == 0,
            "archive child FP suppresses evidence for the trusted embedded layer");
        Directory.Delete(fpArchiveDb, true);
        File.Delete(fpArchivePath);

        var streamHash = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        var streamMd5 = System.Security.Cryptography.MD5.HashData("hello"u8);
        streamHash.Add(new ClamGuard.Signatures.HashSignature("Demo.StreamHash", SignatureType.Hash, "test.hdb", HashAlgorithmKind.Md5, streamMd5, 5));
        streamHash.Build();
        await using var hashStream = new MemoryStream("hello"u8.ToArray());
        var hashResult = await streamHash.MatchStreamAsync(hashStream, 4, 64, "test.hdb");
        Assert(hashResult.Detections.Any(x => x.Name == "Demo.StreamHash"), "streaming matcher computes whole-file hashes incrementally");

        var eofCompiled = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        eofCompiled.Add(new ClamGuard.Signatures.NdbSignature(
            "Demo.StreamEof", "test.ndb", 0, "EOF-1", HexPatternParser.Parse("7a")));
        eofCompiled.Build();
        await using var eofStream = new MemoryStream(new byte[] { 0x61, 0x62, 0x63, 0x7a });
        var eofResult = await eofCompiled.MatchStreamAsync(eofStream, 4, 64, "test.ndb");
        Assert(eofResult.Detections.Any(x => x.Name == "Demo.StreamEof"), "streaming matcher honors EOF-relative offsets");

        var hashIndex = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        var helloMd5 = System.Security.Cryptography.MD5.HashData("hello"u8);
        hashIndex.Add(new ClamGuard.Signatures.HashSignature("Exact.Hello", SignatureType.Hash, "test.hdb", HashAlgorithmKind.Md5, helloMd5, 5));
        hashIndex.Add(new ClamGuard.Signatures.HashSignature("Wildcard.Hello", SignatureType.Hash, "test.hdb", HashAlgorithmKind.Md5, helloMd5, null));
        hashIndex.Add(new ClamGuard.Signatures.HashSignature("WrongSize.Hello", SignatureType.Hash, "test.hdb", HashAlgorithmKind.Md5, helloMd5, 6));
        hashIndex.Build();
        var hashHits = hashIndex.Match("hello"u8, "test.hdb");
        Assert(hashHits.Any(x => x.Name == "Exact.Hello"), "hash index matches exact file-size hash");
        Assert(hashHits.Any(x => x.Name == "Wildcard.Hello"), "hash index matches wildcard-size hash");
        Assert(!hashHits.Any(x => x.Name == "WrongSize.Hello"), "hash index rejects non-matching file size");

        var bmCompiled = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        bmCompiled.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.BM",
            SignatureType.Content,
            "test.db",
            HexPatternParser.Parse("636f6e73697374656e6379")));
        bmCompiled.Build();
        var bmHits = bmCompiled.Match("--consistency--"u8, "test.db");
        Assert(bmHits.Any(x => x.Name == "Demo.BM"), "single long fixed signature uses the BM fast path");

        var incrementalFixed = new ClamGuard.Signatures.Matching.CompiledSignatureSet();
        incrementalFixed.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.First", SignatureType.Content, "test.db", HexPatternParser.Parse("6669727374")));
        incrementalFixed.Build();
        incrementalFixed.Add(new ClamGuard.Signatures.ContentSignature(
            "Demo.Second", SignatureType.Content, "test.db", HexPatternParser.Parse("7365636f6e64")));
        incrementalFixed.Build();
        var incrementalHits = incrementalFixed.Match("first-and-second"u8, "test.db");
        Assert(incrementalHits.Any(x => x.Name == "Demo.Second"), "fixed matcher rebuilds safely when signatures are added after Build");

        var flexibleAlternate = HexPatternParser.Parse("(4142|43)");
        Assert(flexibleAlternate.Matches("xxAB"u8, 2, out var altConsumed) && altConsumed == 2, "generic variable-length alternate matches first branch");
        Assert(flexibleAlternate.Matches("xxC"u8, 2, out altConsumed) && altConsumed == 1, "generic variable-length alternate matches short branch");

        var negatedAlternate = HexPatternParser.Parse("!(4142|4344)");
        Assert(!negatedAlternate.Matches("AB"u8, 0, out _), "negated fixed alternate rejects members");
        Assert(negatedAlternate.Matches("ZZ"u8, 0, out var negConsumed) && negConsumed == 2, "negated fixed alternate accepts non-members");

        var rejectedGenericWildcard = false;
        try { _ = HexPatternParser.Parse("(61*62|63)"); }
        catch (FormatException) { rejectedGenericWildcard = true; }
        Assert(rejectedGenericWildcard, "generic alternates reject unbounded wildcards");

        var rejectedGenericWideRange = false;
        try { _ = HexPatternParser.Parse("(61{128}62|63)"); }
        catch (FormatException) { rejectedGenericWideRange = true; }
        Assert(rejectedGenericWideRange, "generic alternates reject ranged wildcards >= 128 bytes");

        var classes = HexPatternParser.Parse("(B)6869(W)(L)");
        Assert(classes.Matches(" hi!\r\n"u8, 1, out _), "body character classes B/W/L are supported");

        var ldbModifierPath = Path.Combine(Path.GetTempPath(), "clamguard-modifier.ldb");
        File.WriteAllText(ldbModifierPath,
            "Modifier.Case;Engine:81-255,Target:0;0;414243::i\n" +
            "Modifier.Wide;Engine:81-255,Target:0;0;414243::w\n" +
            "Modifier.FullWord;Engine:81-255,Target:0;0;414243::f\n" +
            "Modifier.Both;Engine:81-255,Target:0;0;414243::wa\n");
        var modifierSignatures = SignatureParser.ParseLdbFile(ldbModifierPath).ToArray();
        Assert(modifierSignatures.Length == 4, "LDB parser preserves all supported subsignature modifiers");
        Assert(modifierSignatures[0].SubSignatures[0].MatchOptions.HasFlag(ContentMatchOptions.IgnoreCase), "LDB nocase modifier parsed");
        Assert(modifierSignatures[1].SubSignatures[0].MatchOptions.HasFlag(ContentMatchOptions.Wide), "LDB wide modifier parsed");
        Assert(modifierSignatures[2].SubSignatures[0].MatchOptions.HasFlag(ContentMatchOptions.FullWord), "LDB fullword modifier parsed");
        Assert(modifierSignatures[3].SubSignatures[0].MatchOptions.HasFlag(ContentMatchOptions.Wide) &&
               modifierSignatures[3].SubSignatures[0].MatchOptions.HasFlag(ContentMatchOptions.Ascii), "LDB wide+ASCII modifiers parsed together");

        var ldbContextPath = Path.Combine(Path.GetTempPath(), "clamguard-context.ldb");
        File.WriteAllText(ldbContextPath,
            "Context.Engine;Engine:51-255,Target:1,FileSize:1-999999,EntryPoint:0-999999,NumberOfSections:1-32,Container:ZIP,Intermediates:ZIP>7Z,HandlerType:PE,IconGroup1:GROUP-A,IconGroup2:*;0;4d5a\n");
        var contextSig = SignatureParser.ParseLdbFile(ldbContextPath).Single();
        Assert(contextSig.Target is { Target: 1, Container: "ZIP", HandlerType: "PE" }, "LDB contextual target fields parse");
        Assert(contextSig.Target!.Intermediates is { Count: 2 }, "LDB intermediates parse");

        File.Delete(ldbModifierPath);
        File.Delete(ldbContextPath);
    }
}
