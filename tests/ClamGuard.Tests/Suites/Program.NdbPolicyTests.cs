internal static partial class Program
{
    private static void NdbAndPolicyTests()
    {
        // NDB: target-aware direct evaluation, absolute/range/EOF offsets, and FLEVEL filtering.
        var ndbPath = Path.Combine(Path.GetTempPath(), "clamguard-extended.ndb");
        File.WriteAllText(ndbPath,
            "Ndb.Absolute:0:2:4142\n" +
            "Ndb.Range:0:1,3:4142\n" +
            "Ndb.WrongTarget:1:2:4142\n" +
            "Ndb.EntryPoint:1:EP+0:41424344\n" +
            "Ndb.Eof:0:EOF-2:4142\n" +
            "Ndb.Future:0:0:4142:240\n");
        var ndbParsed = SignatureParser.ParseNdbFile(ndbPath).ToArray();
        Assert(ndbParsed.Length == 5 && ndbParsed.All(x => x.Target is 0 or 1), "NDB parser accepts target, range, EOF and FLEVEL fields");
        Assert(!SignatureParser.ParseNdbFile(ndbPath, 234).Any(x => x.Name == "Ndb.Future"), "NDB minimum FLEVEL filters signatures above the engine level");
        var invalidNdbOffsetPath = Path.Combine(Path.GetTempPath(), "clamguard-invalid-offset.ndb");
        File.WriteAllText(invalidNdbOffsetPath, "Ndb.BadOffset:0:BOGUS:4142\n");
        var invalidNdbOffsetRejected = false;
        try { _ = SignatureParser.ParseNdbFile(invalidNdbOffsetPath).ToArray(); }
        catch (FormatException) { invalidNdbOffsetRejected = true; }
        Assert(invalidNdbOffsetRejected, "NDB parser rejects unsupported offset expressions");

        var bareEofNdbPath = Path.Combine(Path.GetTempPath(), "clamguard-bare-eof.ndb");
        File.WriteAllText(bareEofNdbPath, "Ndb.BareEof:0:EOF:4142\n");
        var bareEofNdbRejected = false;
        try { _ = SignatureParser.ParseNdbFile(bareEofNdbPath).ToArray(); }
        catch (FormatException) { bareEofNdbRejected = true; }
        Assert(bareEofNdbRejected, "NDB parser rejects bare EOF offsets like ClamAV cli_caloff");

        var bareEofLdbPath = Path.Combine(Path.GetTempPath(), "clamguard-bare-eof.ldb");
        File.WriteAllText(bareEofLdbPath, "Ldb.BareEof;Engine:81-255;EOF:4142\n");
        var bareEofLdbRejected = false;
        try { _ = SignatureParser.ParseLdbFile(bareEofLdbPath).ToArray(); }
        catch (FormatException) { bareEofLdbRejected = true; }
        Assert(bareEofLdbRejected, "LDB parser rejects bare EOF offsets like ClamAV cli_caloff");

        var bareEofRegexLdbPath = Path.Combine(Path.GetTempPath(), "clamguard-bare-eof-regex.ldb");
        File.WriteAllText(bareEofRegexLdbPath, "Ldb.BareEofRegex;Engine:81-255;EOF:AB/4142/g\n");
        var bareEofRegexLdbRejected = false;
        try { _ = SignatureParser.ParseLdbFile(bareEofRegexLdbPath).ToArray(); }
        catch (FormatException) { bareEofRegexLdbRejected = true; }
        Assert(bareEofRegexLdbRejected, "LDB PCRE parser rejects bare EOF offsets like ClamAV cli_caloff");

        var eofZeroNdbPath = Path.Combine(Path.GetTempPath(), "clamguard-eof-zero.ndb");
        File.WriteAllText(eofZeroNdbPath, "Ndb.EofZero:0:EOF-0:4142\n");
        var eofZeroParsed = SignatureParser.ParseNdbFile(eofZeroNdbPath).Single();
        Assert(eofZeroParsed.OffsetExpression.Equals("EOF-0", StringComparison.Ordinal), "NDB parser preserves valid EOF-0 offset");

        var extendedTargetPath = Path.Combine(Path.GetTempPath(), "clamguard-extended-targets.ldb");
        File.WriteAllText(extendedTargetPath,
            "Ldb.Internal;Engine:81-255,Target:13;0;4142\n" +
            "Ldb.Other;Engine:81-255,Target:14;0;4142\n");
        var extendedTargets = SignatureParser.ParseLdbFile(extendedTargetPath).ToArray();
        Assert(extendedTargets.Length == 2 && extendedTargets.All(x => x.Target?.Target is 13 or 14),
            "LDB parser accepts ClamAV 1.5.4 targets 13 (INTERNAL) and 14 (OTHER)");

        var extendedNdbTargetPath = Path.Combine(Path.GetTempPath(), "clamguard-extended-targets.ndb");
        File.WriteAllText(extendedNdbTargetPath,
            "Ndb.Internal:13:0:4142\n" +
            "Ndb.Other:14:0:4142\n");
        var extendedNdbTargets = SignatureParser.ParseNdbFile(extendedNdbTargetPath).ToArray();
        Assert(extendedNdbTargets.Length == 2 && extendedNdbTargets.All(x => x.Target is 13 or 14),
            "NDB parser accepts ClamAV 1.5.4 targets 13 (INTERNAL) and 14 (OTHER)");
        var wildcardTargetNdbPath = Path.Combine(Path.GetTempPath(), "clamguard-target-wildcard.ndb");
        File.WriteAllText(wildcardTargetNdbPath, "Ndb.TargetWildcard:*:0:4142\n");
        var wildcardTarget = SignatureParser.ParseNdbFile(wildcardTargetNdbPath).Single();
        Assert(wildcardTarget.Target == 0, "NDB Target:* maps to target 0 like ClamAV atoi(\"*\")");

        var ndbIndentedCommentPath = Path.Combine(Path.GetTempPath(), "clamguard-indented-comment.ndb");
        File.WriteAllText(ndbIndentedCommentPath, " #not-a-comment\n");
        var ndbIndentedCommentRejected = false;
        try { _ = SignatureParser.ParseNdbFile(ndbIndentedCommentPath).ToArray(); }
        catch (FormatException) { ndbIndentedCommentRejected = true; }
        Assert(ndbIndentedCommentRejected, "NDB only treats # at column 0 as a comment");

        var ndbBlankPath = Path.Combine(Path.GetTempPath(), "clamguard-blank.ndb");
        File.WriteAllText(ndbBlankPath, "\n");
        var ndbBlankRejected = false;
        try { _ = SignatureParser.ParseNdbFile(ndbBlankPath).ToArray(); }
        catch (FormatException) { ndbBlankRejected = true; }
        Assert(ndbBlankRejected, "NDB blank lines are malformed rather than silently skipped");

        var ldbIndentedCommentPath = Path.Combine(Path.GetTempPath(), "clamguard-indented-comment.ldb");
        File.WriteAllText(ldbIndentedCommentPath, " #not-a-comment\n");
        var ldbIndentedCommentRejected = false;
        try { _ = SignatureParser.ParseLdbFile(ldbIndentedCommentPath).ToArray(); }
        catch (FormatException) { ldbIndentedCommentRejected = true; }
        Assert(ldbIndentedCommentRejected, "LDB only treats # at column 0 as a comment");

        var ldbBlankPath = Path.Combine(Path.GetTempPath(), "clamguard-blank.ldb");
        File.WriteAllText(ldbBlankPath, "\n");
        var ldbBlankRejected = false;
        try { _ = SignatureParser.ParseLdbFile(ldbBlankPath).ToArray(); }
        catch (FormatException) { ldbBlankRejected = true; }
        Assert(ldbBlankRejected, "LDB blank lines are malformed rather than silently skipped");

        var ldbWhitespacePath = Path.Combine(Path.GetTempPath(), "clamguard-whitespace.ldb");
        File.WriteAllText(ldbWhitespacePath, "Ldb.Whitespace;Engine:81-255, Target:0;0;4142\n");
        var ldbWhitespaceSkipped = SignatureParser.ParseLdbFile(ldbWhitespacePath).ToArray();
        Assert(ldbWhitespaceSkipped.Length == 0, "LDB target attributes are not whitespace-trimmed like the ClamAV tokenizer");

        var ndbDbDir = Path.Combine(Path.GetTempPath(), "clamguard-extended-ndb-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ndbDbDir);
        File.Copy(ndbPath, Path.Combine(ndbDbDir, "extended.ndb"));
        var ndbManager = new DatabaseManager();
        ndbManager.LoadAndCompile(ndbDbDir, true);
        var ndbScanner = new ClamGuard.Scanner.ScannerEngine(ndbManager);
        var ndbAbsoluteFile = Path.Combine(Path.GetTempPath(), "ndb-absolute.bin");
        File.WriteAllBytes(ndbAbsoluteFile, "xxAByy"u8.ToArray());
        var ndbAbsoluteResult = ndbScanner.Scan(ndbAbsoluteFile, new ScanOptions { CollectAllMatches = true });
        Assert(ndbAbsoluteResult.Detections.Any(x => x.Name == "Ndb.Absolute"), "NDB absolute offset is evaluated against the full buffer");
        Assert(ndbAbsoluteResult.Detections.Any(x => x.Name == "Ndb.Range"), "NDB floating range offset is evaluated");
        Assert(ndbAbsoluteResult.Detections.Any(x => x.Name == "Ndb.WrongTarget") == false, "NDB target type prevents a non-PE match");
        var otherNdbPath = Path.Combine(Path.GetTempPath(), "clamguard-other.ndb");
        File.WriteAllText(otherNdbPath, "Ndb.Other:14:0:4142\n");
        var otherDbDir = Path.Combine(Path.GetTempPath(), "clamguard-other-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(otherDbDir);
        File.Copy(otherNdbPath, Path.Combine(otherDbDir, "other.ndb"));
        // ClamAV 1.5.4 loads .ign/.ign2 before normal signatures and suppresses matching
        // signatures at database-load time. Two-field rules additionally require an MD5
        // match of the original database entry line.
        var ignDbDir = Path.Combine(Path.GetTempPath(), "clamguard-ign-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ignDbDir);
        var ignSignaturePath = Path.Combine(ignDbDir, "00-signatures.db");
        var conditionalLine = "Ignore.Conditional=4142";
        File.WriteAllText(ignSignaturePath,
            "Ignore.Direct=4142\n" +
            conditionalLine + "\n" +
            "Ignore.ConditionalMismatch=4142\n" +
            "Keep.Signature=4142\n" +
            "Legacy.Ignore=4142\n" +
            "Unofficial.Signature=4142\n" +
            "Ignore.Two=4142\n");
        var conditionalMd5 = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(Encoding.UTF8.GetBytes(conditionalLine)));
        File.WriteAllText(Path.Combine(ignDbDir, "01-ignore.ign"),
            "Ignore.Direct\n" +
            $"Ignore.Conditional:{conditionalMd5}\n" +
            "Ignore.ConditionalMismatch:00000000000000000000000000000000\n" +
            "ignored:legacy:Legacy.Ignore\n" +
            "Unofficial.Signature\n");
        File.WriteAllText(Path.Combine(ignDbDir, "02-ignore.ign2"), "Ignore.Two\n");
        var ignLoaded = new DatabaseLoader().LoadDirectory(ignDbDir, failOnInvalidFile: true, verifyContainers: false);
        Assert(ignLoaded.SignatureCount == 2 &&
               ignLoaded.Database.Signatures.Select(x => x.Name).OrderBy(x => x, StringComparer.Ordinal).SequenceEqual(new[] { "Ignore.ConditionalMismatch", "Keep.Signature" }),
            ".ign/.ign2 suppress direct, conditional-MD5, legacy and normalized signature rules while preserving non-matching rules");
        Assert(ignLoaded.Database.Signatures.All(static signature => signature.SourceEntry is null),
            "original signature lines are released after .ign/.ign2 filtering to reduce retained database memory");
        var ignManager = new DatabaseManager();
        ignManager.LoadAndCompile(ignDbDir, true);
        var ignScanner = new ClamGuard.Scanner.ScannerEngine(ignManager);
        var ignFile = Path.Combine(Path.GetTempPath(), "clamguard-ign-scan.bin");
        File.WriteAllBytes(ignFile, "xxAByy"u8.ToArray());
        var ignResult = ignScanner.Scan(ignFile, new ScanOptions { CollectAllMatches = true });
        Assert(!ignResult.Detections.Any(x => x.Name is "Ignore.Direct" or "Ignore.Conditional" or "Legacy.Ignore" or "Unofficial.Signature" or "Ignore.Two"),
            ".ign/.ign2 suppression is applied before scanner verdicts");
        Assert(ignResult.Detections.Any(x => x.Name == "Ignore.ConditionalMismatch") &&
               ignResult.Detections.Any(x => x.Name == "Keep.Signature"),
            "conditional .ign rule does not suppress a signature with a different database-entry MD5");
        Directory.Delete(ignDbDir, true);
        File.Delete(ignFile);

        // ClamAV 1.5.4 only loads PUA databases when PUA scanning is explicitly enabled.
        var puaDbDir = Path.Combine(Path.GetTempPath(), "clamguard-pua-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(puaDbDir);
        var puaFile = Path.Combine(puaDbDir, "pua.hdu");
        File.WriteAllText(puaFile, "cb81e7c4bf5847a951a1702052001022:15:PUA.Hash\n");
        var puaDefault = new DatabaseLoader { IncludePua = false }.LoadDirectory(puaDbDir, failOnInvalidFile: true, verifyContainers: false);
        Assert(puaDefault.SignatureCount == 0 && puaDefault.Files.Count == 0, "PUA hash database is skipped by default");
        var puaIncluded = new DatabaseLoader { IncludePua = true }.LoadDirectory(puaDbDir, failOnInvalidFile: true, verifyContainers: false);
        Assert(puaIncluded.SignatureCount == 1 && puaIncluded.Files.Any(x => x.Name == "pua.hdu"), "PUA hash database loads when explicitly enabled");

        File.WriteAllText(puaFile,
            "cb81e7c4bf5847a951a1702052001022:15:PUA.Win.Tool\n" +
            "cb81e7c4bf5847a951a1702052001022:15:PUA.Spy.Tool\n" +
            "cb81e7c4bf5847a951a1702052001022:15:PUA.Win.Packer\n");
        var puaIncludeCategory = new DatabaseLoader { IncludePuaCategories = new[] { "Win" } }
            .LoadDirectory(puaDbDir, failOnInvalidFile: true, verifyContainers: false);
        Assert(puaIncludeCategory.Database.Signatures.Select(x => x.Name).OrderBy(x => x).SequenceEqual(new[] { "PUA.Win.Packer", "PUA.Win.Tool" }),
            "IncludePuaCategories loads only matching top-level PUA category");
        var puaExcludeCategory = new DatabaseLoader { ExcludePuaCategories = new[] { "Win" } }
            .LoadDirectory(puaDbDir, failOnInvalidFile: true, verifyContainers: false);
        Assert(puaExcludeCategory.Database.Signatures.Select(x => x.Name).SequenceEqual(new[] { "PUA.Spy.Tool" }),
            "ExcludePuaCategories loads PUA categories other than the excluded category");
        var puaConflictThrown = false;
        try
        {
            _ = new DatabaseLoader { IncludePuaCategories = new[] { "Win" }, ExcludePuaCategories = new[] { "Spy" } }
                .LoadDirectory(puaDbDir, failOnInvalidFile: true, verifyContainers: false);
        }
        catch (ArgumentException)
        {
            puaConflictThrown = true;
        }
        Assert(puaConflictThrown, "PUA include and exclude categories are mutually exclusive");
        foreach (var extension in new[] { ".hsu", ".mdu", ".msu", ".ndu", ".ldu" })
        {
            var puaSkipPath = Path.Combine(puaDbDir, "skip" + extension);
            File.WriteAllText(puaSkipPath, "this is intentionally invalid when PUA is enabled");
            var skipped = new DatabaseLoader { IncludePua = false }.LoadDirectory(puaDbDir, failOnInvalidFile: true, verifyContainers: false);
            Assert(skipped.Errors.Count == 0, $"PUA database {extension} is not parsed when PUA is disabled");
            File.Delete(puaSkipPath);
        }
        Directory.Delete(puaDbDir, true);

        var otherManager = new DatabaseManager();
        otherManager.LoadAndCompile(otherDbDir, true);
        var otherScanner = new ClamGuard.Scanner.ScannerEngine(otherManager);
        var unknownOtherFile = Path.Combine(Path.GetTempPath(), "clamguard-other.bin");
        File.WriteAllBytes(unknownOtherFile, new byte[] { 0x41, 0x42, 0x02, 0x03, 0xAA, 0xBB });
        var otherResult = otherScanner.Scan(unknownOtherFile);
        Assert(otherResult.Detections.Any(x => x.Name == "Ndb.Other"), "NDB target 14 scans fallback OTHER content");
        var ndbFloatingAbsolutePath = Path.Combine(Path.GetTempPath(), "ndb-floating-absolute.bin");
        File.WriteAllBytes(ndbFloatingAbsolutePath, "xxAByy"u8.ToArray());
        var floatingAbsoluteDbPath = Path.Combine(Path.GetTempPath(), "clamguard-floating-absolute.ndb");
        File.WriteAllText(floatingAbsoluteDbPath, "Ndb.FloatingAbsolute:0:1,1:4142\n");
        var floatingManagerDir = Path.Combine(Path.GetTempPath(), "clamguard-floating-absolute-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(floatingManagerDir);
        File.Copy(floatingAbsoluteDbPath, Path.Combine(floatingManagerDir, "floating.ndb"));
        var floatingManager = new DatabaseManager();
        floatingManager.LoadAndCompile(floatingManagerDir, true);
        var floatingScanner = new ClamGuard.Scanner.ScannerEngine(floatingManager);
        Assert(!floatingScanner.Scan(ndbFloatingAbsolutePath).Detections.Any(x => x.Name == "Ndb.FloatingAbsolute"), "NDB floating offset does not match outside its absolute window");
        File.WriteAllText(floatingAbsoluteDbPath, "Ndb.FloatingAbsolute:0:1,2:4142\n");
        var floatingManager2Dir = Path.Combine(Path.GetTempPath(), "clamguard-floating-absolute-db2-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(floatingManager2Dir);
        File.Copy(floatingAbsoluteDbPath, Path.Combine(floatingManager2Dir, "floating.ndb"));
        var floatingManager2 = new DatabaseManager();
        floatingManager2.LoadAndCompile(floatingManager2Dir, true);
        var floatingScanner2 = new ClamGuard.Scanner.ScannerEngine(floatingManager2);
        Assert(floatingScanner2.Scan(ndbFloatingAbsolutePath).Detections.Any(x => x.Name == "Ndb.FloatingAbsolute"), "NDB floating offset supports absolute base plus max shift");
        var ndbEofFile = Path.Combine(Path.GetTempPath(), "ndb-eof.bin");
        File.WriteAllBytes(ndbEofFile, "xxxxAB"u8.ToArray());
        var ndbEofResult = ndbScanner.Scan(ndbEofFile);
        Assert(ndbEofResult.Detections.Any(x => x.Name == "Ndb.Eof"), "NDB EOF-relative offset is evaluated");
        var ndbPeFile = Path.Combine(Path.GetTempPath(), "ndb-pe.exe");
        File.WriteAllBytes(ndbPeFile, BuildMinimalPe());
        var ndbPeResult = ndbScanner.Scan(ndbPeFile, new ScanOptions { CollectAllMatches = true });
        Assert(ndbPeResult.Detections.Any(x => x.Name == "Ndb.EntryPoint"), "NDB PE entry-point relative offset is evaluated");

        var ndbNormalizedPath = Path.Combine(Path.GetTempPath(), "clamguard-normalized.ndb");
        File.WriteAllText(ndbNormalizedPath,
            "Ndb.HtmlNormalized:3:*:68656c6c6f\n" +
            "Ndb.AsciiNormalized:7:*:68656c6c6f\n");
        var normalizedDbDir = Path.Combine(Path.GetTempPath(), "clamguard-normalized-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(normalizedDbDir);
        File.Copy(ndbNormalizedPath, Path.Combine(normalizedDbDir, "normalized.ndb"));
        var normalizedManager = new DatabaseManager();
        normalizedManager.LoadAndCompile(normalizedDbDir, true);
        var normalizedScanner = new ClamGuard.Scanner.ScannerEngine(normalizedManager);
        var normalizedSamples = CreateNormalizedTextSamples();
        var htmlResult = normalizedScanner.Scan(normalizedSamples.HtmlPath);
        Assert(htmlResult.Detections.Any(x => x.Name == "Ndb.HtmlNormalized"), "NDB HTML target matches normalized HTML content");
        var asciiResult = normalizedScanner.Scan(normalizedSamples.AsciiPath);
        Assert(asciiResult.Detections.Any(x => x.Name == "Ndb.AsciiNormalized"), "NDB ASCII target matches normalized text content");
        File.Delete(normalizedSamples.HtmlPath);
        File.Delete(normalizedSamples.AsciiPath);

        File.Delete(wildcardTargetNdbPath);
        File.Delete(ndbIndentedCommentPath);
        File.Delete(ndbBlankPath);
        File.Delete(ldbIndentedCommentPath);
        File.Delete(ldbBlankPath);
        File.Delete(ldbWhitespacePath);
        File.Delete(ndbPath);
        File.Delete(ndbAbsoluteFile);
        Directory.Delete(ndbDbDir, true);
        File.Delete(ndbEofFile);
        File.Delete(ndbPeFile);
        File.Delete(invalidNdbOffsetPath);
        File.Delete(bareEofNdbPath);
        File.Delete(bareEofLdbPath);
        File.Delete(bareEofRegexLdbPath);
        File.Delete(eofZeroNdbPath);
        File.Delete(extendedTargetPath);
        File.Delete(extendedNdbTargetPath);
        Directory.Delete(otherDbDir, true);
        File.Delete(otherNdbPath);
        File.Delete(unknownOtherFile);
        File.Delete(ndbFloatingAbsolutePath);
        File.Delete(floatingAbsoluteDbPath);
        Directory.Delete(floatingManagerDir, true);
        Directory.Delete(floatingManager2Dir, true);
        File.Delete(ndbNormalizedPath);
        Directory.Delete(normalizedDbDir, true);
    }
}
