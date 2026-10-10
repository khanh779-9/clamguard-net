internal static partial class Program
{
    private static async Task SelfProtectionAndMetadataTestsAsync()
    {
        // SDB uses the NDB grammar but is evaluated on the raw layer before container/type parsing.
        var sdbDir = Path.Combine(Path.GetTempPath(), "clamguard-sdb-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sdbDir);
        var sdbPath = Path.Combine(sdbDir, "selfprotect.sdb");
        File.WriteAllText(sdbPath, "SelfProtect.Test:0:*:534442484954\n");
        var sdbLoaded = new DatabaseLoader().LoadDirectory(sdbDir, failOnInvalidFile: true, verifyContainers: false);
        Assert(sdbLoaded.SignatureCount == 1 && sdbLoaded.Database.HasSelfProtectionSignatures, ".sdb loads through the NDB grammar and activates self-protection");
        var sdbManager = new DatabaseManager();
        sdbManager.LoadAndCompile(sdbDir, true);
        var sdbScanner = new ClamGuard.Scanner.ScannerEngine(sdbManager);
        var sdbFile = Path.Combine(sdbDir, "sample.bin");
        await File.WriteAllBytesAsync(sdbFile, "SDBHIT"u8.ToArray());
        var sdbResult = sdbScanner.Scan(sdbFile);
        Assert(sdbResult.Verdict == ScanVerdict.Malicious && sdbResult.Detections.Any(x => x.Name == "SelfProtect.Test"), ".sdb raw pre-parser path detects a matching layer");
        Directory.Delete(sdbDir, true);

        // ZMD/RMD metadata matcher parity with ClamAV 1.5.4 cli_loadmd()/cli_matchmeta().
        var mdDir = Path.Combine(Path.GetTempPath(), "clamguard-md-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(mdDir);
        var zipForMetadata = Path.Combine(mdDir, "sample.zip");
        await using (var zipFile = File.Create(zipForMetadata))
        {
            using var archive = new System.IO.Compression.ZipArchive(zipFile, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true);
            var entry = archive.CreateEntry("hello.txt", System.IO.Compression.CompressionLevel.NoCompression);
            await using var entryWriter = entry.Open();
            await entryWriter.WriteAsync("HELLO"u8.ToArray());
        }

        var zmdPath = Path.Combine(mdDir, "local.zmd");
        // Stored 5-byte member: original/compressed sizes are both 5; file position is 1.
        File.WriteAllText(zmdPath, "Metadata.Zip:0:hello\\.txt:5:5:*:*:1:*\n");
        var zmdLoaded = new DatabaseLoader().LoadDirectory(mdDir, failOnInvalidFile: true, verifyContainers: false);
        var zmdSignature = zmdLoaded.Database.Signatures.OfType<MetadataSignature>().Single();
        Assert(zmdSignature.ContainerType == "ZIP" && zmdSignature.OriginalSize?.Min == 5 && zmdSignature.OriginalSize?.Max == 5 && zmdSignature.CompressedSize?.Min == 5 && zmdSignature.CompressedSize?.Max == 5 && zmdSignature.FilePosition?.Min == 1 && zmdSignature.FilePosition?.Max == 1,
            "ZMD parses ClamAV 9-field metadata format");

        Assert(zmdSignature.FileNameRegex is not null && zmdSignature.FileNameRegex.IsMatch("hello.txt") && !zmdSignature.FileNameRegex.IsMatch("world.txt"),
            "ZMD filename regex uses POSIX ERE search semantics");

        var zipForFilePosition = Path.Combine(mdDir, "positions.zip");
        await using (var zipPositionFile = File.Create(zipForFilePosition))
        {
            using var archive = new System.IO.Compression.ZipArchive(zipPositionFile, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true);
            var first = archive.CreateEntry("first.txt", System.IO.Compression.CompressionLevel.NoCompression);
            await using (var writer = first.Open()) await writer.WriteAsync("ONE"u8.ToArray());
            var second = archive.CreateEntry("second.txt", System.IO.Compression.CompressionLevel.NoCompression);
            await using (var writer = second.Open()) await writer.WriteAsync("TWO"u8.ToArray());
        }

        var zmdFilePositionPath = Path.Combine(mdDir, "file-position.zmd");
        File.WriteAllText(zmdFilePositionPath, "Metadata.Zip.FilePosition2:0:second\\.txt:3:3:*:*:2:*\n");
        var zmdFilePositionManager = new DatabaseManager();
        zmdFilePositionManager.LoadAndCompile(mdDir, true);
        var zmdFilePositionScanner = new ClamGuard.Scanner.ScannerEngine(zmdFilePositionManager);
        var zmdFilePositionResult = zmdFilePositionScanner.Scan(zipForFilePosition, new ScanOptions { CollectAllMatches = true });
        Assert(zmdFilePositionResult.Detections.Any(x => x.Name == "Metadata.Zip.FilePosition2"),
            "ZMD FilePosition is the 1-based archive entry number");

        var zmdFilePositionZeroPath = Path.Combine(mdDir, "file-position-zero.zmd");
        File.WriteAllText(zmdFilePositionZeroPath, "Metadata.Zip.FilePosition0:0:*:*:*:*:*:0:*\n");
        var zmdFilePositionZeroManager = new DatabaseManager();
        zmdFilePositionZeroManager.LoadAndCompile(mdDir, true);
        var zmdFilePositionZeroScanner = new ClamGuard.Scanner.ScannerEngine(zmdFilePositionZeroManager);
        var zmdFilePositionZeroResult = zmdFilePositionZeroScanner.Scan(zipForFilePosition, new ScanOptions { CollectAllMatches = true });
        Assert(!zmdFilePositionZeroResult.Detections.Any(x => x.Name == "Metadata.Zip.FilePosition0"),
            "ZMD FilePosition 0 is not a wildcard and does not match normal 1-based archive entries");

        var zmdPosixClassPath = Path.Combine(mdDir, "posix-class.zmd");
        File.WriteAllText(zmdPosixClassPath, "Metadata.Zip.PosixClass:0:[[:digit:]]+:5:5:*:*:1:*\n");
        var zmdPosixClassSignature = SignatureParser.ParseFile(zmdPosixClassPath).OfType<MetadataSignature>().Single();
        Assert(zmdPosixClassSignature.FileNameRegex is not null && zmdPosixClassSignature.FileNameRegex.IsMatch("123") && !zmdPosixClassSignature.FileNameRegex.IsMatch("abc"),
            "ZMD filename regex supports POSIX character classes");

        var zmdNetEscapePath = Path.Combine(mdDir, "dotnet-escape.zmd");
        File.WriteAllText(zmdNetEscapePath, "Metadata.Zip.DotNetEscape:0:\\d+:5:5:*:*:1:*\n");
        var zmdNetEscapeSignature = SignatureParser.ParseFile(zmdNetEscapePath).OfType<MetadataSignature>().Single();
        Assert(zmdNetEscapeSignature.FileNameRegex is not null && zmdNetEscapeSignature.FileNameRegex.IsMatch("dd") && !zmdNetEscapeSignature.FileNameRegex.IsMatch("12"),
            "ZMD filename regex does not reinterpret POSIX '\\d' as a .NET digit class");

        var zmdLookaroundPath = Path.Combine(mdDir, "lookaround-rejected.zmd");
        File.WriteAllText(zmdLookaroundPath, "Metadata.Zip.LookaroundRejected:0:(?=hello)hello:5:5:*:*:1:*\n");
        var lookaroundRejected = false;
        try { _ = SignatureParser.ParseFile(zmdLookaroundPath).ToList(); }
        catch (FormatException) { lookaroundRejected = true; }
        File.Delete(zmdLookaroundPath);
        Assert(lookaroundRejected, "ZMD rejects .NET lookaround syntax unsupported by POSIX ERE");

        var zmdMethodPath = Path.Combine(mdDir, "method.zmd");
        File.WriteAllText(zmdMethodPath, "Metadata.Zip.Method:0:hello\\.txt:5:5:*:8:1:*\n");
        var zmdMethodManager = new DatabaseManager();
        zmdMethodManager.LoadAndCompile(mdDir, true);
        var zmdMethodScanner = new ClamGuard.Scanner.ScannerEngine(zmdMethodManager);
        var zmdMethodResult = zmdMethodScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
        Assert(zmdMethodResult.Detections.Any(x => x.Name == "Metadata.Zip.Method"), "ZMD CompressionMethod is accepted but ignored like ClamAV cli_matchmeta");

                    var zmdEncryptedPath = Path.Combine(mdDir, "encrypted-value.zmd");
                    File.WriteAllText(zmdEncryptedPath, "Metadata.Zip.EncryptedValue:3:hello\\.txt:5:5:*:0:1:*");
                    var zmdEncryptedManager = new DatabaseManager();
                    zmdEncryptedManager.LoadAndCompile(mdDir, true);
                    var zmdEncryptedScanner = new ClamGuard.Scanner.ScannerEngine(zmdEncryptedManager);
                    var zmdEncryptedResult = zmdEncryptedScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
                    Assert(!zmdEncryptedResult.Detections.Any(x => x.Name == "Metadata.Zip.EncryptedValue"), "ZMD numeric encrypted value other than 2 is preserved and does not match boolean archive encryption state");

                    var zmdSignedNumericPath = Path.Combine(mdDir, "signed-numeric.zmd");
                    File.WriteAllText(zmdSignedNumericPath, "Metadata.Zip.SignedNumeric:+1:hello\\.txt:5:5:*:0:1:*");
                    var signedNumericRejected = false;
                    try { _ = zmdEncryptedManager.LoadAndCompile(mdDir, true); }
                    catch (InvalidDataException) { signedNumericRejected = true; }
                    File.Delete(zmdSignedNumericPath);
                    Assert(signedNumericRejected, "ZMD numeric fields reject signs because ClamAV cli_isnumber accepts digits only");

                    var zmdOverflowPath = Path.Combine(mdDir, "overflow-numeric.zmd");
                    File.WriteAllText(zmdOverflowPath, "Metadata.Zip.OverflowNumeric:0:hello\\.txt:4294967295:5:*:0:1:*");
                    var overflowRejected = false;
                    try { _ = zmdEncryptedManager.LoadAndCompile(mdDir, true); }
                    catch (InvalidDataException) { overflowRejected = true; }
                    File.Delete(zmdOverflowPath);
                    Assert(overflowRejected, "ZMD int-backed numeric fields reject values outside ClamAV atoi/int range");

                    var zmdEmptyNumericPath = Path.Combine(mdDir, "empty-numeric.zmd");
                    File.WriteAllText(zmdEmptyNumericPath, "Metadata.Zip.EmptyNumeric::hello\\.txt:::*:::");
                    var zmdEmptyNumericSignature = SignatureParser.ParseFile(zmdEmptyNumericPath).OfType<MetadataSignature>().Single();
                    Assert(zmdEmptyNumericSignature.Encrypted == 0 &&
                           zmdEmptyNumericSignature.OriginalSize?.Min == 0 && zmdEmptyNumericSignature.OriginalSize?.Max == 0 &&
                           zmdEmptyNumericSignature.CompressedSize?.Min == 0 && zmdEmptyNumericSignature.CompressedSize?.Max == 0 &&
                           zmdEmptyNumericSignature.CompressionMethod == 0 &&
                           zmdEmptyNumericSignature.FilePosition?.Min == 0 && zmdEmptyNumericSignature.FilePosition?.Max == 0 &&
                           zmdEmptyNumericSignature.MaxDepth == 0,
                        "ZMD empty numeric fields are accepted like ClamAV cli_isnumber()+atoi and become zero");

        var zmdRes1EmptyPath = Path.Combine(mdDir, "res1-empty.zmd");
        File.WriteAllText(zmdRes1EmptyPath, "Metadata.Zip.Res1Empty:0:hello\\.txt:5:5::0:1:*\n");
        var zmdRes1EmptySignature = SignatureParser.ParseFile(zmdRes1EmptyPath).OfType<MetadataSignature>().Single();
        Assert(zmdRes1EmptySignature.Res1 == 0,
            "ZMD empty Res1 is accepted and cli_hex2num(\"\") yields zero");

        var zmdRes1PartialPath = Path.Combine(mdDir, "res1-partial-hex.zmd");
        File.WriteAllText(zmdRes1PartialPath, "Metadata.Zip.Res1Partial:0:hello\\.txt:5:5:12zz:0:1:*\n");
        var zmdRes1PartialSignature = SignatureParser.ParseFile(zmdRes1PartialPath).OfType<MetadataSignature>().Single();
        Assert(zmdRes1PartialSignature.Res1 == 0x12,
            "ZMD Res1 follows cli_hex2num partial parsing when an even-length token contains a non-hex character");

        var zmdRes1OddPath = Path.Combine(mdDir, "res1-odd.zmd");
        File.WriteAllText(zmdRes1OddPath, "Metadata.Zip.Res1Odd:0:hello\\.txt:5:5:123:0:1:*\n");
        var zmdRes1OddRejected = false;
        try { _ = SignatureParser.ParseFile(zmdRes1OddPath).ToList(); }
        catch (FormatException) { zmdRes1OddRejected = true; }
        File.Delete(zmdRes1OddPath);
        Assert(zmdRes1OddRejected, "ZMD odd-length Res1 is rejected like cli_hex2num");

        var zmdRes1LongPath = Path.Combine(mdDir, "res1-long.zmd");
        File.WriteAllText(zmdRes1LongPath, "Metadata.Zip.Res1Long:0:hello\\.txt:5:5:1234567890:0:1:*\n");
        var zmdRes1LongSignature = SignatureParser.ParseFile(zmdRes1LongPath).OfType<MetadataSignature>().Single();
        Assert(zmdRes1LongSignature.Res1 == unchecked((int)0x34567890),
            "ZMD Res1 has no arbitrary eight-hex-digit input limit and preserves cli_hex2num accumulation");

                    var zmdWildcardEncryptedPath = Path.Combine(mdDir, "encrypted-wildcard.zmd");
                    File.WriteAllText(zmdWildcardEncryptedPath, "Metadata.Zip.EncryptedWildcard:*:hello\\.txt:5:5:*:0:1:*");
                    var zmdWildcardManager = new DatabaseManager();
                    zmdWildcardManager.LoadAndCompile(mdDir, true);
                    var zmdWildcardScanner = new ClamGuard.Scanner.ScannerEngine(zmdWildcardManager);
                    var zmdWildcardResult = zmdWildcardScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
                    Assert(zmdWildcardResult.Detections.Any(x => x.Name == "Metadata.Zip.EncryptedWildcard"), "ZMD encrypted wildcard 2 matches either archive encryption state");

        var zmdWhitespacePath = Path.Combine(mdDir, "whitespace-preserved.zmd");
        File.WriteAllText(zmdWhitespacePath, " Metadata.Zip.LeadingSpace:0:hello\\.txt:5:5:*:0:1:*  \n");
        var zmdWhitespaceRejected = false;
        try { _ = SignatureParser.ParseFile(zmdWhitespacePath).ToList(); }
        catch (FormatException) { zmdWhitespaceRejected = true; }
        File.Delete(zmdWhitespacePath);
        Assert(zmdWhitespaceRejected, "ZMD preserves leading/trailing spaces instead of Trim()-normalizing signature fields");

        var zmdLeadingCommentPath = Path.Combine(mdDir, "leading-space-comment.zmd");
        File.WriteAllText(zmdLeadingCommentPath, " #not-a-comment\n");
        var zmdLeadingCommentRejected = false;
        try { _ = SignatureParser.ParseFile(zmdLeadingCommentPath).ToList(); }
        catch (FormatException) { zmdLeadingCommentRejected = true; }
        File.Delete(zmdLeadingCommentPath);
        Assert(zmdLeadingCommentRejected, "ZMD only treats '#' in column zero as a comment");

        var zmdTrailingFieldPath = Path.Combine(mdDir, "trailing-field.zmd");
        File.WriteAllText(zmdTrailingFieldPath, "Metadata.Zip.ExtraField:0:hello\\.txt:5:5:*:0:1:*:extra\n");
        var zmdTrailingFieldRejected = false;
        try { _ = SignatureParser.ParseFile(zmdTrailingFieldPath).ToList(); }
        catch (FormatException) { zmdTrailingFieldRejected = true; }
        File.Delete(zmdTrailingFieldPath);
        Assert(zmdTrailingFieldRejected, "ZMD rejects extra fields beyond the exact nine-field cli_loadmd format");

        var zmdEmptyLinePath = Path.Combine(mdDir, "empty-line.zmd");
        File.WriteAllText(zmdEmptyLinePath, "\n");
        var zmdEmptyLineRejected = false;
        try { _ = SignatureParser.ParseFile(zmdEmptyLinePath).ToList(); }
        catch (FormatException) { zmdEmptyLineRejected = true; }
        File.Delete(zmdEmptyLinePath);
        Assert(zmdEmptyLineRejected, "ZMD empty lines are parsed as malformed records rather than silently skipped");

        var zmdRangeRejectedPath = Path.Combine(mdDir, "range-rejected.zmd");
        File.WriteAllText(zmdRangeRejectedPath, "Metadata.Zip.RangeRejected:0:hello\\.txt:0-5:5:*:*:1:*");
        var zmdRangeRejected = false;
        try
        {
            new DatabaseLoader().LoadDirectory(mdDir, failOnInvalidFile: true, verifyContainers: false);
        }
        catch (InvalidDataException)
        {
            zmdRangeRejected = true;
        }
        File.Delete(zmdRangeRejectedPath);
        Assert(zmdRangeRejected, "ZMD range syntax is rejected because cli_loadmd accepts exact numeric fields only");

        var zmdMaxDepthPath = Path.Combine(mdDir, "maxdepth-ignored.zmd");
        File.WriteAllText(zmdMaxDepthPath, "Metadata.Zip.MaxDepthIgnored:0:hello\\.txt:5:5:*:0:1:0\n");
        var zmdMaxDepthManager = new DatabaseManager();
        zmdMaxDepthManager.LoadAndCompile(mdDir, true);
        var zmdMaxDepthScanner = new ClamGuard.Scanner.ScannerEngine(zmdMaxDepthManager);
        var zmdMaxDepthResult = zmdMaxDepthScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
        Assert(zmdMaxDepthResult.Detections.Any(x => x.Name == "Metadata.Zip.MaxDepthIgnored"), "ZMD MaxDepth is accepted but ignored like ClamAV cli_matchmeta");

        // CDB (container database) parity: cli_loadcdb() + cli_matchmeta().
        var cdbPath = Path.Combine(mdDir, "local.cdb");
        File.WriteAllText(cdbPath, "Container.Zip:CL_TYPE_ZIP:*:^hello\\.txt$:5:5:0:1:*:opaque\n");
        var cdbSignature = SignatureParser.ParseFile(cdbPath).OfType<CdbSignature>().Single();
        Assert(cdbSignature.ContainerType == "CL_TYPE_ZIP" &&
               cdbSignature.FilePosition is { Min: 1, Max: 1 } &&
               cdbSignature.Encrypted == 0 &&
               cdbSignature.Res2 == "opaque" &&
               cdbSignature.SourceEntry is not null,
               "CDB parser preserves container type, ranges, encryption, Res2 and source line");

        var cdbScanner = new ScannerEngine(new DatabaseManager(new DatabaseLoader().LoadDirectory(mdDir, verifyContainers: false).Database));
        var cdbResult = cdbScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
        Assert(cdbResult.Detections.Any(x => x.Name == "Container.Zip" && x.Type == SignatureType.Metadata),
               "CDB matches ZIP member metadata like cli_matchmeta");

        var cdbRangePath = Path.Combine(mdDir, "range.cdb");
        File.WriteAllText(cdbRangePath, "Container.Zip.Range:CL_TYPE_ZIP:0-999999:^hello\\.txt$:0-10:0-10:0:1:*:*\n");
        var cdbRangeScanner = new ScannerEngine(new DatabaseManager(new DatabaseLoader().LoadDirectory(mdDir, verifyContainers: false).Database));
        var cdbRangeResult = cdbRangeScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
        Assert(cdbRangeResult.Detections.Any(x => x.Name == "Container.Zip.Range"),
               "CDB non-exact ranges treat zero endpoints as unbounded like CDBRANGE");

        var cdbBadTypePath = Path.Combine(mdDir, "bad-type.cdb");
        File.WriteAllText(cdbBadTypePath, "Container.Bad:CL_TYPE_NOT_A_REAL_TYPE:*:*:*:*:*:*:*:*\n");
        var cdbBadTypeRejected = false;
        try { _ = SignatureParser.ParseFile(cdbBadTypePath).ToArray(); }
        catch (FormatException) { cdbBadTypeRejected = true; }
        Assert(cdbBadTypeRejected, "CDB rejects unknown cli_ftcode container types");
        File.Delete(cdbBadTypePath);

        var rmdPath = Path.Combine(mdDir, "local.rmd");
        File.WriteAllText(rmdPath, "Metadata.Rar:1:*:*:*:*:*:1:*\n");
        var rmdSignature = SignatureParser.ParseFile(rmdPath).OfType<MetadataSignature>().Single();
        Assert(rmdSignature.ContainerType == "RAR" && rmdSignature.Encrypted == 1 && rmdSignature.FilePosition?.Min == 1 && rmdSignature.FilePosition?.Max == 1,
            "RMD parses with RAR container semantics");

        var mdManager = new DatabaseManager();
        mdManager.LoadAndCompile(mdDir, true);
        var mdScanner = new ClamGuard.Scanner.ScannerEngine(mdManager);
        var mdResult = mdScanner.Scan(zipForMetadata, new ScanOptions { CollectAllMatches = true });
        Assert(mdResult.Verdict == ScanVerdict.Malicious && mdResult.Detections.Any(x => x.Name == "Metadata.Zip" && x.Type == SignatureType.Metadata),
            "ZMD metadata signature fires during ZIP member discovery");

        var rarForMetadata = Path.Combine(mdDir, "sample.rar");
        var rarPayload = "HELLO"u8.ToArray();
        await File.WriteAllBytesAsync(rarForMetadata, CreateMinimalRar4("hello.txt", rarPayload));
        var rarCrc = RarCrc32(rarPayload);
        var rmdMatchPath = Path.Combine(mdDir, "match.rmd");
        File.WriteAllText(rmdMatchPath, $"Metadata.Rar:0:hello\\.txt:5:5:{rarCrc:X8}:*:1:*\n");
        var rarManager = new DatabaseManager();
        rarManager.LoadAndCompile(mdDir, true);
        var rarScanner = new ClamGuard.Scanner.ScannerEngine(rarManager);
        var rarResult = rarScanner.Scan(rarForMetadata, new ScanOptions { CollectAllMatches = true });
        Assert(rarResult.Verdict == ScanVerdict.Malicious && rarResult.Detections.Any(x => x.Name == "Metadata.Rar" && x.Type == SignatureType.Metadata),
            "RMD metadata signature fires from managed RAR4 metadata without 7z/unrar");
        Directory.Delete(mdDir, true);
    }
}
