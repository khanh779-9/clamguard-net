internal static partial class Program
{
    private static void ScanOptionsBehaviorTests()
    {
        var defaults = ScanOptions.Default;
        Assert(defaults.ScanArchive && defaults.ScanPE && defaults.ScanELF && defaults.ScanOLE2 &&
               defaults.ScanPDF && defaults.ScanHTML && defaults.ScanMail,
            "ScanOptions enables supported parsers by default while allowing each parser to be disabled independently");
        Assert(!defaults.DetectPUA && !defaults.BlockEncrypted && defaults.Recursive &&
               defaults.UseMultithreading && defaults.MaxThreads >= 1,
            "ScanOptions defaults keep PUA/encrypted alerts opt-in and directory scanning bounded");
        Assert(defaults.MaxScanSize == 400 * 1024 * 1024 && defaults.MaxRecursion == 17 &&
               defaults.MaxFiles == 10_000 && defaults.MaxFileSize == 100 * 1024 * 1024,
            "default scan ceilings align with ClamAV 1.5.x MaxScanSize, MaxRecursion, MaxFiles, and MaxFileSize defaults");
        Assert(defaults.ScanSWF && defaults.ScanHWP3 && defaults.ScanXMLDocs && defaults.ScanOneNote &&
               defaults.ScanImage && defaults.ScanImageFuzzyHash,
            "ClamAV 1.5.4 parser capabilities have independent switches for SWF, HWP3, XML docs, OneNote, image, and image fuzzy hash");
        var splitHeuristics = new ScanOptions { HeuristicEncryptedArchive = true, HeuristicEncryptedDoc = false };
        Assert(splitHeuristics.BlockEncrypted && splitHeuristics.HeuristicEncryptedArchive && !splitHeuristics.HeuristicEncryptedDoc,
            "native encrypted-archive and encrypted-document heuristics are independently configurable while preserving the legacy alias");
        var disabledHeuristics = new ScanOptions { EnableHeuristics = false };
        Assert(disabledHeuristics.FilterDetections([new Detection("Heuristics.Limits.Exceeded", SignatureType.Metadata, null, "heuristics")]).Count == 0,
            "disabling CL_SCAN_GENERAL_HEURISTICS suppresses heuristic-only results");
        var heuristicPrecedence = new ScanOptions { HeuristicPrecedence = true };
        var precedence = heuristicPrecedence.FilterDetections([
            new Detection("Win.Test.Malware", SignatureType.Ndb, 1, "daily.ndb"),
            new Detection("Heuristics.Test", SignatureType.Metadata, null, "heuristics")]);
        Assert(precedence.Count == 1 && precedence[0].Name == "Heuristics.Test" && heuristicPrecedence.HasBlockingDetections(precedence),
            "CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE allows an enabled heuristic alert to take precedence");

        var limitOptions = new ScanOptions
        {
            Limits = new ScanLimits
            {
                MaxFileSize = 64L << 20,
                MaxFullBufferSize = 16L << 20,
                MaxArchiveEntries = 200,
                MaxArchiveDepth = 12,
                MaxArchiveExpandedBytes = 512L << 20
            },
            MaxFileSize = 32 * 1024 * 1024,
            MaxScanSize = 48 * 1024 * 1024,
            MaxFiles = 50,
            MaxRecursion = 6
        };
        var effective = limitOptions.CreateEffectiveLimits();
        Assert(effective.MaxFileSize == 32L << 20 && effective.MaxFullBufferSize == 16L << 20,
            "legacy file-size limit is merged with detailed ScanLimits without widening either ceiling");
        Assert(effective.MaxArchiveEntries == 50 && effective.MaxArchiveDepth == 6 &&
               effective.MaxArchiveExpandedBytes == 48L << 20,
            "max files, recursion depth, and total expanded scan size reach the archive budget");

        var pua = new Detection("PUA.Win.Test", SignatureType.Hash, null, "pua.hdu");
        var malware = new Detection("Win.Test.Malware", SignatureType.Ndb, 3, "daily.ndb");
        var heuristic = new Detection("Heuristics.Limits.Exceeded", SignatureType.Metadata, null, "heuristics");
        var puaOff = new ScanOptions { CollectAllMatches = true }.FilterDetections([pua, malware, heuristic]);
        Assert(puaOff.Any(x => x.Name == "Win.Test.Malware") && puaOff.All(x => x.Name != pua.Name),
            "DetectPUA=false filters PUA alerts without hiding malware matches");
        var puaOnSingle = new ScanOptions { DetectPUA = true, CollectAllMatches = false }
            .FilterDetections([pua, heuristic, malware]);
        Assert(puaOnSingle.Count == 1 && puaOnSingle[0].Name == malware.Name,
            "single-result mode prioritizes malware over an earlier PUA/heuristic match");

        var tempRoot = Path.Combine(Path.GetTempPath(), "clamguard-scanoptions-" + Guid.NewGuid().ToString("N"));
        var nestedCache = Path.Combine(tempRoot, "cache", "subdir");
        Directory.CreateDirectory(nestedCache);
        try
        {
            var exclusions = new ScanOptions
            {
                ExcludeDirectories = ["cache"],
                ExcludeExtensions = ["tmp", ".bak"]
            };
            Assert(exclusions.IsExcludedDirectory(Path.Combine(tempRoot, "cache"), tempRoot) &&
                   exclusions.IsExcludedDirectory(nestedCache, tempRoot) &&
                   !exclusions.IsExcludedDirectory(Path.Combine(tempRoot, "cache-copy"), tempRoot),
                "directory exclusions match exact path segments and their descendants, not substring lookalikes");
            Assert(exclusions.IsExcludedExtension("sample.TMP") && exclusions.IsExcludedExtension("backup.BAK") &&
                   !exclusions.IsExcludedExtension("sample.txt"),
                "extension exclusions normalize leading dots and compare case-insensitively");
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }

        var invalidOptionsRejected = false;
        try { new ScanOptions { MaxThreads = 0 }.Validate(); }
        catch (ArgumentOutOfRangeException) { invalidOptionsRejected = true; }
        Assert(invalidOptionsRejected, "invalid concurrency options are rejected before a scan starts");

        var zeroFileLimit = new ScanOptions { MaxFileSize = 0, MaxScanSize = 0 };
        zeroFileLimit.Validate();
        Assert(zeroFileLimit.MaxFileSize == ScanOptions.DefaultMaxFileSize &&
               zeroFileLimit.MaxScanSize == ScanOptions.DefaultMaxScanSize,
            "invalid public size limits recover to safe defaults rather than aborting scanning");

        var overflowedFileLimit = new ScanOptions { MaxFileSize = int.MinValue };
        overflowedFileLimit.Validate();
        Assert(overflowedFileLimit.MaxFileSize == ScanOptions.DefaultMaxFileSize,
            "a negative MaxFileSize caused by integer overflow is normalized before scan validation");

        var twoGiBFileLimit = new ScanOptions { MaxFileSize = 2L << 30 };
        twoGiBFileLimit.Validate();
        Assert(twoGiBFileLimit.MaxFileSize == ScanOptions.MaximumSupportedFileSize,
            "MaxFileSize supports the 2 GiB native ceiling without int overflow");

        var invalidNestedFileLimit = new ScanOptions
        {
            Limits = new ScanLimits { MaxFileSize = 0 }
        };
        invalidNestedFileLimit.Validate();
        Assert(invalidNestedFileLimit.Limits.MaxFileSize == (1L << 30),
            "invalid low-level ScanLimits.MaxFileSize also recovers before effective limits are calculated");

        // Prove the parser switch affects actual nested scanning, not merely the public property.
        var dbDir = Path.Combine(Path.GetTempPath(), "clamguard-scanoptions-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dbDir);
        var zipPath = Path.Combine(Path.GetTempPath(), "clamguard-scanoptions.zip");
        var ooxmlPath = Path.Combine(Path.GetTempPath(), "clamguard-scanoptions.docx");
        try
        {
            File.WriteAllText(Path.Combine(dbDir, "options.ldb"),
                "Options.ZipChild;Engine:81-255,Target:0,Container:CL_TYPE_ZIP;0;5343414e4f5054494f4e534348494c44\n");
            File.WriteAllText(Path.Combine(dbDir, "raw.ndb"),
                "Raw.ZipBytes:0:*:5343414e4f5054494f4e534348494c44\n");
            var manager = new DatabaseManager();
            manager.LoadAndCompile(dbDir, failOnInvalidFile: true);
            var scanner = new ClamGuard.Scanner.ScannerEngine(manager);
            File.WriteAllBytes(zipPath, CreateZipEntry("child.bin", Encoding.ASCII.GetBytes("SCANOPTIONSCHILD")));
            var enabled = scanner.Scan(zipPath, new ScanOptions { CollectAllMatches = true, ScanArchive = true });
            var disabled = scanner.Scan(zipPath, new ScanOptions { CollectAllMatches = true, ScanArchive = false });
            var recoveredInvalidSize = scanner.Scan(zipPath, new ScanOptions
            {
                CollectAllMatches = true,
                ScanArchive = true,
                MaxFileSize = 0
            });
            Assert(recoveredInvalidSize.Verdict != ScanVerdict.Error &&
                   recoveredInvalidSize.Detections.Any(x => x.Name == "Raw.ZipBytes"),
                "scan remains operational when a stale or overflowed public MaxFileSize value is normalized");
            Assert(enabled.Detections.Any(x => x.Name == "Options.ZipChild"),
                "ScanArchive=true extracts and scans a real nested ZIP entry");
            Assert(!disabled.Detections.Any(x => x.Name == "Options.ZipChild") &&
                   disabled.Detections.Any(x => x.Name == "Raw.ZipBytes"),
                "ScanArchive=false disables nested parsing while preserving raw-byte signature scanning");

            // Native ClamAV handles OOXML with two distinct switches: XMLDOCS
            // controls the optional OOXML metadata path, while ARCHIVE controls
            // ZIP extraction and malware scanning of contained entries.
            File.WriteAllBytes(ooxmlPath, CreateZipEntry("word/document.xml", Encoding.ASCII.GetBytes("SCANOPTIONSCHILD")));
            var xmlDocsEnabledArchiveDisabled = scanner.Scan(ooxmlPath, new ScanOptions
            {
                CollectAllMatches = true,
                ScanArchive = false,
                ScanXMLDocs = true
            });
            var xmlDocsDisabledArchiveEnabled = scanner.Scan(ooxmlPath, new ScanOptions
            {
                CollectAllMatches = true,
                ScanArchive = true,
                ScanXMLDocs = false
            });
            Assert(!xmlDocsEnabledArchiveDisabled.Detections.Any(x => x.Name == "Options.ZipChild"),
                "ScanArchive=false prevents OOXML ZIP member extraction even if ScanXMLDocs=true");
            Assert(xmlDocsDisabledArchiveEnabled.Detections.Any(x => x.Name == "Options.ZipChild"),
                "ScanArchive=true still scans OOXML ZIP members when the separate ScanXMLDocs metadata option is disabled");

            var limitedBuffer = scanner.Scan(zipPath, new ScanOptions
            {
                CollectAllMatches = true,
                ScanArchive = true,
                Limits = new ScanLimits
                {
                    MaxFileSize = 1L << 20,
                    MaxFullBufferSize = 4,
                    MaxArchiveEntries = 100,
                    MaxArchiveDepth = 8,
                    MaxArchiveExpandedBytes = 16L << 20,
                    MaxEmbeddedStreamSize = 1L << 20,
                    MaxHtmlNormalize = 1L << 20,
                    MaxHtmlNoTags = 1L << 20,
                    MaxScriptNormalize = 1L << 20
                }
            });
            Assert(limitedBuffer.Detections.Any(x => x.Name == "Raw.ZipBytes") &&
                   limitedBuffer.Detections.Any(x => x.Name == "Heuristics.Limits.Exceeded"),
                "full-buffer limits skip secondary parsing but continue the raw signature pass and report incomplete scanning");
        }
        finally
        {
            if (File.Exists(zipPath)) File.Delete(zipPath);
            if (File.Exists(ooxmlPath)) File.Delete(ooxmlPath);
            if (Directory.Exists(dbDir)) Directory.Delete(dbDir, recursive: true);
        }
    }
}
