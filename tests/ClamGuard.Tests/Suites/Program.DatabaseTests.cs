internal static partial class Program
{
    private static void DatabaseAndCvdTests()
    {
        var pattern = HexPatternParser.Parse("68656c6c6f");
        Assert(pattern.Matches("hello"u8, 0, out _), "fixed hexadecimal pattern matches");

        var wildcard = HexPatternParser.Parse("68??????6f");
        Assert(wildcard.Matches("hello"u8, 0, out _), "byte wildcard pattern matches");

        var range = HexPatternParser.Parse("68{1-3}6f");
        Assert(range.Matches("hello"u8, 0, out _), "bounded gap matches");

        var temp = Path.Combine(Path.GetTempPath(), "clamguard-demo.hdb");
        File.WriteAllText(temp, "5d41402abc4b2a76b9719d911017c592:5:Demo.HelloWorld\n");
        var signatures = SignatureParser.ParseHashFile(temp).ToArray();
        Assert(signatures.Length == 1 && signatures[0].Algorithm == HashAlgorithmKind.Md5, "HDB parser recognizes MD5");

        var header = CvdReader.ParseHeader("ClamAV-VDB:01 Jan 2026 00-00 +0000:42:123:150:abc:def:builder:1767225600");
        Assert(header.Version == 42 && header.SignatureCount == 123 && header.FunctionalityLevel == 150, "CVD header fields parse");

        var invalidHeaderRejected = false;
        try { _ = CvdReader.ParseHeader("ClamAV-VDB:missing:fields"); }
        catch (FormatException) { invalidHeaderRejected = true; }
        Assert(invalidHeaderRejected, "malformed CVD header is rejected");

        var rawCvdRoot = Path.Combine(Path.GetTempPath(), "clamguard-cvd-rawtar-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rawCvdRoot);
        var rawCvd = Path.Combine(rawCvdRoot, "daily.cvd");
        var rawTar = Path.Combine(rawCvdRoot, "payload.tar");
        using (var tarFile = File.Create(rawTar))
        using (var tarWriter = new TarWriter(tarFile, TarEntryFormat.Ustar, leaveOpen: false))
        {
            var copying = new UstarTarEntry(TarEntryType.RegularFile, "COPYING")
            { DataStream = new MemoryStream(Encoding.ASCII.GetBytes("ClamAV raw-tar fixture\n")) };
            tarWriter.WriteEntry(copying);

            var entry = new UstarTarEntry(TarEntryType.RegularFile, "raw.ndb")
            { DataStream = new MemoryStream(Encoding.UTF8.GetBytes("6d616c77617265:6:RawTar.Test\n")) };
            tarWriter.WriteEntry(entry);
        }
        using (var rawCvdFile = File.Create(rawCvd))
        {
            var headerBytes = new byte[512];
            var headerText = Encoding.ASCII.GetBytes("ClamAV-VDB:Thu Jan 01 00:00:00 2026:42:1:150:abc:def:builder:1767225600\n");
            headerText.CopyTo(headerBytes, 0);
            rawCvdFile.Write(headerBytes);
            using var tarInput = File.OpenRead(rawTar);
            var marker = new byte[7];
            tarInput.ReadExactly(marker);
            Assert(Encoding.ASCII.GetString(marker) == "COPYING", "raw tar fixture starts with ClamAV's COPYING marker");
            tarInput.Position = 0;
            tarInput.CopyTo(rawCvdFile);
        }
        var extractedRaw = Path.Combine(rawCvdRoot, "extract");
        CvdReader.Extract(rawCvd, extractedRaw);
        Assert(File.ReadAllText(Path.Combine(extractedRaw, "raw.ndb")) == "6d616c77617265:6:RawTar.Test\n", "CVD raw tar payload extracts like ClamAV 1.5.4");
        Directory.Delete(rawCvdRoot, true);

        // ClamAV 1.5.4 loads only one of the daily.cld/daily.cvd pair: highest version,
        // with daily.cld preferred when versions are equal. A skipped daily.cvd must not
        // be opened/extracted merely because it is present beside a newer CLD.
        var dailySelectionClDPath = Path.Combine(Path.GetTempPath(), "clamguard-daily-selection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dailySelectionClDPath);
        WriteCvdFixture(Path.Combine(dailySelectionClDPath, "daily.cld"), 42, "Daily.ClD:0:0:4142\n");
        WriteCvdFixture(Path.Combine(dailySelectionClDPath, "daily.cvd"), 41, "Daily.CvD:0:0:4143\n", truncatePayload: true);
        var dailyClDResult = new DatabaseLoader().LoadDirectory(dailySelectionClDPath, failOnInvalidFile: false, verifyContainers: false);
        Assert(dailyClDResult.Errors.Count == 0 &&
               dailyClDResult.Files.Any(x => string.Equals(x.Name, "daily.cld", StringComparison.OrdinalIgnoreCase)) &&
               !dailyClDResult.Files.Any(x => string.Equals(x.Name, "daily.cvd", StringComparison.OrdinalIgnoreCase)),
            "daily.cld wins over an older daily.cvd without opening the skipped payload");
        Directory.Delete(dailySelectionClDPath, true);

        var dailySelectionCvDPath = Path.Combine(Path.GetTempPath(), "clamguard-daily-selection-cvd-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dailySelectionCvDPath);
        WriteCvdFixture(Path.Combine(dailySelectionCvDPath, "daily.cld"), 41, "Daily.ClD:0:0:4142\n");
        WriteCvdFixture(Path.Combine(dailySelectionCvDPath, "daily.cvd"), 42, "Daily.CvD:0:0:4143\n");
        var dailyCvDResult = new DatabaseLoader().LoadDirectory(dailySelectionCvDPath, failOnInvalidFile: false, verifyContainers: false);
        Assert(dailyCvDResult.Errors.Count == 0 &&
               dailyCvDResult.Files.Any(x => string.Equals(x.Name, "daily.cvd", StringComparison.OrdinalIgnoreCase)) &&
               !dailyCvDResult.Files.Any(x => string.Equals(x.Name, "daily.cld", StringComparison.OrdinalIgnoreCase)),
            "newer daily.cvd wins over an older daily.cld");
        Directory.Delete(dailySelectionCvDPath, true);

        var dailySelectionTiePath = Path.Combine(Path.GetTempPath(), "clamguard-daily-selection-tie-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dailySelectionTiePath);
        WriteCvdFixture(Path.Combine(dailySelectionTiePath, "daily.cld"), 42, "Daily.ClD:0:0:4142\n");
        WriteCvdFixture(Path.Combine(dailySelectionTiePath, "daily.cvd"), 42, "Daily.CvD:0:0:4143\n");
        var dailyTieResult = new DatabaseLoader().LoadDirectory(dailySelectionTiePath, failOnInvalidFile: false, verifyContainers: false);
        Assert(dailyTieResult.Files.Any(x => string.Equals(x.Name, "daily.cld", StringComparison.OrdinalIgnoreCase)) &&
               !dailyTieResult.Files.Any(x => string.Equals(x.Name, "daily.cvd", StringComparison.OrdinalIgnoreCase)),
            "daily.cld wins when daily.cld and daily.cvd have the same version");
        Directory.Delete(dailySelectionTiePath, true);

        // ClamAV 1.5.4 does not apply conventional '&' before '|'. It splits at the first
        // top-level operator, so 0&1|2 means 0&(1|2). Parentheses remain the explicit way
        // to request (0&1)|2.
        var ldbPrecedencePath = Path.Combine(Path.GetTempPath(), "clamguard-clamav-precedence.ldb");
        File.WriteAllText(ldbPrecedencePath,
            "Logic.ClamAvPrecedence;Engine:81-255,Target:0;0&1|2;4141;4242;4343\n" +
            "Logic.ExplicitGrouping;Engine:81-255,Target:0;(0&1)|2;4141;4242;4343\n");
        var ldbPrecedenceDir = Path.Combine(Path.GetTempPath(), "clamguard-clamav-precedence-db-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(ldbPrecedenceDir);
        File.Copy(ldbPrecedencePath, Path.Combine(ldbPrecedenceDir, "precedence.ldb"));
        var ldbPrecedenceManager = new DatabaseManager();
        ldbPrecedenceManager.LoadAndCompile(ldbPrecedenceDir, true);
        var ldbPrecedenceScanner = new ClamGuard.Scanner.ScannerEngine(ldbPrecedenceManager);
        var ldbPrecedenceFile = Path.Combine(Path.GetTempPath(), "clamguard-clamav-precedence.bin");
        File.WriteAllBytes(ldbPrecedenceFile, "BBCC"u8.ToArray());
        var ldbPrecedenceResult = ldbPrecedenceScanner.Scan(ldbPrecedenceFile);
        Assert(!ldbPrecedenceResult.Detections.Any(x => x.Name == "Logic.ClamAvPrecedence"),
            "LDB mixed operators follow ClamAV 1.5.4 precedence semantics");
        Assert(ldbPrecedenceResult.Detections.Any(x => x.Name == "Logic.ExplicitGrouping"),
            "LDB parentheses override the ClamAV mixed-operator split semantics");
        Directory.Delete(ldbPrecedenceDir, true);
        File.Delete(ldbPrecedencePath);
        File.Delete(ldbPrecedenceFile);

        File.Delete(temp);
    }
}
