internal static partial class Program
{
    private static async Task ScanHostSmokeAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "clamguard-scanhost-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var file = Path.Combine(root, "clean.bin");
        await File.WriteAllBytesAsync(file, "scanhost-smoke"u8.ToArray());
        var dbDir = Path.Combine(root, "db");
        Directory.CreateDirectory(dbDir);
        File.WriteAllText(Path.Combine(dbDir, "smoke.hdb"), "cb81e7c4bf5847a951a1702052001022:15:ScanHost.CleanProbe\n");
        var manager = new DatabaseManager();
        manager.LoadAndCompile(dbDir, true);
        var scanner = new ClamGuard.Scanner.ScannerEngine(manager);
        using var host = new ClamGuard.Scanner.Hosting.ScanHost(
            manager,
            scanner,
            new ClamGuard.Scanner.Hosting.ScanHostOptions { MaxConcurrentScans = 1, MaxQueuedScans = 2 });
        var result = await host.ScanAsync(file);
        Assert(result.Verdict == ScanVerdict.Clean, "scan host clean scan");
        var metrics = host.GetMetrics();
        Assert(metrics.Started == 1 && metrics.Completed == 1 && metrics.Errors == 0, "scan host metrics accounting");
        var health = host.GetHealth();
        Assert(health.Healthy && health.SignatureCount == 1, "scan host health accepts loaded database");

        var slow = new SlowScanner(TimeSpan.FromMilliseconds(200));
        using var queueHost = new ClamGuard.Scanner.Hosting.ScanHost(
            manager,
            scanner,
            new ClamGuard.Scanner.Hosting.ScanHostOptions
            { MaxConcurrentScans = 1, MaxQueuedScans = 1, QueueWaitTimeout = TimeSpan.FromMilliseconds(25), ScanTimeout = TimeSpan.FromSeconds(2) });
        var slowOptions = new ScanOptions();
        slowOptions.ContentScanners.Add(slow);
        var firstScan = Task.Run(() => queueHost.ScanAsync(file, slowOptions));
        await slow.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var queueTimeout = await queueHost.ScanAsync(file);
        var firstResult = await firstScan;
        Assert(firstResult.Verdict == ScanVerdict.Clean, "bounded scan completes while another request queues");
        Assert(queueTimeout.Verdict == ScanVerdict.Timeout, "queue timeout is fail-closed");
        var queueMetrics = queueHost.GetMetrics();
        Assert(queueMetrics.QueueTimeouts == 1 && queueMetrics.Timeouts == 1, "timeout accounting is not double-counted");

        File.Delete(file);
        Directory.Delete(root, true);
    }

    private static async Task SpecializedHandlersSmokeAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "clamguard-specialized-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // HTML: the native handler runs before the raw scan and emits normalized
            // nocomment/notags/javascript layers. Verify a target-7 signature can match
            // JavaScript extracted from an HTML file.
            var htmlDb = Path.Combine(root, "html");
            Directory.CreateDirectory(htmlDb);
            File.WriteAllText(Path.Combine(htmlDb, "types.ftm"),
                "0:0:3c21444f4354595045:HTML:CL_TYPE_ANY:CL_TYPE_HTML\n");
            File.WriteAllText(Path.Combine(htmlDb, "script.ndb"),
                "Special.JsAscii:7:*:636f6e736f6c652e6c6f67\n"); // console.log
            var htmlManager = new DatabaseManager();
            htmlManager.LoadAndCompile(htmlDb, true);
            var htmlFile = Path.Combine(root, "page.bin");
            await File.WriteAllTextAsync(htmlFile,
                "<!DOCTYPE html><html><script>  CONSOLE . LOG  ( 'x' ) </script><!--ignore--></html>");
            var htmlResult = new ClamGuard.Scanner.ScannerEngine(htmlManager).Scan(htmlFile);
            Assert(htmlResult.FileType == "HTML" && htmlResult.Detections.Any(x => x.Name == "Special.JsAscii"),
                "specialized HTML handler extracts JavaScript and scans it as normalized ASCII");

            // HWP3: the native handler parses the 30-byte identity + 128-byte docinfo +
            // 1008-byte summary header, then inflates the body with raw DEFLATE.
            // Put the detection payload only in the compressed body so the test proves
            // the specialized parser path rather than the root raw scan.
            var hwpDb = Path.Combine(root, "hwp");
            Directory.CreateDirectory(hwpDb);
            File.WriteAllText(Path.Combine(hwpDb, "types.ftm"),
                "0:0:48575020446f63756d656e742046696c652056332e3030201a0102030405:HWP3:CL_TYPE_ANY:CL_TYPE_HWP3\n");
            File.WriteAllText(Path.Combine(hwpDb, "hwp-body.ndb"),
                "Special.HwpBody:0:*:4857502d52455343414e2d4d41524b4552\n"); // HWP-RESCAN-MARKER
            var hwpManager = new DatabaseManager();
            hwpManager.LoadAndCompile(hwpDb, true);

            var hwpFile = Path.Combine(root, "compressed.hwp");
            var hwp = new byte[1166];
            Encoding.ASCII.GetBytes("HWP Document File V3.00 \x1A\x01\x02\x03\x04\x05").CopyTo(hwp, 0);
            // DocumentInfo is at offset 30; compression flag is byte 124 inside it.
            hwp[30 + 124] = 1;
            using var body = new MemoryStream();
            await using (var deflater = new DeflateStream(body, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                await deflater.WriteAsync("HWP-RESCAN-MARKER"u8.ToArray());
            }
            await File.WriteAllBytesAsync(hwpFile, hwp.Concat(body.ToArray()).ToArray());

            var hwpResult = new ClamGuard.Scanner.ScannerEngine(hwpManager).Scan(hwpFile);
            Assert(hwpResult.FileType == "HWP3" && hwpResult.Detections.Any(x => x.Name == "Special.HwpBody"),
                "specialized HWP3 handler inflates raw-DEFLATE body and rescans the decompressed layer");
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static async Task NativeSpecializedSmokeAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "clamguard-native-specialized-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // OneNote fallback path from ClamAV's onenote.rs: 16-byte OneStore magic,
            // FileDataStoreObject GUID, 32-byte header tail, then a bounded payload.
            var oneDb = Path.Combine(root, "one-db");
            Directory.CreateDirectory(oneDb);
            File.WriteAllText(Path.Combine(oneDb, "types.ftm"),
                "0:0:e4525c7b8cd8a74daeb15378d02996d3:OneNote:CL_TYPE_ANY:CL_TYPE_ONENOTE\n");
            File.WriteAllText(Path.Combine(oneDb, "one.ndb"),
                "Special.OneAttachment:0:*:4f4e452d4154544143484d454e542d4d41524b4552\n");
            var oneManager = new DatabaseManager();
            oneManager.LoadAndCompile(oneDb, true);
            var onePayload = "ONE-ATTACHMENT-MARKER"u8.ToArray();
            var one = new List<byte>();
            one.AddRange(new byte[] { 0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D,0xAE,0xB1,0x53,0x78,0xD0,0x29,0x96,0xD3 });
            one.AddRange(new byte[] { 0xE7,0x16,0xE3,0xBD,0x65,0x26,0x11,0x45,0xA4,0xC4,0x8D,0x4D,0x0B,0x7A,0x9E,0xAC });
            var header16 = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(header16, checked((uint)onePayload.Length));
            one.AddRange(header16); // FileDataHeader bytes 16..31 with cbLength at start
            one.AddRange(new byte[12]); // upper cbLength + unused + reserved
            one.AddRange(onePayload);
            var oneFile = Path.Combine(root, "attachment.one");
            await File.WriteAllBytesAsync(oneFile, one.ToArray());
            var oneResult = new ClamGuard.Scanner.ScannerEngine(oneManager).Scan(oneFile);
            Assert(oneResult.FileType == "ONENOTE" && oneResult.Detections.Any(x => x.Name == "Special.OneAttachment"),
                "OneNote fallback extracts FileDataStoreObject payload and rescans it");

            // XDP: cli_scanxdp() only submits decoded <chunk> data when a %PDF- marker
            // is found near the beginning of the decoded payload.
            var xdpDb = Path.Combine(root, "xdp-db");
            Directory.CreateDirectory(xdpDb);
            File.WriteAllText(Path.Combine(xdpDb, "types.ftm"),
                "1:*:3c7864703a786470:XDP:CL_TYPE_ANY:CL_TYPE_XDP:79\n");
            File.WriteAllText(Path.Combine(xdpDb, "xdp.ndb"),
                "Special.XdpPdf:0:*:255044462d312e37\n"); // %PDF-1.7
            var xdpManager = new DatabaseManager();
            xdpManager.LoadAndCompile(xdpDb, true);
            var pdfPayload = Encoding.ASCII.GetBytes("%PDF-1.7\nXDP-EMBEDDED-MARKER\n");
            var xdp = $"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><chunk>{Convert.ToBase64String(pdfPayload)}</chunk></xdp:xdp>";
            var xdpFile = Path.Combine(root, "embedded.xdp");
            await File.WriteAllTextAsync(xdpFile, xdp);
            var xdpResult = new ClamGuard.Scanner.ScannerEngine(xdpManager).Scan(xdpFile);
            Console.WriteLine($"XDP DEBUG: FileType='{xdpResult.FileType}', Verdict={xdpResult.Verdict}, Detections={string.Join(", ", xdpResult.Detections.Select(x => x.Name))}");
            Assert(xdpResult.FileType == "XDP" && xdpResult.Detections.Any(x => x.Name == "Special.XdpPdf"),
                "XDP decodes PDF chunk only after native-style marker gate");

            // HWPML: ClamAV binds bindata/scriptheader/scriptsource values to a callback;
            // Base64 decoding and optional zlib decompression happen before rescanning.
            var hwpmlDb = Path.Combine(root, "hwpml-db");
            Directory.CreateDirectory(hwpmlDb);
            File.WriteAllText(Path.Combine(hwpmlDb, "types.ftm"),
                "1:0:efbbbf3c3f786d6c2076657273696f6e3d22312e3022*3c4857504d4c:HWPML:CL_TYPE_ANY:CL_TYPE_XML_HWP:82\n");
            File.WriteAllText(Path.Combine(hwpmlDb, "hwpml.ndb"),
                "Special.HwpmlBinary:0:*:4857504d4c2d454d4245444445442d4d41524b4552\n");
            var hwpmlManager = new DatabaseManager();
            hwpmlManager.LoadAndCompile(hwpmlDb, true);
            var hwpmlPayload = Encoding.ASCII.GetBytes("HWPML-EMBEDDED-MARKER");
            var hwpml = "\uFEFF<?xml version=\"1.0\"?><HWPML><tail><bindatastorage><bindata Encoding=\"Base64\" Compress=\"false\">" +
                        Convert.ToBase64String(hwpmlPayload) + "</bindata></bindatastorage></tail></HWPML>";
            var hwpmlFile = Path.Combine(root, "document.hwpml");
            await File.WriteAllTextAsync(hwpmlFile, hwpml);
            var hwpmlResult = new ClamGuard.Scanner.ScannerEngine(hwpmlManager).Scan(hwpmlFile);
            Assert(hwpmlResult.FileType == "XML_HWP" && hwpmlResult.Detections.Any(x => x.Name == "Special.HwpmlBinary"),
                "HWPML Base64 binary callback decodes and rescans embedded content");
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static void SpecialDatabaseLoadSmoke()
    {
        var root = Path.Combine(Path.GetTempPath(), "clamguard-db-loader-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "types.ftm"), "0:0:504b0304:ZIP:CL_TYPE_BINARY_DATA:CL_TYPE_ZIP:234:999\n1:*:3c48544d4c3e:HTML:CL_TYPE_ANY:CL_TYPE_HTML\n4:0:55aa:PART:CL_TYPE_BINARY_DATA:CL_TYPE_PART_ANY:234:999\n");
            File.WriteAllText(Path.Combine(root, "daily.cfg"), "PE:0x20000:234:999\nARCHIVE:0x4000000:234:999\nDOCUMENT:0x100:234:999\n");
            File.WriteAllText(Path.Combine(root, "allow.wdb"), "^example\\.com$\n");
            File.WriteAllText(Path.Combine(root, "domains.pdb"), "^https?://evil\\.example/\n");
            File.WriteAllText(Path.Combine(root, "domains.gdb"), "^https?://evil\\.example/\n");
            File.WriteAllText(Path.Combine(root, "passwords.pwdb"), "KnownPassword;Container:ZIP;0;secret\nHexPassword;Container:RAR;1;736563726574\n");
            File.WriteAllText(Path.Combine(root, "certs.crb"), "TestCA;1;00112233445566778899aabbccddeeff00112233;;010001;65537;1;1;1;0;comment;234;999\n");
            File.WriteAllBytes(Path.Combine(root, "catalog.cat"), [0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
            File.WriteAllText(Path.Combine(root, "ioc.ioc"), "<?xml version=\"1.0\"?><ioc><definition><Indicator><IndicatorItem><Context document=\"FileItem\" search=\"FileItem/Sha256sum\"><Content type=\"sha256\">0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</Content></Context></IndicatorItem></Indicator></definition></ioc>");
            File.WriteAllText(Path.Combine(root, "rule.yar"), "rule Demo { condition: true }");
            File.WriteAllText(Path.Combine(root, "rule.cbc"), BuildMinimalClamBc());
            File.WriteAllText(Path.Combine(root, "database.info"), "ClamAV-VDB:test\ndaily.ndb;42;0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n");

            var loaded = new DatabaseLoader { IncludePua = true }.LoadDirectory(root, failOnInvalidFile: true, verifyContainers: false);
            Assert(loaded.Database.SpecialDatabases.FileTypes.Count == 3, "FTM database fully loaded");
            Assert(loaded.Database.SpecialDatabases.DynamicConfig.Count == 3, "DCONF database fully loaded");
            Assert(loaded.Database.SpecialDatabases.PhishingRules.Count == 3, "WDB/PDB/GDB databases loaded");
            Assert(loaded.Database.SpecialDatabases.Passwords.Count == 2, "PWDB database fully loaded");
            Assert(loaded.Database.SpecialDatabases.Certificates.Count == 1, "CRB database fully loaded");
            Assert(loaded.Database.SpecialDatabases.Catalogs.Count == 1 && loaded.Database.SpecialDatabases.Catalogs[0].LooksLikePkcs7SignedData, "CAT database structurally recognized");
            Assert(loaded.Database.Signatures.OfType<HashSignature>().Count() == 1, "OpenIOC hash extraction matches ClamAV supported hash behavior");
            Assert(loaded.Database.SpecialDatabases.AlternativeRuleFiles.Count == 2 &&
                   loaded.Database.SpecialDatabases.AlternativeRuleFiles.Sum(x => x.EntryCount) == 2, "YARA and bytecode databases parsed");
            Assert(loaded.Database.SpecialDatabases.InfoRecords.Count == 1 && loaded.Database.SpecialDatabases.InfoRecords[0].Size == 42, "INFO database records parsed");
            Assert(loaded.Errors.Count == 0, "all supported database fixtures load without errors");
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static async Task ScanPipelineFileTypeSmokeAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "clamguard-scan-pipeline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // Mode-0 FTM ignores rtype in ClamAV's native cli_ftype list.
            var directDb = Path.Combine(root, "direct");
            Directory.CreateDirectory(directDb);
            File.WriteAllText(Path.Combine(directDb, "types.ftm"),
                "0:0:41424344:DirectElf:CL_TYPE_MSEXE:CL_TYPE_ELF\n");
            var directManager = new DatabaseManager();
            directManager.LoadAndCompile(directDb, true);
            var directFile = Path.Combine(root, "direct.bin");
            await File.WriteAllBytesAsync(directFile, "ABCD-not-a-real-elf"u8.ToArray());
            var directResult = new ClamGuard.Scanner.ScannerEngine(directManager).Scan(directFile);
            Assert(directResult.FileType == "ELF", "FTM mode-0 direct magic uses type even when rtype is non-matching");

            // Mode-1 FTM uses the already detected text/binary type as rtype and can
            // promote the layer to a specialized handler without relying on file names.
            var contentDb = Path.Combine(root, "content");
            Directory.CreateDirectory(contentDb);
            File.WriteAllText(Path.Combine(contentDb, "types.ftm"),
                "1:*:414243:RetypeScript:CL_TYPE_TEXT_ASCII:CL_TYPE_SCRIPT\n");
            var contentManager = new DatabaseManager();
            contentManager.LoadAndCompile(contentDb, true);
            var contentFile = Path.Combine(root, "scriptless.bin");
            await File.WriteAllBytesAsync(contentFile, "zzABCzz"u8.ToArray());
            var contentResult = new ClamGuard.Scanner.ScannerEngine(contentManager).Scan(contentFile);
            Assert(contentResult.FileType == "SCRIPT", "FTM mode-1 content matching retypes ASCII content");

            // PE-specialized hash databases must not run on non-PE layers.
            var nonPeDb = Path.Combine(root, "nonpe");
            Directory.CreateDirectory(nonPeDb);
            var nonPeFile = Path.Combine(root, "plain.txt");
            await File.WriteAllTextAsync(nonPeFile, "specialized hash must not run here");
            var md5 = Convert.ToHexString(System.Security.Cryptography.MD5.HashData(await File.ReadAllBytesAsync(nonPeFile))).ToLowerInvariant();
            File.WriteAllText(Path.Combine(nonPeDb, "test.mdb"), $"{new FileInfo(nonPeFile).Length}:{md5}:PE.NonPeHash\n");
            var nonPeManager = new DatabaseManager();
            nonPeManager.LoadAndCompile(nonPeDb, true);
            var nonPeResult = new ClamGuard.Scanner.ScannerEngine(nonPeManager).Scan(nonPeFile);
            Assert(!nonPeResult.Detections.Any(x => x.Name == "PE.NonPeHash"), "PE section hash matcher is gated to PE file types");

            // Later FTM definitions take precedence, matching cli_loadftm() list insertion.
            var precedenceDb = Path.Combine(root, "precedence");
            Directory.CreateDirectory(precedenceDb);
            File.WriteAllText(Path.Combine(precedenceDb, "types.ftm"),
                "0:0:44454647:First:CL_TYPE_ANY:CL_TYPE_ELF\n" +
                "0:0:44454647:Second:CL_TYPE_ANY:CL_TYPE_MSEXE\n");
            var precedenceManager = new DatabaseManager();
            precedenceManager.LoadAndCompile(precedenceDb, true);
            var precedenceFile = Path.Combine(root, "precedence.bin");
            await File.WriteAllBytesAsync(precedenceFile, "DEFGpayload"u8.ToArray());
            var precedenceResult = new ClamGuard.Scanner.ScannerEngine(precedenceManager).Scan(precedenceFile);
            Assert(precedenceResult.FileType == "PE", "FTM overlapping definitions preserve later-definition precedence");

            // Specialized graphics types are distinct ClamAV scan-layer types, while
            // target type 5 matches the whole graphics family (GRAPHICS/GIF/PNG/JPEG/TIFF).
            var pngDb = Path.Combine(root, "png");
            Directory.CreateDirectory(pngDb);
            File.WriteAllText(Path.Combine(pngDb, "types.ftm"),
                "0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_PNG\n");
            var pngManager = new DatabaseManager();
            pngManager.LoadAndCompile(pngDb, true);
            var pngFile = Path.Combine(root, "image.bin");
            await File.WriteAllBytesAsync(pngFile, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
            var pngResult = new ClamGuard.Scanner.ScannerEngine(pngManager).Scan(pngFile);
            Assert(pngResult.FileType == "PNG", "PNG keeps its specialized ClamAV file type");

            // Target 5 is the graphics family in ClamAV: specialized GIF/PNG/JPEG/TIFF
            // types are eligible for the same raw target bucket.
            File.WriteAllText(Path.Combine(pngDb, "graphics.ndb"),
                "Graphics.Target5:5:0:89504e47\n");
            var graphicsManager = new DatabaseManager();
            graphicsManager.LoadAndCompile(pngDb, true);
            var graphicsResult = new ClamGuard.Scanner.ScannerEngine(graphicsManager).Scan(pngFile);
            Assert(graphicsResult.Detections.Any(x => x.Name == "Graphics.Target5"),
                "NDB target 5 matches a specialized PNG file type through the graphics family");
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }
}
