using System.Buffers.Binary;
using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using ClamGuard.Core;
using ClamGuard.Signatures;
using ClamGuard.Database;
using ClamGuard.Scanner;
using ClamGuard.Signatures.Parsing;
using ClamGuard.Signatures.Patterns;

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException("TEST FAILED: " + message);
    Console.WriteLine("PASS: " + message);
}

static void WriteCvdFixture(string path, uint version, string ndbLine, bool truncatePayload = false)
{
    using var tarBuffer = new MemoryStream();
    using (var tarWriter = new TarWriter(tarBuffer, TarEntryFormat.Ustar, leaveOpen: true))
    {
        var copying = new UstarTarEntry(TarEntryType.RegularFile, "COPYING")
        { DataStream = new MemoryStream(Encoding.ASCII.GetBytes("ClamAV raw-tar fixture\n")) };
        tarWriter.WriteEntry(copying);

        var entry = new UstarTarEntry(TarEntryType.RegularFile, "selection.ndb")
        { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(ndbLine)) };
        tarWriter.WriteEntry(entry);
    }

    var payload = tarBuffer.ToArray();
    using var file = File.Create(path);
    var headerBytes = new byte[512];
    var header = Encoding.ASCII.GetBytes($"ClamAV-VDB:Thu Jan 01 00:00:00 2026:{version}:1:150:abc:def:builder:1767225600\n");
    header.CopyTo(headerBytes, 0);
    file.Write(headerBytes);
    if (!truncatePayload)
        file.Write(payload);
}


static uint RarCrc32(ReadOnlySpan<byte> data)
{
    var crc = 0xFFFFFFFFu;
    foreach (var value in data)
    {
        crc ^= value;
        for (var i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint)-(int)(crc & 1));
    }
    return crc ^ 0xFFFFFFFFu;
}

static byte[] BuildRar4Block(byte type, ushort flags, ReadOnlySpan<byte> body)
{
    var size = checked(7 + body.Length);
    var block = new byte[size];
    block[2] = type;
    BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(3, 2), flags);
    BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(5, 2), checked((ushort)size));
    body.CopyTo(block.AsSpan(7));
    BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(0, 2), checked((ushort)RarCrc32(block.AsSpan(2))));
    return block;
}

static byte[] CreateMinimalRar4(string name, byte[] content)
{
    var nameBytes = Encoding.ASCII.GetBytes(name);
    var mainBody = new byte[6]; // RESERVED1 + RESERVED2
    var main = BuildRar4Block(0x73, 0, mainBody);

    var fileBody = new byte[25 + nameBytes.Length];
    BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(0, 4), checked((uint)content.Length)); // PACK_SIZE
    BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(4, 4), checked((uint)content.Length)); // UNP_SIZE
    fileBody[8] = 0; // HOST_OS
    BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(9, 4), RarCrc32(content));
    BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(13, 4), 0); // FTIME
    fileBody[17] = 20; // UNP_VER
    fileBody[18] = 0x30; // METHOD: store
    BinaryPrimitives.WriteUInt16LittleEndian(fileBody.AsSpan(19, 2), checked((ushort)nameBytes.Length));
    BinaryPrimitives.WriteUInt32LittleEndian(fileBody.AsSpan(21, 4), 0); // ATTR
    nameBytes.CopyTo(fileBody.AsSpan(25));
    var file = BuildRar4Block(0x74, 0, fileBody);
    var end = BuildRar4Block(0x7B, 0, []);

    return [
        0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00,
        ..main,
        ..file,
        ..content,
        ..end
    ];
}

static string EncodeBcNumber(ulong value)
{
    var digits = Math.Max(1, (64 - System.Numerics.BitOperations.LeadingZeroCount(value) + 3) / 4);
    var chars = new char[digits + 1];
    chars[0] = (char)(0x60 + digits);
    for (var i = 0; i < digits; i++)
        chars[i + 1] = (char)(0x60 + ((value >> (i * 4)) & 0xF));
    return new string(chars);
}

static string EncodeBcFixed(ulong value, int width)
{
    var chars = new char[width];
    for (var i = 0; i < width; i++)
        chars[i] = (char)(0x60 + ((value >> (i * 4)) & 0xF));
    return new string(chars);
}

static string EncodeBcString(string value)
{
    var bytes = Encoding.UTF8.GetBytes(value + "\0");
    return "|" + EncodeBcNumber((ulong)bytes.Length) + new string(bytes.SelectMany(b => new[] { (char)(0x60 + (b & 0xF)), (char)(0x60 + (b >> 4)) }).ToArray());
}

static string BuildMinimalClamBc()
{
    var magic1 = 0x53e5493e9f3d1c30UL;
    var header = "ClamBC" + EncodeBcNumber(6) + EncodeBcNumber(0) + EncodeBcString("test") +
                 EncodeBcNumber(0) + EncodeBcNumber(0) + EncodeBcNumber(0) + EncodeBcNumber(0) + EncodeBcNumber(0) +
                 EncodeBcString("test") + EncodeBcNumber(0) + EncodeBcNumber(1) + EncodeBcNumber(magic1) + EncodeBcFixed(42, 2) + ":";
    var typeTable = "T" + EncodeBcFixed(69, 2);
    var apis = "E" + EncodeBcNumber(0) + EncodeBcNumber(0);
    var globals = "G" + EncodeBcNumber(0) + EncodeBcNumber(0);
    var function = "A" + EncodeBcFixed(0, 1) + EncodeBcNumber(1) + "L" + EncodeBcNumber(0) + "F" + EncodeBcNumber(1) + EncodeBcNumber(1);
    var block = "B" + EncodeBcNumber(1) + EncodeBcNumber(0) + EncodeBcFixed(20, 2);
    return string.Join("\n", new[] { header, "Test", typeTable, apis, globals, function, block, "S" });
}

static async Task ProductionSmokeAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "clamguard-production-smoke-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    var file = Path.Combine(root, "clean.bin");
    await File.WriteAllBytesAsync(file, "production-smoke"u8.ToArray());
    var dbDir = Path.Combine(root, "db");
    Directory.CreateDirectory(dbDir);
    File.WriteAllText(Path.Combine(dbDir, "smoke.hdb"), "cb81e7c4bf5847a951a1702052001022:15:Production.CleanProbe\n");
    var manager = new DatabaseManager();
    manager.LoadAndCompile(dbDir, true);
    var scanner = new ClamGuard.Scanner.ScannerEngine(manager);
    using var host = new ClamGuard.Production.ProductionScanHost(
        manager,
        scanner,
        new ClamGuard.Production.ProductionScanOptions { MaxConcurrentScans = 1, MaxQueuedScans = 2 });
    var result = await host.ScanAsync(file);
    Assert(result.Verdict == ScanVerdict.Clean, "production host clean scan");
    var metrics = host.GetMetrics();
    Assert(metrics.Started == 1 && metrics.Completed == 1 && metrics.Errors == 0, "production metrics accounting");
    var health = host.GetHealth();
    Assert(health.Healthy && health.SignatureCount == 1, "production health accepts loaded database");

    var slow = new SlowScanner(TimeSpan.FromMilliseconds(200));
    using var queueHost = new ClamGuard.Production.ProductionScanHost(
        manager,
        scanner,
        new ClamGuard.Production.ProductionScanOptions
        { MaxConcurrentScans = 1, MaxQueuedScans = 1, QueueWaitTimeout = TimeSpan.FromMilliseconds(25), ScanTimeout = TimeSpan.FromSeconds(2) });
    var slowOptions = new ScanOptions();
    slowOptions.ContentScanners.Add(slow);
    var firstScan = Task.Run(() => queueHost.ScanAsync(file, slowOptions));
    await slow.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
    var queueTimeout = await queueHost.ScanAsync(file);
    var firstResult = await firstScan;
    Assert(firstResult.Verdict == ScanVerdict.Clean, "production bounded scan completes while another request queues");
    Assert(queueTimeout.Verdict == ScanVerdict.Timeout, "production queue timeout is fail-closed");
    var queueMetrics = queueHost.GetMetrics();
    Assert(queueMetrics.QueueTimeouts == 1 && queueMetrics.Timeouts == 1, "production timeout accounting is not double-counted");

    File.Delete(file);
    Directory.Delete(root, true);
}

await ProductionSmokeAsync();

static async Task SpecializedHandlersSmokeAsync()
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
        Encoding.ASCII.GetBytes("HWP Document File V3.00\x1A\x01\x02\x03\x04\x05").CopyTo(hwp, 0);
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

await SpecializedHandlersSmokeAsync();


static async Task NativeSpecializedSmokeAsync()
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
        var xdp = $"<xdp><chunk>{Convert.ToBase64String(pdfPayload)}</chunk></xdp>";
        var xdpFile = Path.Combine(root, "embedded.xdp");
        await File.WriteAllTextAsync(xdpFile, xdp);
        var xdpResult = new ClamGuard.Scanner.ScannerEngine(xdpManager).Scan(xdpFile);
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
        var hwpml = "\uFEFF<?xml version=\"1.0\"?><hwpml><tail><bindatastorage><bindata Encoding=\"Base64\" Compress=\"false\">" +
                    Convert.ToBase64String(hwpmlPayload) + "</bindata></bindatastorage></tail></hwpml>";
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

await NativeSpecializedSmokeAsync();

static void SpecialDatabaseLoadSmoke()
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

SpecialDatabaseLoadSmoke();

static async Task ScanPipelineFileTypeSmokeAsync()
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

await ScanPipelineFileTypeSmokeAsync();

static byte[] BuildMinimalPe()
{
    var data = new byte[0x600];
    data[0] = (byte)'M'; data[1] = (byte)'Z';
    BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3c), 0x80);
    data[0x80] = (byte)'P'; data[0x81] = (byte)'E';
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x86), 1);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94), 0xE0);
    var opt = 0x98;
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(opt), 0x10B);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 16), 0x1000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 60), 0x200);
    var section = 0x178;
    ".text"u8.CopyTo(data.AsSpan(section));
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8), 4);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12), 0x1000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16), 4);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 20), 0x200);
    "ABCD"u8.CopyTo(data.AsSpan(0x200));
    data[0x204] = (byte)'E';
    return data;
}

static byte[] CreateZipEntry(string name, byte[] content)
{
    using var ms = new MemoryStream();
    using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
    {
        var entry = zip.CreateEntry(name, System.IO.Compression.CompressionLevel.NoCompression);
        using var output = entry.Open();
        output.Write(content);
    }
    return ms.ToArray();
}

static byte[] BuildPeWithImport(bool pe32Plus, string library = "KERNEL32.dll", string function = "CreateFileA")
{
    var optionalSize = pe32Plus ? 0xF0 : 0xE0;
    var section = 0x98 + optionalSize;
    var data = new byte[0x600];
    data[0] = (byte)'M'; data[1] = (byte)'Z';
    BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3c), 0x80);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x80), 0x00004550);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x84), pe32Plus ? (ushort)0x8664 : (ushort)0x14c);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x86), 1);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94), (ushort)optionalSize);
    var opt = 0x98;
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(opt), pe32Plus ? (ushort)0x20B : (ushort)0x10B);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 16), 0x1000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 32), 0x1000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 36), 0x200);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 56), 0x2000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 60), 0x200);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(opt + 92), 16);
    var dd = opt + (pe32Plus ? 112 : 96);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(dd + 8), 0x1100);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(dd + 12), 0x28);

    ".text"u8.CopyTo(data.AsSpan(section));
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 8), 0x400);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 12), 0x1000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16), 0x400);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 20), 0x200);

    // Import descriptor at RVA 0x1100 -> raw 0x300.
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x300), 0x1180);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x30C), 0x1160);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x310), 0x1190);
    // INT and IAT point to one IMAGE_IMPORT_BY_NAME record.
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x380), 0x1198);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x390), 0x1198);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x398), 0);
    Encoding.ASCII.GetBytes(function + "\0").CopyTo(data.AsSpan(0x39A));
    Encoding.ASCII.GetBytes(library + "\0").CopyTo(data.AsSpan(0x360));
    return data;
}

static byte[] CreateBinHex(string fileName, byte[] content)
{
    const string alphabet = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
    using var raw = new MemoryStream();
    var name = Encoding.ASCII.GetBytes(fileName);
    raw.WriteByte((byte)name.Length);
    raw.Write(name);
    raw.WriteByte(1); // BinHex file version byte
    raw.Write("TEXT"u8);
    raw.Write("ttxt"u8);
    raw.Write(new byte[2]);
    Span<byte> lengths = stackalloc byte[8];
    BinaryPrimitives.WriteUInt32BigEndian(lengths, (uint)content.Length);
    BinaryPrimitives.WriteUInt32BigEndian(lengths[4..], 0);
    raw.Write(lengths);
    raw.Write(new byte[2]);
    foreach (var b in content)
    {
        if (b == 0x90) { raw.WriteByte(0x90); raw.WriteByte(0); }
        else raw.WriteByte(b);
    }
    raw.Write(new byte[2]);
    raw.Write(new byte[2]);
    var bytes = raw.ToArray();
    using var encoded = new MemoryStream();
    uint acc = 0; var bits = 0;
    foreach (var b in bytes)
    {
        acc = (acc << 8) | b; bits += 8;
        while (bits >= 6)
        {
            bits -= 6;
            encoded.WriteByte((byte)alphabet[(int)((acc >> bits) & 0x3f)]);
        }
    }
    if (bits != 0) encoded.WriteByte((byte)alphabet[(int)((acc << (6 - bits)) & 0x3f)]);
    var prefix = Encoding.ASCII.GetBytes("(This file must be converted with BinHex 4.0)\r\n");
    var all = new MemoryStream(); all.Write(prefix); all.WriteByte((byte)':'); all.WriteByte((byte)'\r'); all.WriteByte((byte)'\n'); all.Write(encoded.ToArray()); all.WriteByte((byte)':'); all.WriteByte((byte)'\r'); all.WriteByte((byte)'\n');
    return all.ToArray();
}

static byte[] CreateUuEncoded(string fileName, byte[] content)
{
    using var ms = new MemoryStream();
    var begin = Encoding.ASCII.GetBytes($"begin 644 {fileName}\n");
    ms.Write(begin);
    Span<byte> quad = stackalloc byte[4];
    for (var offset = 0; offset < content.Length; offset += 45)
    {
        var count = Math.Min(45, content.Length - offset);
        ms.WriteByte((byte)(' ' + count));
        for (var i = 0; i < count; i += 3)
        {
            var remaining = Math.Min(3, count - i);
            var a = content[offset + i];
            var b = remaining > 1 ? content[offset + i + 1] : (byte)0;
            var c = remaining > 2 ? content[offset + i + 2] : (byte)0;
            quad[0] = (byte)(' ' + ((a >> 2) & 0x3f));
            quad[1] = (byte)(' ' + (((a << 4) | (b >> 4)) & 0x3f));
            quad[2] = (byte)(' ' + (((b << 2) | (c >> 6)) & 0x3f));
            quad[3] = (byte)(' ' + (c & 0x3f));
            ms.Write(quad);
        }
        ms.WriteByte((byte)'\n');
    }
    ms.Write(" \nend\n"u8);
    return ms.ToArray();
}

static byte[] CreateTnef(string fileName, byte[] content)
{
    using var ms = new MemoryStream();
    var u32 = new byte[4];
    BinaryPrimitives.WriteUInt32LittleEndian(u32, 0x223E9F78u); ms.Write(u32);
    var u16 = new byte[2];
    BinaryPrimitives.WriteUInt16LittleEndian(u16, 0x0100); ms.Write(u16);
    void Attr(byte level, ushort type, ushort tag, byte[] value)
    {
        ms.WriteByte(level);
        BinaryPrimitives.WriteUInt32LittleEndian(u32, ((uint)type << 16) | tag); ms.Write(u32);
        BinaryPrimitives.WriteInt32LittleEndian(u32, value.Length); ms.Write(u32);
        ms.Write(value);
        BinaryPrimitives.WriteUInt16LittleEndian(u16, 0); ms.Write(u16);
    }
    Attr(2, 1, 0x8010, Encoding.ASCII.GetBytes(fileName + "\0"));
    Attr(2, 2, 0x800f, content);
    return ms.ToArray();
}

static byte[] BuildIsoHeaderSample()
{
    var data = new byte[32774];
    data[32768] = 1;
    "CD001"u8.CopyTo(data.AsSpan(32769));
    data[32774 - 1] = 1;
    return data;
}

static byte[] BuildDmgTrailerSample()
{
    var data = new byte[1024];
    "koly"u8.CopyTo(data.AsSpan(512));
    return data;
}

static byte[] CreateTarEntry(string name, byte[] content)
{
    using var ms = new MemoryStream();
    var header = new byte[512];
    Encoding.ASCII.GetBytes(name).AsSpan().CopyTo(header.AsSpan(0, Math.Min(name.Length, 100)));
    Encoding.ASCII.GetBytes(Convert.ToString(0x1a4, 8).PadLeft(7, '0') + "\0").AsSpan().CopyTo(header.AsSpan(100, 8));
    Encoding.ASCII.GetBytes(Convert.ToString(content.Length, 8).PadLeft(11, '0') + "\0").AsSpan().CopyTo(header.AsSpan(124, 12));
    header[156] = (byte)'0';
    "ustar"u8.CopyTo(header.AsSpan(257));
    "00"u8.CopyTo(header.AsSpan(263));
    for (var i = 148; i < 156; i++) header[i] = (byte)' ';
    var checksum = header.Sum(static b => (int)b);
    Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8).PadLeft(6, '0') + " \0").AsSpan().CopyTo(header.AsSpan(148, 8));
    ms.Write(header);
    ms.Write(content);
    var pad = (512 - (content.Length % 512)) % 512;
    if (pad != 0) ms.Write(new byte[pad]);
    ms.Write(new byte[1024]);
    return ms.ToArray();
}

static byte[] CreateOldTarEntry(string name, byte[] content)
{
    var data = CreateTarEntry(name, content);
    var header = data.AsSpan(0, 512);
    header.Slice(257, 8).Clear();
    var checksum = 0;
    foreach (var b in header) checksum += b;
    Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8).PadLeft(6, '0') + " \0").AsSpan().CopyTo(header.Slice(148, 8));
    return data;
}

static byte[] CreateGzip(byte[] content)
{
    using var ms = new MemoryStream();
    using (var gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
        gzip.Write(content);
    return ms.ToArray();
}

static byte[] CreateCpioNewc(string name, byte[] content)
{
    static string Hex32(uint value) => value.ToString("x8");
    var fileName = Encoding.ASCII.GetBytes(name + "\0");
    using var ms = new MemoryStream();
    void Header(uint mode, uint size, uint nameSize)
    {
        var text = "070701" + Hex32(1) + Hex32(mode) + Hex32(0) + Hex32(0) + Hex32(1) + Hex32(0) + Hex32(size) +
                   Hex32(0) + Hex32(0) + Hex32(0) + Hex32(0) + Hex32(nameSize) + Hex32(0);
        ms.Write(Encoding.ASCII.GetBytes(text));
    }
    Header(0x81A4, (uint)content.Length, (uint)fileName.Length);
    ms.Write(fileName);
    while (ms.Length % 4 != 0) ms.WriteByte(0);
    ms.Write(content);
    while (ms.Length % 4 != 0) ms.WriteByte(0);
    var trailer = Encoding.ASCII.GetBytes("TRAILER!!!\0");
    Header(0, 0, (uint)trailer.Length);
    ms.Write(trailer);
    while (ms.Length % 4 != 0) ms.WriteByte(0);
    return ms.ToArray();
}

static byte[] CreateCpioOld(string name, byte[] content, bool littleEndian = true)
{
    using var ms = new MemoryStream();
    var nameBytes = Encoding.ASCII.GetBytes(name + "\0");
    void U16(ushort value)
    {
        Span<byte> b = stackalloc byte[2];
        if (littleEndian) BinaryPrimitives.WriteUInt16LittleEndian(b, value);
        else BinaryPrimitives.WriteUInt16BigEndian(b, value);
        ms.Write(b);
    }
    void U32(uint value)
    {
        Span<byte> b = stackalloc byte[4];
        if (littleEndian) BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        else BinaryPrimitives.WriteUInt32BigEndian(b, value);
        ms.Write(b);
    }
    U16(0x71C7);
    U16(0); U16(1); U16(0x81A4); U16(0); U16(0); U16(1); U16(0);
    U32(0); U16((ushort)nameBytes.Length); U32((uint)content.Length);
    ms.Write(nameBytes);
    if ((ms.Length & 1) != 0) ms.WriteByte(0);
    ms.Write(content);
    if ((ms.Length & 1) != 0) ms.WriteByte(0);
    U16(0x71C7);
    U16(0); U16(0); U16(0); U16(0); U16(0); U16(0); U16(0); U32(0);
    var trailer = Encoding.ASCII.GetBytes("TRAILER!!!\0");
    U16((ushort)trailer.Length); U32(0);
    ms.Write(trailer);
    if ((ms.Length & 1) != 0) ms.WriteByte(0);
    return ms.ToArray();
}

static byte[] CreatePdfAsciiHex(byte[] content)
{
    var hex = Encoding.ASCII.GetBytes(Convert.ToHexString(content) + ">");
    var prefix = Encoding.ASCII.GetBytes($"%PDF-1.7\n1 0 obj\n<< /Length {hex.Length} /Filter /ASCIIHexDecode >>\nstream\n");
    var suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n%%EOF\n");
    return prefix.Concat(hex).Concat(suffix).ToArray();
}

static bool TryNativeCompress(string executable, string extension, byte[] content, out byte[] archive)
{
    archive = [];
    var inputPath = Path.Combine(Path.GetTempPath(), "clamguard-test-" + Guid.NewGuid().ToString("N") + ".bin");
    try
    {
        File.WriteAllBytes(inputPath, content);
        var psi = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        if (executable.Equals("bzip2", StringComparison.OrdinalIgnoreCase) || executable.EndsWith("bzip2.exe", StringComparison.OrdinalIgnoreCase))
        {
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("--");
            psi.ArgumentList.Add(inputPath);
        }
        else
        {
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("--");
            psi.ArgumentList.Add(inputPath);
        }
        using var process = Process.Start(psi);
        if (process is null) return false;
        using var ms = new MemoryStream();
        process.StandardOutput.BaseStream.CopyTo(ms);
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) return false;
        archive = ms.ToArray();
        return archive.Length != 0;
    }
    catch
    {
        return false;
    }
    finally
    {
        try { File.Delete(inputPath); } catch { }
    }
}

static byte[] CreateCpioOdc(string name, byte[] content)
{
    static string Octal(int value, int width) => Convert.ToString(value, 8).PadLeft(width, '0');
    using var ms = new MemoryStream();
    var nameBytes = Encoding.ASCII.GetBytes(name + "\0");
    var fields = new[] {
        "070707", Octal(0, 6), Octal(1, 6), Octal(0x81A4, 6), Octal(0, 6), Octal(0, 6),
        Octal(1, 6), Octal(0, 6), Octal(0, 11), Octal(nameBytes.Length, 6), Octal(content.Length, 11) };
    ms.Write(Encoding.ASCII.GetBytes(string.Concat(fields)));
    ms.Write(nameBytes);
    if (ms.Length % 2 != 0) ms.WriteByte(0);
    ms.Write(content);
    if (ms.Length % 2 != 0) ms.WriteByte(0);
    var trailer = Encoding.ASCII.GetBytes(string.Concat(new[] {
        "070707", Octal(0, 6), Octal(0, 6), Octal(0, 6), Octal(0, 6), Octal(0, 6),
        Octal(0, 6), Octal(0, 6), Octal(0, 11), Octal(11, 6), Octal(0, 11) }));
    ms.Write(trailer);
    ms.Write(Encoding.ASCII.GetBytes("TRAILER!!!\0"));
    if (ms.Length % 2 != 0) ms.WriteByte(0);
    return ms.ToArray();
}

static byte[] CreatePdfFlate(byte[] content)
{
    using var compressed = new MemoryStream();
    using (var z = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
        z.Write(content);
    var c = compressed.ToArray();
    var prefix = Encoding.ASCII.GetBytes($"%PDF-1.7\n1 0 obj\n<< /Length {c.Length} /Filter /FlateDecode >>\nstream\n");
    var suffix = Encoding.ASCII.GetBytes("\nendstream\nendobj\n%%EOF\n");
    return prefix.Concat(c).Concat(suffix).ToArray();
}


static byte[] CreateCwsSwf(byte[] body)
{
    using var compressed = new MemoryStream();
    using (var z = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
        z.Write(body);
    using var ms = new MemoryStream();
    ms.Write("CWS"u8);
    ms.WriteByte(9);
    Span<byte> len = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)(body.Length + 8));
    ms.Write(len);
    ms.Write(compressed.ToArray());
    return ms.ToArray();
}

static byte[] BuildAutoItMarker()
{
    var magic = Convert.FromHexString("a3484bbe986c4aa9994c530a86d6487d41553321454130");
    return magic.Concat(new byte[] { 0x35 }).Concat("AUTOIT"u8.ToArray()).ToArray();
}

static byte[] BuildInstallShieldMarker()
{
    using var ms = new MemoryStream();
    ms.Write("InstallShield\0"u8);
    ms.Write(new byte[292]);
    ms.WriteByte(0x06);
    ms.Write(new byte[7]);
    ms.Write(new byte[16]);
    Span<byte> one = stackalloc byte[4];
    BinaryPrimitives.WriteUInt32LittleEndian(one, 1);
    ms.Write(one);
    return ms.ToArray();
}

static byte[] BuildMinimalSisHeader()
{
    var data = new byte[16];
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 0x10201A7A);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 0x10000419);
    return data;
}

static byte[] BuildMinimalSzddHeader()
{
    var data = new byte[14];
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 0x44445A53);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0x3327F088);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8), 0x0041);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(10), 1);
    return data;
}

static byte[] BuildMachOFat32TwoSlices()
{
    const int first = 0x40, second = 0x80, sliceSize = 0x40;
    var data = new byte[second + sliceSize];
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0), 0xCAFEBABE);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 2);

    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), 0x01000007);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), 3);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16), first);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20), sliceSize);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(24), 2);

    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(28), 0x0000000C);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(32), 0);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(36), second);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(40), sliceSize);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(44), 2);

    // Both entries are valid thin x86_64 Mach-O headers; only the second carries
    // the test signature.
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first), 0xFEEDFACF);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first + 4), 0x01000007);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first + 8), 3);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(first + 12), 2);

    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second), 0xFEEDFACF);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second + 4), 0x01000007);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second + 8), 3);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(second + 12), 2);
    new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }.AsSpan().CopyTo(data.AsSpan(second + 0x20, 4));
    return data;
}

static byte[] CreatePdfLzw(byte[] content)
{
    var codes = new List<int>(content.Length + 2) { 256 };
    codes.AddRange(content.Select(static b => (int)b));
    codes.Add(257);

    var output = new List<byte>();
    uint bitBuffer = 0;
    var bitCount = 0;
    foreach (var code in codes)
    {
        bitBuffer = (bitBuffer << 9) | (uint)code;
        bitCount += 9;
        while (bitCount >= 8)
        {
            bitCount -= 8;
            output.Add((byte)((bitBuffer >> bitCount) & 0xFF));
            bitBuffer &= bitCount == 0 ? 0u : (uint)((1UL << bitCount) - 1);
        }
    }
    if (bitCount != 0)
        output.Add((byte)(bitBuffer << (8 - bitCount)));

    using var ms = new MemoryStream();
    var dict = $"<< /Length {output.Count} /Filter /LZWDecode /DecodeParms << /EarlyChange 1 >> >>\nstream\n";
    ms.Write(Encoding.ASCII.GetBytes("%PDF-1.7\n"));
    ms.Write(Encoding.ASCII.GetBytes(dict));
    ms.Write(output.ToArray());
    ms.Write(Encoding.ASCII.GetBytes("\nendstream\n%%EOF\n"));
    return ms.ToArray();
}

static byte[] BuildMinimalElf32()
{
    var data = new byte[160];
    data[0] = 0x7f; data[1] = (byte)'E'; data[2] = (byte)'L'; data[3] = (byte)'F';
    data[4] = 1; data[5] = 1; data[6] = 1;
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(16), 2);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(18), 3);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), 1);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(24), 0x08048000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(28), 52);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), 84);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(40), 0);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(42), 32);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(44), 1);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(46), 40);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(48), 1);
    BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(50), 0);
    // PT_LOAD covering the file; entry virtual address resolves to raw offset 0.
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(52), 1);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(56), 0);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(60), 0x08048000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(64), 0x08048000);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(68), (uint)data.Length);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(72), (uint)data.Length);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(76), 5);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(80), 0x1000);
    return data;
}

static byte[] CreateMinimalOle2(byte[] content)
{
    const int sectorSize = 512;
    const int streamSectors = 8;
    var data = new byte[sectorSize + sectorSize * (2 + streamSectors + 1)];
    var header = data.AsSpan(0, 512);
    header[0] = 0xD0; header[1] = 0xCF; header[2] = 0x11; header[3] = 0xE0; header[4] = 0xA1; header[5] = 0xB1; header[6] = 0x1A; header[7] = 0xE1;
    BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(28, 2), 0xFFFE);
    BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(30, 2), 9);
    BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(32, 2), 6);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(40, 4), 0);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(44, 4), 1);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(48, 4), 1);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(56, 4), 4096);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(60, 4), 0xFFFFFFFE);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(64, 4), 0);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(68, 4), 0xFFFFFFFE);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(72, 4), 0);
    for (var i = 0; i < 109; i++) BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(76 + i * 4, 4), 0xFFFFFFFF);
    BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(76, 4), 0);

    var dir = data.AsSpan(512, 512);
    WriteOleDirEntry(dir.Slice(0, 128), "Root Entry", 5, 0xFFFFFFFF, 0);
    WriteOleDirEntry(dir.Slice(128, 128), "Payload", 2, 2, 4096);

    var fat = data.AsSpan(512 + (2 + streamSectors) * sectorSize, sectorSize);
    for (var i = 0; i < 128; i++) BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(i * 4, 4), 0xFFFFFFFF);
    BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(0, 4), 0xFFFFFFFD); // FAT sector 0
    BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice(1 * 4, 4), 0xFFFFFFFE); // directory sector 1
    for (var i = 0; i < streamSectors; i++)
        BinaryPrimitives.WriteUInt32LittleEndian(fat.Slice((2 + i) * 4, 4), i + 2 == 2 + streamSectors - 1 ? 0xFFFFFFFEu : (uint)(3 + i));

    var stream = data.AsSpan(512 + 2 * sectorSize, streamSectors * sectorSize);
    content.AsSpan(0, Math.Min(content.Length, stream.Length)).CopyTo(stream);
    return data;

    static void WriteOleDirEntry(Span<byte> entry, string name, byte objectType, uint startSector, ulong size)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name + "\0");
        nameBytes.AsSpan(0, Math.Min(nameBytes.Length, 64)).CopyTo(entry);
        BinaryPrimitives.WriteUInt16LittleEndian(entry.Slice(64, 2), (ushort)Math.Min(64, nameBytes.Length));
        entry[66] = objectType;
        BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(68, 4), 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(72, 4), 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(76, 4), objectType == 5 ? 0xFFFFFFFFu : 0xFFFFFFFFu);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.Slice(116, 4), startSector);
        BinaryPrimitives.WriteUInt64LittleEndian(entry.Slice(120, 8), size);
    }
}

static byte[] BuildMachO64WithSection()
{
    const int loadCommandSize = 152;
    const int sectionOffset = 0x200;
    var data = new byte[0x300];
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0), 0xFEEDFACF);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0x01000007);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 3);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(12), 2);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), 1);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), loadCommandSize);
    // LC_SEGMENT_64
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(32), 0x19);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(36), loadCommandSize);
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(56), 0);
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(64), 0x1000);
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(72), 0x100);
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(80), sectionOffset);
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(88), 4);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(96), 7);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(100), 5);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(104), 1);
    var section = 32 + 72;
    "__text"u8.CopyTo(data.AsSpan(section));
    "__TEXT"u8.CopyTo(data.AsSpan(section + 16));
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(section + 32), 0x1000);
    BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(section + 40), 4);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 48), sectionOffset);
    "MACH"u8.CopyTo(data.AsSpan(sectionOffset));
    return data;
}

static byte[] BuildMachOFat32()
{
    var data = new byte[0x40];
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0), 0xCAFEBABE);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 1);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), 0x01000007);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), 3);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16), 0x20);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(20), 0x20);
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(24), 2);
    // Thin x86_64 Mach-O header at 0x20.
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x20), 0xFEEDFACF);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x24), 0x01000007);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x28), 3);
    BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x2C), 2);
    return data;
}

var pattern = HexPatternParser.Parse("68656c6c6f");
Assert(pattern.Matches("hello"u8, 0, out _), "fixed hexadecimal pattern matches");

var wildcard = HexPatternParser.Parse("68????6f");
Assert(wildcard.Matches("hello"u8, 0, out _), "byte wildcard pattern matches");

var range = HexPatternParser.Parse("68{1-3}6f");
Assert(range.Matches("heXXllo"u8, 0, out _), "bounded gap matches");

var temp = Path.Combine(Path.GetTempPath(), "clamguard-demo.hdb");
File.WriteAllText(temp, "5d41402abc4b2a76b9719d911017c592:5:Demo.HelloWorld\n");
var signatures = SignatureParser.ParseHashFile(temp).ToArray();
Assert(signatures.Length == 1 && signatures[0].Algorithm == HashAlgorithmKind.Md5, "HDB parser recognizes MD5");

var header = CvdReader.ParseHeader("ClamAV-VDB:Thu Jan 01 00:00:00 2026:42:123:150:abc:def:builder:1767225600");
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
Console.WriteLine("All tests passed.");

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
var rangeHits = compiled.Match("heXXllo"u8, "test.db");
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

// HandlerType must perform a full child-layer rescan, not only an LDB pass.
var handlerTypePath = Path.Combine(Path.GetTempPath(), "clamguard-handler-type.ldb");
File.WriteAllText(handlerTypePath,
    "Handler.Rescan;Engine:81-255,Target:0,HandlerType:PE;0;4141\n");
var handlerTypeDir = Path.Combine(Path.GetTempPath(), "clamguard-handler-type-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(handlerTypeDir);
File.Copy(handlerTypePath, Path.Combine(handlerTypeDir, "handler.ldb"));
File.WriteAllText(Path.Combine(handlerTypeDir, "child.ndb"),
    "Handler.RescannedPE:1:0:*:4d5a\n");
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
    "MacroA:0:$12:626262\n" +
    "MacroB:0:$12:636363\n");
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
Assert(ndbParsed.Length == 4 && ndbParsed.All(x => x.Target is 0 or 1), "NDB parser accepts target, range, EOF and FLEVEL fields");
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
var ndbAbsoluteResult = ndbScanner.Scan(ndbAbsoluteFile);
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
var ignManager = new DatabaseManager();
ignManager.LoadAndCompile(ignDbDir, true);
var ignScanner = new ClamGuard.Scanner.ScannerEngine(ignManager);
var ignFile = Path.Combine(Path.GetTempPath(), "clamguard-ign-scan.bin");
File.WriteAllBytes(ignFile, "xxAByy"u8.ToArray());
var ignResult = ignScanner.Scan(ignFile);
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
File.WriteAllBytes(unknownOtherFile, new byte[] { 0x00, 0x01, 0x02, 0x03, 0xAA });
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
var ndbPeResult = ndbScanner.Scan(ndbPeFile);
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
var htmlFile = Path.Combine(Path.GetTempPath(), "sample-normalized.html");
File.WriteAllText(htmlFile, "<HTML>\n<!-- remove me -->\n<BODY> HeLLo </BODY>\n</HTML>");
var htmlResult = normalizedScanner.Scan(htmlFile);
Assert(htmlResult.Detections.Any(x => x.Name == "Ndb.HtmlNormalized"), "NDB HTML target matches normalized HTML content");
var asciiFile = Path.Combine(Path.GetTempPath(), "sample-normalized.txt");
File.WriteAllText(asciiFile, "  HeLLo\tWORLD  ");
var asciiResult = normalizedScanner.Scan(asciiFile);
Assert(asciiResult.Detections.Any(x => x.Name == "Ndb.AsciiNormalized"), "NDB ASCII target matches normalized text content");

// LDB container semantics: CL_TYPE_ANY is root-only; Intermediates are top-down with the last layer immediate.
var containerLdbPath = Path.Combine(Path.GetTempPath(), "clamguard-container.ldb");
File.WriteAllText(containerLdbPath,
    "Ldb.RootOnly;Engine:81-255,Target:0,Container:CL_TYPE_ANY;0;524f4f54\n" +
    "Ldb.ZipChild;Engine:81-255,Target:0,Container:CL_TYPE_ZIP;0;5a49504348494c44\n" +
    "Ldb.Nested;Engine:81-255,Target:0,Intermediates:CL_TYPE_ZIP>CL_TYPE_ZIP;0;4e4553544544\n");
var containerDbDir = Path.Combine(Path.GetTempPath(), "clamguard-container-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(containerDbDir);
File.Copy(containerLdbPath, Path.Combine(containerDbDir, "container.ldb"));
var containerManager = new DatabaseManager();
containerManager.LoadAndCompile(containerDbDir, true);
var containerScanner = new ClamGuard.Scanner.ScannerEngine(containerManager);
var rootFile = Path.Combine(Path.GetTempPath(), "container-root.bin");
File.WriteAllBytes(rootFile, "ROOT"u8.ToArray());
Assert(containerScanner.Scan(rootFile).Detections.Any(x => x.Name == "Ldb.RootOnly"), "LDB Container:ANY matches root objects");
var directZip = Path.Combine(Path.GetTempPath(), "container-direct.zip");
File.WriteAllBytes(directZip, CreateZipEntry("child.bin", "ZIPCHILD"u8.ToArray()));
var directZipResult = containerScanner.Scan(directZip);
Assert(directZipResult.Detections.Any(x => x.Name == "Ldb.ZipChild"), "LDB concrete Container matches the immediate ZIP parent");
Assert(!directZipResult.Detections.Any(x => x.Name == "Ldb.RootOnly"), "LDB Container:ANY does not match files inside a container");
var innerZip = CreateZipEntry("nested.bin", "NESTED"u8.ToArray());
var outerZip = Path.Combine(Path.GetTempPath(), "container-nested.zip");
File.WriteAllBytes(outerZip, CreateZipEntry("inner.zip", innerZip));
var nestedZipResult = containerScanner.Scan(outerZip);
Assert(nestedZipResult.Detections.Any(x => x.Name == "Ldb.Nested"), "LDB Intermediates matches the requested inner container chain");

// LDB executable-relative offsets and section boundaries.
var sectionLdbPath = Path.Combine(Path.GetTempPath(), "clamguard-section.ldb");
File.WriteAllText(sectionLdbPath,
    "Ldb.SectionExact;Engine:81-255,Target:1;0;SE0:41424344\n" +
    "Ldb.SectionCross;Engine:81-255,Target:1;0;SE0:4142434445\n" +
    "Ldb.EntryPoint;Engine:81-255,Target:1;0;EP+0:41424344\n");
var sectionDbDir = Path.Combine(Path.GetTempPath(), "clamguard-section-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(sectionDbDir);
File.Copy(sectionLdbPath, Path.Combine(sectionDbDir, "section.ldb"));
var sectionManager = new DatabaseManager();
sectionManager.LoadAndCompile(sectionDbDir, true);
var sectionScanner = new ClamGuard.Scanner.ScannerEngine(sectionManager);
var peFile = Path.Combine(Path.GetTempPath(), "section-test.exe");
File.WriteAllBytes(peFile, BuildMinimalPe());
var peResult = sectionScanner.Scan(peFile);
Assert(peResult.Detections.Any(x => x.Name == "Ldb.SectionExact"), "LDB SEx matches content inside the PE section");
Assert(!peResult.Detections.Any(x => x.Name == "Ldb.SectionCross"), "LDB SEx does not allow a pattern to cross the section boundary");
Assert(peResult.Detections.Any(x => x.Name == "Ldb.EntryPoint"), "LDB PE entry-point relative offset resolves to the raw file location");

// ClamAV-style PE overlay scanning and SFX container aliases.
var overlayDbDir = Path.Combine(Path.GetTempPath(), "clamguard-overlay-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(overlayDbDir);
File.WriteAllText(Path.Combine(overlayDbDir, "overlay.ldb"),
    "PE.Overlay;Engine:81-255,Target:0,Container:CL_TYPE_PE;0;4f564c484954\n" +
    "PE.ZipSfx;Engine:81-255,Target:0,Container:CL_TYPE_ZIPSFX;0;535846484954\n");
var overlayManager = new DatabaseManager();
overlayManager.LoadAndCompile(overlayDbDir, true);
var overlayScanner = new ClamGuard.Scanner.ScannerEngine(overlayManager);
var peBase = BuildMinimalPe().AsSpan(0, 0x204).ToArray();
var overlayPe = peBase.Concat("OVLHIT"u8.ToArray()).ToArray();
var overlayPath = Path.Combine(Path.GetTempPath(), "pe-overlay.bin");
File.WriteAllBytes(overlayPath, overlayPe);
Assert(overlayScanner.Scan(overlayPath).Detections.Any(x => x.Name == "PE.Overlay"), "PE overlay is scanned as an embedded layer");
var sfxPayload = CreateZipEntry("sfx.bin", "SXFHIT"u8.ToArray());
var sfxPe = peBase.Concat(sfxPayload).ToArray();
var sfxPath = Path.Combine(Path.GetTempPath(), "pe-zipsfx.bin");
File.WriteAllBytes(sfxPath, sfxPe);
Assert(overlayScanner.Scan(sfxPath).Detections.Any(x => x.Name == "PE.ZipSfx"), "PE ZIP overlay preserves ZIPSFX compatibility alias");

var normalizedLdbPath = Path.Combine(Path.GetTempPath(), "clamguard-normalized.ldb");
File.WriteAllText(normalizedLdbPath,
    "Ldb.HtmlNormalized;Engine:81-255,Target:3;0;68656c6c6f\n" +
    "Ldb.AsciiNormalized;Engine:81-255,Target:7;0;68656c6c6f\n");
var normalizedLdbDir = Path.Combine(Path.GetTempPath(), "clamguard-normalized-ldb-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(normalizedLdbDir);
File.Copy(normalizedLdbPath, Path.Combine(normalizedLdbDir, "normalized.ldb"));
var normalizedLdbManager = new DatabaseManager();
normalizedLdbManager.LoadAndCompile(normalizedLdbDir, true);
var normalizedLdbScanner = new ClamGuard.Scanner.ScannerEngine(normalizedLdbManager);
Assert(normalizedLdbScanner.Scan(htmlFile).Detections.Any(x => x.Name == "Ldb.HtmlNormalized"), "LDB HTML target matches normalized HTML content");
Assert(normalizedLdbScanner.Scan(asciiFile).Detections.Any(x => x.Name == "Ldb.AsciiNormalized"), "LDB ASCII target matches normalized text content");

// Archive children must use the same type detector as root scans so NDB/LDB target-aware
// signatures such as GRAPHICS (target 5) are not skipped for extensionless entries.
var graphicsNdbDir = Path.Combine(Path.GetTempPath(), "clamguard-graphics-child-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(graphicsNdbDir);
File.WriteAllText(Path.Combine(graphicsNdbDir, "graphics-child.ndb"),
    "Ndb.GraphicsChild:5:*:89504e470d0a1a0a\n");
var graphicsChildManager = new DatabaseManager();
graphicsChildManager.LoadAndCompile(graphicsNdbDir, true);
var graphicsChildScanner = new ClamGuard.Scanner.ScannerEngine(graphicsChildManager);
var pngChild = new byte[32];
"\x89PNG\x1A\x0A"u8.CopyTo(pngChild.AsSpan());
var graphicsZipPath = Path.Combine(Path.GetTempPath(), "graphics-child.zip");
File.WriteAllBytes(graphicsZipPath, CreateZipEntry("blob.bin", pngChild));
var graphicsChildResult = graphicsChildScanner.Scan(graphicsZipPath);
Assert(graphicsChildResult.Detections.Any(x => x.Name == "Ndb.GraphicsChild"),
    "Archive child uses shared type detection for NDB GRAPHICS target");
var utf16HtmlPath = Path.Combine(Path.GetTempPath(), "sample-normalized-utf16.html");
File.WriteAllBytes(utf16HtmlPath, Encoding.Unicode.GetBytes("\uFEFF<html><body>Hello</body></html>"));
Assert(normalizedLdbScanner.Scan(utf16HtmlPath).FileType == "HTML_UTF16" || normalizedLdbScanner.Scan(utf16HtmlPath).Detections.Any(x => x.Name == "Ldb.HtmlNormalized"), "HTML UTF-16 is decoded for normalized-target matching");

// LDB PCRE rolling/global/encompass semantics and future-trigger rejection.
var advancedRegexPath = Path.Combine(Path.GetTempPath(), "clamguard-regex-advanced.ldb");
File.WriteAllText(advancedRegexPath,
    "Ldb.Rolling;Engine:81-255,Target:0;0&1;7878;0:0/abc/r\n" +
    "Ldb.Global;Engine:81-255,Target:0;0&1=3;61;0:0/a/g\n" +
    "Ldb.Encompass;Engine:81-255,Target:0;0&1;61;1,2:0/abc/ge\n" +
    "Ldb.FutureTrigger;Engine:81-255,Target:0;0&1;61;0:1/a/\n");
var advancedRegexDbDir = Path.Combine(Path.GetTempPath(), "clamguard-regex-advanced-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(advancedRegexDbDir);
File.Copy(advancedRegexPath, Path.Combine(advancedRegexDbDir, "advanced.ldb"));
var advancedRegexManager = new DatabaseManager();
advancedRegexManager.LoadAndCompile(advancedRegexDbDir, true);
var advancedRegexScanner = new ClamGuard.Scanner.ScannerEngine(advancedRegexManager);
var rollingFile = Path.Combine(Path.GetTempPath(), "regex-rolling.bin");
File.WriteAllBytes(rollingFile, "xxabc"u8.ToArray());
Assert(advancedRegexScanner.Scan(rollingFile).Detections.Any(x => x.Name == "Ldb.Rolling"), "LDB PCRE rolling flag searches past the starting offset");
var globalFile = Path.Combine(Path.GetTempPath(), "regex-global.bin");
File.WriteAllBytes(globalFile, "aaa"u8.ToArray());
Assert(advancedRegexScanner.Scan(globalFile).Detections.Any(x => x.Name == "Ldb.Global"), "LDB PCRE global flag counts all matches");
var encompassFile = Path.Combine(Path.GetTempPath(), "regex-encompass.bin");
File.WriteAllBytes(encompassFile, "xabc"u8.ToArray());
Assert(!advancedRegexScanner.Scan(encompassFile).Detections.Any(x => x.Name == "Ldb.Encompass"), "LDB PCRE encompass flag confines matches to the max-shift range");
Assert(!advancedRegexScanner.Scan(globalFile).Detections.Any(x => x.Name == "Ldb.FutureTrigger"), "LDB PCRE triggers cannot reference later subsignatures");


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
var pe32Result = peHashScanner.Scan(pe32Path);
var pe64Result = peHashScanner.Scan(pe64Path);
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

// Archive/document extraction: TAR -> GZIP -> CPIO and PDF filters.
var archiveDbDir = Path.Combine(Path.GetTempPath(), "clamguard-archive-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(archiveDbDir);
File.WriteAllText(Path.Combine(archiveDbDir, "archives.ldb"),
    "Archive.Tar;Engine:81-255,Target:0,Container:CL_TYPE_TAR;0;5441524348495645\n" +
    "Archive.Nested;Engine:81-255,Target:0,Intermediates:CL_TYPE_GZ>CL_TYPE_TAR;0;4e4553544544\n" +
    "Archive.Cpio;Engine:81-255,Target:0,Container:CL_TYPE_CPIO_NEWC;0;4350494f484954\n" +
    "Archive.CpioOdc;Engine:81-255,Target:0,Container:CL_TYPE_CPIO_ODC;0;4f4443484954\n" +
    "Archive.CpioOld;Engine:81-255,Target:0,Container:CL_TYPE_CPIO_OLD;0;4f4c44484954\n" +
    "Archive.Ole;Engine:81-255,Target:0,Container:CL_TYPE_OLE2;0;4f4c45484954\n" +
    "Archive.BinHex;Engine:81-255,Target:0,Container:CL_TYPE_BINHEX;0;42494e484954\n" +
    "Archive.UuEncode;Engine:81-255,Target:0,Container:CL_TYPE_UUENCODED;0;5555484954\n" +
    "Archive.Tnef;Engine:81-255,Target:0,Container:CL_TYPE_TNEF;0;544e4546484954\n" +
    "Archive.PdfFlate;Engine:81-255,Target:0;0;504446464c415445\n" +
    "Archive.PdfAsciiHex;Engine:81-255,Target:0;0;5044464845584854\n" +
    "Archive.Bz2Nested;Engine:81-255,Target:0,Intermediates:CL_TYPE_BZ>CL_TYPE_TAR;0;425a32484954\n" +
    "Archive.XzNested;Engine:81-255,Target:0,Intermediates:CL_TYPE_XZ>CL_TYPE_TAR;0;585a32484954\n");
var archiveManager = new DatabaseManager();
archiveManager.LoadAndCompile(archiveDbDir, true);
var archiveScanner = new ClamGuard.Scanner.ScannerEngine(archiveManager);
var tarPath = Path.Combine(Path.GetTempPath(), "sample.tar");
File.WriteAllBytes(tarPath, CreateTarEntry("sample.bin", "ARCHIVE"u8.ToArray()));
Assert(archiveScanner.Scan(tarPath).Detections.Any(x => x.Name == "Archive.Tar"), "TAR entry scanning honors the immediate parent container");
var oldTarPath = Path.Combine(Path.GetTempPath(), "sample-old.tar");
File.WriteAllBytes(oldTarPath, CreateOldTarEntry("old.bin", "ARCHIVE"u8.ToArray()));
Assert(archiveScanner.Scan(oldTarPath).Detections.Any(x => x.Name == "Archive.Tar"), "old-style TAR header detection is checksum-validated");
var nestedTar = CreateTarEntry("nested.bin", "NESTED"u8.ToArray());
var gzTarPath = Path.Combine(Path.GetTempPath(), "sample.tar.gz");
File.WriteAllBytes(gzTarPath, CreateGzip(nestedTar));
Assert(archiveScanner.Scan(gzTarPath).Detections.Any(x => x.Name == "Archive.Nested"), "GZIP-wrapped TAR preserves the intermediate container chain");
var cpioPath = Path.Combine(Path.GetTempPath(), "sample.cpio");
File.WriteAllBytes(cpioPath, CreateCpioNewc("sample.bin", "CPIOHIT"u8.ToArray()));
Assert(archiveScanner.Scan(cpioPath).Detections.Any(x => x.Name == "Archive.Cpio"), "CPIO newc entry scanning extracts regular files");
var cpioOdcPath = Path.Combine(Path.GetTempPath(), "sample-odc.cpio");
File.WriteAllBytes(cpioOdcPath, CreateCpioOdc("sample.bin", "ODCHIT"u8.ToArray()));
Assert(archiveScanner.Scan(cpioOdcPath).Detections.Any(x => x.Name == "Archive.CpioOdc"), "CPIO ODC entry scanning extracts regular files");
var cpioOldPath = Path.Combine(Path.GetTempPath(), "sample-old.cpio");
File.WriteAllBytes(cpioOldPath, CreateCpioOld("sample.bin", "OLDHIT"u8.ToArray()));
Assert(archiveScanner.Scan(cpioOldPath).Detections.Any(x => x.Name == "Archive.CpioOld"), "CPIO old-endian binary entry scanning extracts regular files");
var olePath = Path.Combine(Path.GetTempPath(), "sample.ole");
File.WriteAllBytes(olePath, CreateMinimalOle2("OLEHIT"u8.ToArray()));
Assert(archiveScanner.Scan(olePath).Detections.Any(x => x.Name == "Archive.Ole"), "OLE2 regular stream extraction scans embedded payloads");

// CDB archive-handler parity: ClamAV 1.5.4 calls cli_matchmeta() from
// ZIP/RAR/ARJ/EGG plus TAR/CPIO handlers, but not the OLE2 handler.
var cdbArchiveDbDir = Path.Combine(Path.GetTempPath(), "clamguard-cdb-archive-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(cdbArchiveDbDir);
File.WriteAllText(Path.Combine(cdbArchiveDbDir, "archive.cdb"),
    "Cdb.Archive.Tar:CL_TYPE_POSIX_TAR:*:^sample\\.bin$:7:7:0:1:*:*\n" +
    "Cdb.Archive.OldTar:CL_TYPE_OLD_TAR:*:^old\\.bin$:7:7:0:1:*:*\n" +
    "Cdb.Archive.Cpio:CL_TYPE_CPIO_NEWC:*:^sample\\.bin$:7:7:0:1:*:*\n" +
    "Cdb.Archive.CpioOdc:CL_TYPE_CPIO_ODC:*:^sample\\.bin$:6:6:0:1:*:*\n" +
    "Cdb.Archive.CpioOld:CL_TYPE_CPIO_OLD:*:^sample\\.bin$:7:7:0:1:*:*\n" +
    "Cdb.Archive.OleMustNotMatch:CL_TYPE_MSOLE2:*:^Payload$:4096:4096:0:2:*:*\n");
var cdbArchiveManager = new DatabaseManager();
cdbArchiveManager.LoadAndCompile(cdbArchiveDbDir, true);
var cdbArchiveScanner = new ClamGuard.Scanner.ScannerEngine(cdbArchiveManager);
Assert(cdbArchiveScanner.Scan(tarPath, new ScanOptions { CollectAllMatches = true }).Detections.Any(x => x.Name == "Cdb.Archive.Tar"),
    "CDB matches POSIX TAR metadata through the native tar-handler contract");
Assert(cdbArchiveScanner.Scan(oldTarPath, new ScanOptions { CollectAllMatches = true }).Detections.Any(x => x.Name == "Cdb.Archive.OldTar"),
    "CDB matches OLD TAR metadata through the native tar-handler contract");
Assert(cdbArchiveScanner.Scan(cpioPath, new ScanOptions { CollectAllMatches = true }).Detections.Any(x => x.Name == "Cdb.Archive.Cpio"),
    "CDB matches CPIO newc metadata through the native cpio-handler contract");
Assert(cdbArchiveScanner.Scan(cpioOdcPath, new ScanOptions { CollectAllMatches = true }).Detections.Any(x => x.Name == "Cdb.Archive.CpioOdc"),
    "CDB matches CPIO ODC metadata through the native cpio-handler contract");
Assert(cdbArchiveScanner.Scan(cpioOldPath, new ScanOptions { CollectAllMatches = true }).Detections.Any(x => x.Name == "Cdb.Archive.CpioOld"),
    "CDB matches CPIO old metadata through the native cpio-handler contract");
Assert(!cdbArchiveScanner.Scan(olePath, new ScanOptions { CollectAllMatches = true }).Detections.Any(x => x.Name == "Cdb.Archive.OleMustNotMatch"),
    "CDB does not run for OLE2 because ClamAV 1.5.4 does not call cli_matchmeta() there");
Directory.Delete(cdbArchiveDbDir, true);

var pdfPath = Path.Combine(Path.GetTempPath(), "sample-flate.pdf");
File.WriteAllBytes(pdfPath, CreatePdfFlate("PDFFLATE"u8.ToArray()));
Assert(archiveScanner.Scan(pdfPath).Detections.Any(x => x.Name == "Archive.PdfFlate"), "PDF FlateDecode embedded-stream scanning detects decompressed content");
var pdfHexPath = Path.Combine(Path.GetTempPath(), "sample-hex.pdf");
File.WriteAllBytes(pdfHexPath, CreatePdfAsciiHex("PDFHEXHT"u8.ToArray()));
Assert(archiveScanner.Scan(pdfHexPath).Detections.Any(x => x.Name == "Archive.PdfAsciiHex"), "PDF ASCIIHexDecode embedded-stream scanning detects decoded content");

var binHexPath = Path.Combine(Path.GetTempPath(), "sample.hqx");
File.WriteAllBytes(binHexPath, CreateBinHex("sample.bin", "BINHIT"u8.ToArray()));
Assert(archiveScanner.Scan(binHexPath).Detections.Any(x => x.Name == "Archive.BinHex"), "BinHex data-fork extraction scans embedded payloads");
File.Delete(binHexPath);

var uuPath = Path.Combine(Path.GetTempPath(), "sample.uue");
File.WriteAllBytes(uuPath, CreateUuEncoded("sample.bin", "UUHIT"u8.ToArray()));
Assert(archiveScanner.Scan(uuPath).Detections.Any(x => x.Name == "Archive.UuEncode"), "UUEncode extraction scans embedded payloads");
File.Delete(uuPath);

var tnefPath = Path.Combine(Path.GetTempPath(), "winmail.dat");
File.WriteAllBytes(tnefPath, CreateTnef("sample.bin", "TNEFHIT"u8.ToArray()));
Assert(archiveScanner.Scan(tnefPath).Detections.Any(x => x.Name == "Archive.Tnef"), "TNEF attachment extraction scans embedded payloads");
File.Delete(tnefPath);

var mimeDbDir = Path.Combine(Path.GetTempPath(), "clamguard-mime-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(mimeDbDir);
File.WriteAllText(Path.Combine(mimeDbDir, "mime.ldb"),
    "Archive.Mhtml;Engine:81-255,Target:0,Container:CL_TYPE_MHTML;0;4d48544c484954\n" +
    "Archive.Mail;Engine:81-255,Target:0,Container:CL_TYPE_MAIL;0;4d41494c484954\n");
var mimeManager = new DatabaseManager();
mimeManager.LoadAndCompile(mimeDbDir, true);
var mimeScanner = new ClamGuard.Scanner.ScannerEngine(mimeManager);
var mhtmlPath = Path.Combine(Path.GetTempPath(), "sample.mhtml");
var mhtml = "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=abc123\r\n\r\n" +
             "--abc123\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nTUhUTEhJVA==\r\n--abc123--\r\n";
File.WriteAllText(mhtmlPath, mhtml, Encoding.ASCII);
Assert(mimeScanner.Scan(mhtmlPath).FileType == "MHTML", "MHTML multipart type detection is recognized");
Assert(mimeScanner.Scan(mhtmlPath).Detections.Any(x => x.Name == "Archive.Mhtml"), "MHTML multipart Base64 parts are extracted and scanned");
var emlPath = Path.Combine(Path.GetTempPath(), "sample.eml");
var eml = "From: sender@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=mail123\r\n\r\n" +
          "--mail123\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nMA=49=4CHIT\r\n--mail123--\r\n";
File.WriteAllText(emlPath, eml, Encoding.ASCII);
Assert(mimeScanner.Scan(emlPath).FileType == "MAIL", "mail MIME type detection is recognized");
Assert(mimeScanner.Scan(emlPath).Detections.Any(x => x.Name == "Archive.Mail"), "MAIL quoted-printable parts are extracted and scanned");

var swfDbDir = Path.Combine(Path.GetTempPath(), "clamguard-swf-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(swfDbDir);
File.WriteAllText(Path.Combine(swfDbDir, "swf.ldb"), "Archive.SwfCws;Engine:81-255,Target:11;0;535746484954\n");
var swfManager = new DatabaseManager();
swfManager.LoadAndCompile(swfDbDir, true);
var swfScanner = new ClamGuard.Scanner.ScannerEngine(swfManager);
var swfPath = Path.Combine(Path.GetTempPath(), "sample.swf");
File.WriteAllBytes(swfPath, CreateCwsSwf("SWFHIT"u8.ToArray()));
Assert(swfScanner.Scan(swfPath).FileType == "FLASH", "SWF file type detection recognizes FWS/CWS/ZWS headers");
Assert(swfScanner.Scan(swfPath).Detections.Any(x => x.Name == "Archive.SwfCws"), "CWS SWF payload is decompressed and scanned");

var specialTypeSamples = new (string Name, byte[] Data, string ExpectedType)[]
{
    ("sample.autoit", BuildAutoItMarker(), "AUTOIT"),
    ("sample.ish", BuildInstallShieldMarker(), "ISHIELD_MSI"),
    ("sample.udf", Enumerable.Repeat((byte)0, 32770).Append((byte)'B').Append((byte)'E').Append((byte)'A').Append((byte)'0').Append((byte)'1').ToArray(), "UDF")
};
foreach (var sample in specialTypeSamples)
{
    var samplePath = Path.Combine(Path.GetTempPath(), sample.Name);
    File.WriteAllBytes(samplePath, sample.Data);
    Assert(swfScanner.Scan(samplePath).FileType == sample.ExpectedType, $"ClamAV specialized type detection routes {sample.ExpectedType}");
    File.Delete(samplePath);
}

// Extended archive-family routing. Extraction is delegated only when a compatible
// 7-Zip build is present; without it the file still receives a deterministic type hint.
var extendedArchiveSamples = new (string Name, byte[] Data, string ExpectedType)[]
{
    ("sample.arj", [0x60, 0xEA], "ARJ"),
    ("sample.cab", "MSCF"u8.ToArray(), "CAB"),
    ("sample.chm", "ITSF"u8.ToArray(), "CHM"),
    ("sample.xar", "xar!"u8.ToArray(), "XAR"),
    ("sample.iso", BuildIsoHeaderSample(), "ISO"),
    ("sample.dmg", BuildDmgTrailerSample(), "DMG"),
    ("sample.lzh", [0, 0, 0x2d, 0x6c, 0x68, 0x35, 0x2d], "LHA")
};
foreach (var sample in extendedArchiveSamples)
{
    var samplePath = Path.Combine(Path.GetTempPath(), sample.Name);
    File.WriteAllBytes(samplePath, sample.Data);
    Assert(archiveScanner.Scan(samplePath).FileType == sample.ExpectedType, $"Extended archive type detection routes {sample.ExpectedType}");
    File.Delete(samplePath);
}

// Container markers must still be detected when the filename provides no extension.
// ISO/UDF signatures can sit around the 32 KiB boundary, while DMG stores "koly" in
// the final 512-byte trailer. These classifications control whether full container
// expansion is attempted by ScannerEngine.
var extensionlessIsoPath = Path.Combine(Path.GetTempPath(), "clamguard-extensionless-iso");
File.WriteAllBytes(extensionlessIsoPath, BuildIsoHeaderSample());
Assert(archiveScanner.Scan(extensionlessIsoPath).FileType == "ISO", "extensionless ISO marker is detected before container expansion decision");
File.Delete(extensionlessIsoPath);

var extensionlessDmgPath = Path.Combine(Path.GetTempPath(), "clamguard-extensionless-dmg");
File.WriteAllBytes(extensionlessDmgPath, BuildDmgTrailerSample());
Assert(archiveScanner.Scan(extensionlessDmgPath).FileType == "DMG", "extensionless DMG trailer is detected before container expansion decision");
File.Delete(extensionlessDmgPath);

var clamArchiveFamilySamples = new (string Name, byte[] Data, string ExpectedType)[]
{
    ("sample.egg", [0x45, 0x47, 0x47, 0x41, 0x00, 0x01], "EGG"),
    ("sample.alz", [0x41, 0x4C, 0x5A, 0x01], "ALZ"),
    ("sample.sis", BuildMinimalSisHeader(), "SIS"),
    ("sample.szdd", BuildMinimalSzddHeader(), "SZDD")
};
foreach (var sample in clamArchiveFamilySamples)
{
    var samplePath = Path.Combine(Path.GetTempPath(), sample.Name);
    File.WriteAllBytes(samplePath, sample.Data);
    Assert(archiveScanner.Scan(samplePath).FileType == sample.ExpectedType, $"ClamAV archive-family detection routes {sample.ExpectedType}");
    File.Delete(samplePath);
}

// PDF LZWDecode + EarlyChange=1 compatibility.
var pdfLzwPath = Path.Combine(Path.GetTempPath(), "sample-lzw.pdf");
File.WriteAllBytes(pdfLzwPath, CreatePdfLzw("PDFLZW!"u8.ToArray()));
var pdfLzwDb = Path.Combine(Path.GetTempPath(), "clamguard-pdf-lzw-db-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(pdfLzwDb);
File.WriteAllText(Path.Combine(pdfLzwDb, "lzw.ldb"), "Archive.PdfLzw;Engine:81-255,Target:0,Container:CL_TYPE_PDF;0;5044464c5a57\n");
var pdfLzwManager = new DatabaseManager();
pdfLzwManager.LoadAndCompile(pdfLzwDb, true);
var pdfLzwScanner = new ClamGuard.Scanner.ScannerEngine(pdfLzwManager);
Assert(pdfLzwScanner.Scan(pdfLzwPath).Detections.Any(x => x.Name == "Archive.PdfLzw"), "PDF LZWDecode embedded-stream scanning detects decoded content");
Directory.Delete(pdfLzwDb, true);
File.Delete(pdfLzwPath);

var bz2Available = TryNativeCompress("bzip2", ".bz2", CreateTarEntry("bz.bin", "BZ2HIT"u8.ToArray()), out var bz2);
if (bz2Available)
{
    var bz2Path = Path.Combine(Path.GetTempPath(), "sample.tar.bz2");
    File.WriteAllBytes(bz2Path, bz2);
    Assert(archiveScanner.Scan(bz2Path).Detections.Any(x => x.Name == "Archive.Bz2Nested"), "BZip2 external decoder extracts nested TAR payloads");
    File.Delete(bz2Path);
}

var xzAvailable = TryNativeCompress("xz", ".xz", CreateTarEntry("xz.bin", "XZ2HIT"u8.ToArray()), out var xz);
if (xzAvailable)
{
    var xzPath = Path.Combine(Path.GetTempPath(), "sample.tar.xz");
    File.WriteAllBytes(xzPath, xz);
    Assert(archiveScanner.Scan(xzPath).Detections.Any(x => x.Name == "Archive.XzNested"), "XZ external decoder extracts nested TAR payloads");
    File.Delete(xzPath);
}


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
static string BcNumber(ulong value)
{
    if (value == 0) return "`";
    var digits = new List<char>();
    var v = value;
    while (v != 0) { digits.Add((char)(0x60 + (v & 0xF))); v >>= 4; }
    var text = new string(new[] { (char)(0x60 + digits.Count) });
    return text + new string(digits.ToArray());
}
static string BcFixed(int value, int width)
{
    var chars = new char[width];
    for (var i = 0; i < width; i++) chars[i] = (char)(0x60 + ((value >> (4 * i)) & 0xF));
    return new string(chars);
}
static string BcString(string value)
{
    var bytes = Encoding.UTF8.GetBytes(value + "\0");
    var encoded = new StringBuilder();
    foreach (var b in bytes) encoded.Append((char)(0x60 + (b & 0xF))).Append((char)(0x60 + ((b >> 4) & 0xF)));
    return "|" + BcNumber((ulong)bytes.Length) + encoded;
}
static string BcConstant64(ulong value)
{
    var encoded = new StringBuilder("P");
    for (var i = 0; i < 16; i++) encoded.Append((char)(0x60 + ((value >> (4 * i)) & 0xF)));
    return encoded.ToString();
}
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


File.Delete(wildcardTargetNdbPath);
File.Delete(ndbIndentedCommentPath);
File.Delete(ndbBlankPath);
File.Delete(ldbIndentedCommentPath);
File.Delete(ldbBlankPath);
File.Delete(ldbWhitespacePath);
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
Directory.Delete(archiveDbDir, true);
File.Delete(tarPath);
File.Delete(oldTarPath);
File.Delete(gzTarPath);
File.Delete(cpioPath);
File.Delete(cpioOdcPath);
File.Delete(cpioOldPath);
File.Delete(olePath);
File.Delete(pdfPath);
File.Delete(pdfHexPath);
File.Delete(macho64Path);

File.Delete(ndbPath);
File.Delete(ndbAbsoluteFile);
File.Delete(ndbEofFile);
File.Delete(ndbPeFile);
Directory.Delete(ndbDbDir, true);
File.Delete(containerLdbPath);
File.Delete(rootFile);
File.Delete(directZip);
File.Delete(outerZip);
Directory.Delete(containerDbDir, true);
File.Delete(sectionLdbPath);
File.Delete(peFile);
Directory.Delete(sectionDbDir, true);
File.Delete(advancedRegexPath);
File.Delete(rollingFile);
File.Delete(globalFile);
File.Delete(encompassFile);
Directory.Delete(advancedRegexDbDir, true);
File.Delete(invalidByteComparePath);

File.Delete(regexPath);
File.Delete(regexFile);
Directory.Delete(regexDbDir, true);
File.Delete(byteComparePath);
File.Delete(byteCompareFile);
Directory.Delete(byteCompareDbDir, true);

File.Delete(ldbModifierPath);
File.Delete(ldbContextPath);
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
            catch (FormatException) { signedNumericRejected = true; }
            Assert(signedNumericRejected, "ZMD numeric fields reject signs because ClamAV cli_isnumber accepts digits only");

            var zmdOverflowPath = Path.Combine(mdDir, "overflow-numeric.zmd");
            File.WriteAllText(zmdOverflowPath, "Metadata.Zip.OverflowNumeric:0:hello\\.txt:4294967295:5:*:0:1:*");
            var overflowRejected = false;
            try { _ = zmdEncryptedManager.LoadAndCompile(mdDir, true); }
            catch (FormatException) { overflowRejected = true; }
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
Assert(zmdWhitespaceRejected, "ZMD preserves leading/trailing spaces instead of Trim()-normalizing signature fields");

var zmdLeadingCommentPath = Path.Combine(mdDir, "leading-space-comment.zmd");
File.WriteAllText(zmdLeadingCommentPath, " #not-a-comment\n");
var zmdLeadingCommentRejected = false;
try { _ = SignatureParser.ParseFile(zmdLeadingCommentPath).ToList(); }
catch (FormatException) { zmdLeadingCommentRejected = true; }
Assert(zmdLeadingCommentRejected, "ZMD only treats '#' in column zero as a comment");

var zmdTrailingFieldPath = Path.Combine(mdDir, "trailing-field.zmd");
File.WriteAllText(zmdTrailingFieldPath, "Metadata.Zip.ExtraField:0:hello\\.txt:5:5:*:0:1:*:extra\n");
var zmdTrailingFieldRejected = false;
try { _ = SignatureParser.ParseFile(zmdTrailingFieldPath).ToList(); }
catch (FormatException) { zmdTrailingFieldRejected = true; }
Assert(zmdTrailingFieldRejected, "ZMD rejects extra fields beyond the exact nine-field cli_loadmd format");

var zmdEmptyLinePath = Path.Combine(mdDir, "empty-line.zmd");
File.WriteAllText(zmdEmptyLinePath, "\n");
var zmdEmptyLineRejected = false;
try { _ = SignatureParser.ParseFile(zmdEmptyLinePath).ToList(); }
catch (FormatException) { zmdEmptyLineRejected = true; }
Assert(zmdEmptyLineRejected, "ZMD empty lines are parsed as malformed records rather than silently skipped");

var zmdRangeRejectedPath = Path.Combine(mdDir, "range-rejected.zmd");
File.WriteAllText(zmdRangeRejectedPath, "Metadata.Zip.RangeRejected:0:hello\\.txt:0-5:5:*:*:1:*");
var zmdRangeRejected = false;
try
{
    new DatabaseLoader().LoadDirectory(mdDir, failOnInvalidFile: true, verifyContainers: false);
}
catch (FormatException)
{
    zmdRangeRejected = true;
}
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

sealed class SlowScanner(TimeSpan delay) : IContentScanner
{
    public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public IReadOnlyList<Detection> Scan(ReadOnlySpan<byte> data, string path, CancellationToken cancellationToken = default)
    {
        Entered.TrySetResult(true);
        cancellationToken.ThrowIfCancellationRequested();
        Thread.Sleep(delay);
        cancellationToken.ThrowIfCancellationRequested();
        return [];
    }
}

