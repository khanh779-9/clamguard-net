internal static partial class Program
{
    private static void ArchiveDocumentTests()
    {
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
        Directory.Delete(mimeDbDir, true);
        File.Delete(mhtmlPath);
        File.Delete(emlPath);
        Directory.Delete(swfDbDir, true);
        File.Delete(swfPath);
    }
}
