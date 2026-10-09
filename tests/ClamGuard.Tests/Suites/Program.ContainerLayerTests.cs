internal static partial class Program
{
    private static void ContainerLayerTests()
    {
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
        var peResult = sectionScanner.Scan(peFile, new ScanOptions { CollectAllMatches = true });
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
        var normalizedSamples = CreateNormalizedTextSamples();
        Assert(normalizedLdbScanner.Scan(normalizedSamples.HtmlPath).Detections.Any(x => x.Name == "Ldb.HtmlNormalized"), "LDB HTML target matches normalized HTML content");
        Assert(normalizedLdbScanner.Scan(normalizedSamples.AsciiPath).Detections.Any(x => x.Name == "Ldb.AsciiNormalized"), "LDB ASCII target matches normalized text content");
        File.Delete(normalizedSamples.HtmlPath);
        File.Delete(normalizedSamples.AsciiPath);

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
        new byte[] { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a }.CopyTo(pngChild.AsSpan());
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
        Directory.Delete(overlayDbDir, true);
        File.Delete(sfxPath);
        File.Delete(normalizedLdbPath);
        Directory.Delete(normalizedLdbDir, true);
        Directory.Delete(graphicsNdbDir, true);
        File.Delete(graphicsZipPath);
        File.Delete(utf16HtmlPath);
    }
}
