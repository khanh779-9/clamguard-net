# project-ClamGuard.Scanner

> The **scanning engine** of the system: takes a path/buffer plus `ScanOptions` and returns a
> `ScanResult`. Spans file-type detection (FTM), hashes, raw patterns, archive/container
> extraction, PE-specific matching, image fuzzy hashing, the logical runtime and multi-threaded
> hosting (`ScanHost`).

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0` |
| Dependencies | `ClamGuard.Core`, `ClamGuard.Signatures`, `ClamGuard.Database`, `ClamGuard.Yara`, `ClamGuard.Bytecode`; NuGet **SharpCompress 0.50.4** (RAR/7Z/ARJ) |
| Source files | 44 (~9,900 lines) — the largest project |

## 2. Layout

```text
Engine/
  ScannerEngine.cs               Main pipeline (partial) — ScanAsync/Scan/ScanMemoryBuffer
  ScannerEngine.Content.cs       ScanBuffer (nested layers), EvaluateNdb/EvaluateLogical, group wrappers
  ScannerEngine.FileTypes.cs     DetectType (FTM -> magic -> extension), LooksLike*, DetectMimeType
  ScannerEngine.Normalization.cs HTML/ASCII normalization, RescanAsHandlerType, OffsetAllows, byte-compare
Detection/
  ScanTypePolicy.cs              Single source of policy: ShouldParseContainer, IsPe/IsElf/IsMachO,
                                 IsRawOffsetStreamSafe, ShouldRunSpecializedPreRaw/PostRaw
  PreparedScanRules.cs           Per-database-generation view (NDB/logical/PE rules per file type)
  FileTypeMagicDetector.cs       Runtime FTM (mode 0 direct / mode 1 content, PatternCache)
Containers/
  ArchiveScanner(.Formats/.Helpers).cs   Entry point + per-format parsers + budget
  ArchiveScanBudget.cs           Shared entries/expandedBytes/limitExceeded budget
  MailDocumentExtractor.cs       MIME/uuencode/BinHex/TNEF
  OfficeOleExtractor.cs          OLE2 CFB (FAT/miniFAT), HWP5, RTF objdata
  PdfSwfExtractor.cs             PDF stream/filter chain, SWF CWS
Archives/
  ArchiveManagedDecoder.cs       SharpCompress (RAR/7Z/ARJ) — size/ratio gate before extraction
  ArchiveExternalDecoder.cs      7z/unrar/bzip2/xz via Process (ArgumentList, no shell)
Pe/                              PeSpecializedMatcher (section/import hashes), Parsing, PeOverlayScanner
Executable/                      ExecutableInspector (PE/ELF/Mach-O -> LdbExecutableInfo), VersionInfoParser
Image/                           ImageDecoder + Png/Gif/Bmp fallbacks + IconDecoder + IconMetrics (a port of
                                 pe_icons.c) + FuzzyImageHasher (64-bit pHash) + ResourceParser
Content/Logical/                 LdbRuntime (context, ResolveOffset, icon), LogicalContentMatcher,
                                 LogicalExpressionEvaluator (AST, right-associative), RegexContentMatcher
Specialized/                     HTML variants, MS-XML/HWP (pre-raw), OneNote/XDP attachments
Hosting/                         ScanHost (production facade), ScanContext (recursion+budget), options/metrics/observer
```

## 3. Main scan pipeline (`ScannerEngine.ScanAsync`)

```text
File.Exists / MaxFileSize gate (Heuristics.Limits.Exceeded when enabled)
  -> 1028-byte probe (one FileStream with seeks: ISO CD001 @32769, UDF BEA01 @32768, DMG koly trailer)
  -> DetectType (FTM -> builtin magic -> extension)
  -> decide needsFullBuffer (container / logical / PE / normalized target...)
       - exceeding MaxFullBufferSize turns off secondary parsing, the RAW pass continues
         (reports Heuristics.Limits.Exceeded)
  -> full buffer (single read) or MemoryMappedFile streaming
  -> container pre-scan -> pre-raw specialized -> RAW match (AC / streaming)
  -> .fp trust check (hit -> Trusted, clears evidence, stops descending)
  -> signature groups run in PARALLEL (NDB / logical / PE) with a linked CTS and an
     OR-short-circuit when a blocking detection appears
  -> PE overlay -> Mach-O fat slices -> streaming section-hash/import-hash path
  -> CreateDetectionResult (verdict: Malicious > PotentiallyUnwanted > StrongIndicator > Clean)
```

**Nested layers**: every extracted payload (archive member, PDF stream, OneNote attachment...)
re-enters through `ScanBuffer` with a shared `ScanContext` — depth and budget are **not reset**
between layers (section 7.1). `ScanHost` is the production facade adding: admission
(MaxConcurrent/MaxQueued), per-scan timeout, `Interlocked` metrics, a health gate tied to the
database, observer callbacks and dispose-drain.

## 4. Key subsystems

### 4.1. Containers & archives (`ArchiveScanner*`)

- Natively parsed formats: ZIP (EOCD/central-directory metadata + 3 zip-bomb layers: count/size/
  **ratio**), GZ, TAR (ustar/old + GNU longname + PAX), CPIO (newc/crc/odc/old), SZDD (LZSS),
  OLE2 CFB, PDF (Flate/ASCIIHex/ASCII85/RunLength/LZW `EarlyChange`), SWF, MAIL/MHTML, BinHex,
  UUE, TNEF.
- Via external decoders (Process with `ArgumentList`, no shell, stderr drained, process tree
  killed): 7z, unrar, bzip2, xz.
- `ArchiveScanBudget` + `ConsumeBudget` **accumulate across layers** (consumed at materialization
  points, never double-counted). `ScanChild` keeps ClamAV's layer ordering and FP-checks each layer.

### 4.2. Logical runtime (`Content/Logical`)

- `LdbRuntime.ResolveOffset` turns offset expressions into ranges with an **executable context**
  (EP+/-, SL+, SEx, Sn+, VI, EOF-n, macro `$n$`, `base,maxshift`).
- `LogicalExpressionEvaluator`: lexer+parser AST, right-associative `0&1|2 == 0&(1|2)`,
  count modifiers (`>5`, `=3,2`), future-reference rejection, `Guard(depth)`.
- HTML/ASCII normalization is **memoized per target** within one evaluation (100 HTML-target rules
  normalize the buffer once).
- PCRE: `Regex` cache keyed by (pattern, flags), 250ms timeout per call, flags `i s m x U E A g r e`.

### 4.3. PE (`Pe`, `Executable`, `Image`)

- `ExecutableInspector`: PE/ELF/Mach-O -> entry point, sections, version-info regions, icon groups
  (used by LDB target descriptions).
- `PeSpecializedMatcher`: section hashes (`.mdb/.msb`) — hashed **once per algorithm per section** —
  and import hashes (`.imp`, imphash with "first dot" normalization parity).
- `PeOverlayScanner`: the overlay as a child layer (streaming path reads a 4MB prefix + overlay).
- Image: PNG/GIF/BMP/WPF decoding (4096px/64MiB caps, bounded inflate — malformed input returns
  `false`, never throws), icon metrics ported from `pe_icons.c`, 64-bit pHash (Lanczos3 -> DCT).

### 4.4. Specialized handlers

Pre-raw for `HWP3/HWPOLE2/HTML/HTML_UTF16/ONENOTE/XDP/XML_*/XML_HWP` — each handler extracts a
child layer and calls `ScanNestedBytes -> ScanBuffer` (context Descend). Post-raw for the HTML
variants. XML always uses `DtdProcessing.Prohibit` (XXE-safe); HWP-ML enforces
`MaxCharactersInDocument`.

### 4.5. Hosting (`Hosting/ScanHost.cs`)

```csharp
var host = new ScanHost(engine, options, observer);
ScanResult r = await host.ScanFileAsync(path, ct);   // admission -> queue -> timeout -> metrics
```

- Metrics: completed/error/timeout/rejected via `Interlocked`; a 6-bucket snapshot.
- `EnterOperation` double-checks disposed; the semaphore is disposed only when active == 0;
  `DisposeAsync` awaits a drain via TCS.
- Every scanner exception (except OOM/AV) becomes `ScanVerdict.Error` — the caller never crashes
  because of one file.

## 5. Untrusted-data safety

| Threat | Mitigation |
|--------|------------|
| Infinite zip<->OneNote<->zip recursion | `ScanContext` depth gate = `MaxArchiveDepth` (default 17) + an accumulating budget |
| Zip bombs | Entry count + MaxFileSize + **compression ratio** + expanded-bytes budget, bounded mid-stream |
| Malformed/bomb images | 4096px/64MiB caps, bounded inflate, every TryDecode returns `false` instead of throwing |
| Dirty PE32+ thunk values | Range check before casting (no `checked`-throw) |
| Slow PCRE | 250ms timeout + cache + trigger gating |
| Hanging regex matching | `RegexMatchTimeoutException` caught separately; the scan continues |
| File exceeding `MaxFullBufferSize` | Raw pass continues, secondary parsing skipped + heuristic reported |

## 6. Thread-safety

- `ScannerEngine`: stateless apart from `_optionalScannerCache` (Lazy thread-safe) and the
  prepared-rules cache (double-checked `Volatile`) — parallel scans are safe.
- `PreparedScanRules`: immutable + lazy per file type (`ConcurrentDictionary`).
- `ScanHost`: admission/metrics via `Interlocked`; observers called inline with try/catch-swallow.
- `ScanContext`: per scan tree, read-only after creation.

## 7. Design decisions & recent hardening

1. **ScanContext (critical fix)**: `ScanBuffer` used to call archives with a hard-coded depth 0
   and a fresh budget per layer — a zip->OneNote->zip cycle caused a StackOverflow. The context
   now flows through, and the budget is only consumed at materialization points (`TryReadStream`).
2. **Exception-free image decoders**: every fallback decoder returns `false` on malformed input;
   `TryDecode` wraps the caps plus a deliberate catch-all (WPF path).
3. **Performance**: `PreparedScanRules`/typed caches replace `OfType<T>().ToArray()` per member;
   Regex cache; PE hash-once; normalize/context memoization; GC.Collect/EmptyWorkingSet removed
   (buffer pooling is the real remedy).
4. **Evasion resistance**: containers exceeding `MaxFullBufferSize` still get the raw scan and
   report the "incomplete scanning" heuristic.

## 8. Testing

`Program.ArchiveTests.cs` (32), `Program.ContainerLayerTests.cs` (17), `Program.ExecutableTests.cs`
(10), `Program.SmokeTests.cs` (29 — FTM pipeline, ScanHost queue/timeout fail-closed), plus the
whole pipeline through `Program.ScanOptionsTests.cs` (24). Fixtures are 100% runtime-generated;
no binaries are committed.
