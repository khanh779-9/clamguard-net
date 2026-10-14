# project-ClamGuard.Scanner

> **Cỗ máy quét** của hệ thống: nhận một đường dẫn/buffer + `ScanOptions`, trả về
> `ScanResult`. Bao trùm file-type detection (FTM), hash, raw pattern, container/archive
> extraction, PE chuyên biệt, image fuzzy hash, logical runtime, hosting đa luồng (`ScanHost`).

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core`, `ClamGuard.Signatures`, `ClamGuard.Database`, `ClamGuard.Yara`, `ClamGuard.Bytecode`; NuGet **SharpCompress 0.50.4** (RAR/7Z/ARJ) |
| Số file nguồn | 44 (~9 900 dòng) — project lớn nhất |

## 2. Cấu trúc thư mục

```text
Engine/
  ScannerEngine.cs               Pipeline chính (partial) — ScanAsync/Scan/ScanMemoryBuffer
  ScannerEngine.Content.cs       ScanBuffer (layer lồng), EvaluateNdb/EvaluateLogical, group wrappers
  ScannerEngine.FileTypes.cs     DetectType (FTM → magic → extension), LooksLike*, DetectMimeType
  ScannerEngine.Normalization.cs Normalize HTML/ASCII, RescanAsHandlerType, OffsetAllows, byte-compare
Detection/
  ScanTypePolicy.cs              Single source of policy: ShouldParseContainer, IsPe/IsElf/IsMachO,
                                 IsRawOffsetStreamSafe, ShouldRunSpecializedPreRaw/PostRaw
  PreparedScanRules.cs           View theo database generation (NDB/logical/PE rules per file-type)
  FileTypeMagicDetector.cs       Runtime FTM (mode 0 direct / mode 1 content, PatternCache)
Containers/
  ArchiveScanner(.Formats/.Helpers).cs   Entry point + parser từng định dạng + budget
  ArchiveScanBudget.cs           Ngân sách entries/expandedBytes/limitExceeded dùng chung
  MailDocumentExtractor.cs       MIME/uuencode/BinHex/TNEF
  OfficeOleExtractor.cs          OLE2 CFB (FAT/miniFAT), HWP5, RTF objdata
  PdfSwfExtractor.cs             PDF stream/filter chain, SWF CWS
Archives/
  ArchiveManagedDecoder.cs       SharpCompress (RAR/7Z/ARJ) — gate size/ratio trước extract
  ArchiveExternalDecoder.cs      7z/unrar/bzip2/xz qua Process (ArgumentList, no shell)
Pe/                              PeSpecializedMatcher (section/import hash), Parsing, PeOverlayScanner
Executable/                      ExecutableInspector (PE/ELF/Mach-O → LdbExecutableInfo), VersionInfoParser
Image/                           ImageDecoder + Png/Gif/Bmp fallback + IconDecoder + IconMetrics (port
                                 pe_icons.c) + FuzzyImageHasher (pHash 64-bit) + ResourceParser
Content/Logical/                 LdbRuntime (context, ResolveOffset, icon), LogicalContentMatcher,
                                 LogicalExpressionEvaluator (AST, right-assoc), RegexContentMatcher
Specialized/                     HTML variants, MS-XML/HWP (pre-raw), OneNote/XDP attachments
Hosting/                         ScanHost (facade production), ScanContext (recursion+budget), options/metrics/observer
```

## 3. Pipeline quét chính (`ScannerEngine.ScanAsync`)

```text
File.Exists / MaxFileSize gate (heuristic Exceeded nếu bật)
  → probe 1028 byte (1 FileStream, seeks: ISO CD001 @32769, UDF BEA01 @32768, DMG koly trailer)
  → DetectType (FTM → builtin magic → extension)
  → quyết định needsFullBuffer (container / logical / PE / normalized target…)
      └─ MaxFullBufferSize vượt → tắt secondary parsing, CÒN raw-pass (báo Heuristics.Limits.Exceeded)
  → full buffer (đọc 1 lần) hoặc MemoryMappedFile streaming
  → container pre-scan → pre-raw specialized → RAW match (AC/ streaming)
  → .fp trust check (khớp → Trusted, xoá evidence, dừng)
  → signature groups chạy SONG SONG (NDB / logical / PE) với linked CTS,
    ||-short-circuit khi có blocking detection
  → PE overlay → Mach-O fat slices → section-hash/import-hash streaming path
  → CreateDetectionResult (verdict: Malicious > PotentiallyUnwanted > StrongIndicator > Clean)
```

**Layer lồng nhau**: mọi nội dung trích ra (member archive, PDF stream, OneNote attachment…) quay
lại qua `ScanBuffer` với `ScanContext` dùng chung — depth + budget **không reset** giữa các tầng
(§7.1). `ScanHost` là facade production bổ sung: admission (MaxConcurrent/MaxQueued), timeout từng
scan, metrics `Interlocked`, health gate theo DB, observer callbacks, dispose-drain.

## 4. Các subsystem trọng yếu

### 4.1. Container & archive (`ArchiveScanner*`)

- Định dạng native-managed: ZIP (metadata EOCD/central dir + 3 lớp chống zip-bomb: count/size/
  **ratio**), GZ, TAR (ustar/old + GNU longname + PAX), CPIO (newc/crc/odc/old), SZDD (LZSS),
  OLE2 CFB, PDF (Flate/ASCIIHex/ASCII85/RunLength/LZW `EarlyChange`), SWF, MAIL/MHTML, BinHex,
  UUE, TNEF.
- Qua decoder ngoài (Process, `ArgumentList`, không shell, drain stderr, kill process tree):
  7z, unrar, bzip2, xz.
- `ArchiveScanBudget` + `ConsumeBudget` **tích lũy xuyên layer** (count tại điểm materialize,
  không double-count). `ScanChild` giữ đúng thứ tự layer ClamAV và FP-check từng layer.

### 4.2. Logical runtime (`Content/Logical`)

- `LdbRuntime.ResolveOffset` dịch offset expression thành ranges với **executable context**
  (EP±, SL+, SEx, Sn+, VI, EOF-n, macro `$n$`, `base,maxshift`).
- `LogicalExpressionEvaluator`: lexer+parser AST, right-associative `0&1|2 ≡ 0&(1|2)`,
  count modifier (`>5`, `=3,2`), chặn tham chiếu subsig tương lai, `Guard(depth)`.
- Normalize HTML/ASCII **memoize theo target** trong một lần evaluate (100 rule HTML target →
  normalize đúng 1 lần).
- PCRE: cache `Regex` theo (pattern, flags), timeout 250ms/call, flags `i s m x U E A g r e`.

### 4.3. PE (`Pe`, `Executable`, `Image`)

- `ExecutableInspector`: PE/ELF/Mach-O → entry point, sections, version-info regions, icon groups
  (dùng cho target-description LDB).
- `PeSpecializedMatcher`: section hash (`.mdb/.msb`) — hash **một lần/thuật toán/section** — và
  import hash (`.imp`, imphash với normalize "first dot" parity).
- `PeOverlayScanner`: overlay như layer con (streaming path đọc 4MB prefix + overlay).
- Image: decode PNG/GIF/BMP/WPF (cap 4096px, 64MiB pixel, bounded inflate — malformed → `false`,
  không throw), icon metrics port `pe_icons.c`, pHash 64-bit (Lanczos3 → DCT).

### 4.4. Specialized handlers

Pre-raw cho `HWP3/HWPOLE2/HTML/HTML_UTF16/ONENOTE/XDP/XML_*/XML_HWP` — mỗi handler trích layer
con rồi gọi `ScanNestedBytes → ScanBuffer` (context Descend). Post-raw cho HTML variants.
XML luôn `DtdProcessing.Prohibit` (chống XXE); HWP-ML dùng `MaxCharactersInDocument`.

### 4.5. Hosting (`Hosting/ScanHost.cs`)

```csharp
var host = new ScanHost(engine, options, observer);
ScanResult r = await host.ScanFileAsync(path, ct);   // admission → queue → timeout → metrics
```

- Metrics: completed/error/timeout/rejected theo `Interlocked`; snapshot 6 bucket.
- `EnterOperation` double-check disposed; semaphore dispose chỉ khi active = 0; `DisposeAsync`
  chờ drain qua TCS.
- Mọi exception của scanner (trừ OOM/AV) chuyển thành `ScanVerdict.Error` — caller không bao giờ
  thấy crash vì một file.

## 5. An toàn với dữ liệu không đáng tin

| Nguy cơ | Phòng thủ |
|---------|-----------|
| Đệ quy zip↔OneNote↔zip vô hạn | `ScanContext` depth gate = `MaxArchiveDepth` (mặc định 17) + budget tích lũy |
| Zip-bomb | Entry count + MaxFileSize + **compression ratio** + expanded-bytes budget, cap giữa chừng |
| Ảnh malformed/bomb | Cap 4096px/64MiB, inflate bounded, mọi TryDecode trả `false` thay vì throw |
| PE32+ thunk bẩn | Range-check trước cast (không `checked`-throw) |
| Regex PCRE chậm | Timeout 250ms + cache + anchor gate bởi trigger |
| Regex matching treo | `RegexMatchTimeoutException` bắt riêng, không abort scan |
| File vượt `MaxFullBufferSize` | Raw-pass tiếp tục, secondary parsing bị skip + heuristic |

## 6. Thread-safety

- `ScannerEngine`: stateless ngoài `_optionalScannerCache` (Lazy thread-safe) và prepared-rules
  cache (double-checked `Volatile`) — scan chạy song song an toàn.
- `PreparedScanRules`: immutable + lazy per-file-type (`ConcurrentDictionary`).
- `ScanHost`: admission/metrics `Interlocked`; observers được gọi inline với try/catch-swallow.
- `ScanContext`: per-scan-tree, chỉ đọc sau khi tạo.

## 7. Quyết định thiết kế & hardening gần đây

1. **ScanContext (fix CRITICAL)**: trước đây `ScanBuffer` gọi archive với depth cứng 0 + budget
   mới mỗi tầng — chu kỳ zip→OneNote→zip gây StackOverflow. Nay context xuyên suốt, budget chỉ
   tiêu tại điểm materialize (`TryReadStream`).
2. **Image decoders exception-free**: mọi fallback decoder trả `false` khi malformed; `TryDecode`
   wrap cap + catch-all có chủ đích (WPF path).
3. **Perf**: dùng `PreparedScanRules`/typed caches thay `OfType<T>().ToArray()` per member;
   Regex cache; PE hash-once; normalize/context memoize; bỏ GC.Collect/EmptyWorkingSet (buffer
   pooling là giải pháp thật).
4. **Evasion**: container vượt `MaxFullBufferSize` vẫn raw-scan và báo heuristic "incomplete".

## 8. Kiểm thử

`Program.ArchiveTests.cs` (32), `Program.ContainerLayerTests.cs` (17), `Program.ExecutableTests.cs`
(10), `Program.SmokeTests.cs` (29 — FTM pipeline, ScanHost queue/timeout fail-closed), và toàn bộ
pipeline qua `Program.ScanOptionsTests.cs` (24). Fixtures 100 % sinh runtime, không commit binary.
