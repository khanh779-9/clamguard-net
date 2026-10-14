# project-ClamGuard.Signatures

> Parse toàn bộ định dạng chữ ký của ClamAV thành model có cấu trúc, rồi build thành các
> **matcher đã biên dịch** (Aho-Corasick, Boyer-Moore-Horspool, hash buckets, prefilter logical)
> chạy in-memory và streaming trên dữ liệu không đáng tin.

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core` |
| Số file nguồn | 43 (Matching 7, Patterns 8, Parsing 11, Models 16, csproj) |
| Định dạng parse | `.hdb/.hdu/.hsb/.hsu/.mdb/.mdu/.msb/.msu/.fp/.sfp/.ndb/.ndu/.ldb/.ldu/.cdb/.zmd/.rmd/.idb/.db/.ign/.ign2` |

## 2. Cấu trúc thư mục

```text
Parsing/
  SignatureParser.cs            Facade điều phối theo extension
  SignatureParserCommon.cs      Helpers dùng chung (algorithm theo độ dài hash, ParseInt/Size, Engine range)
  Hash/HashSignatureParser.cs   .hdb/.hsb/.fp/.sfp/.mdb/.imp (size TRƯỚC hash cho mdb/msb)
  Content/Ndb/NdbSignatureParser.cs     .ndb/.ndu/.sdb — validate offset (cli_caloff parity)
  Content/Ldb/LdbSignatureParser.cs     .ldb/.ldu — split ';' an toàn, phân loại subsig
  Content/Ldb/LdbSubsigParser.cs        hex::mods, PCRE, byte-compare, fuzzy_img, macro
  Content/Ldb/LdbTargetParser.cs        TDB (Target/Engine/Container/FileSize/IconGroup…)
  Content/Ndb/NdbSignatureParser.cs     macro group $n$, FLEVEL gate
  Metadata/IdbSignatureParser.cs        .idb — 62-byte metric, bounds từng bước
  Container/ContainerSignatureParser.cs .cdb/.zmd/.rmd — bug-for-bug với cli_loadmd/cli_loadcdb
Patterns/
  PatternAtom.cs (+ ExactByte/MaskedByte/Gap/CharacterClass/Alternate)
  HexPattern.cs                 Dual representation: fixed byte[] ↔ atoms; backtracking matcher
Matching/
  AhoCorasick.cs                Sparse trie → frozen arrays → dense int[256] cho 8192 state đầu
  BoyerMooreHorspoolMatcher.cs  Fast path cho trường hợp đúng 1 fixed pattern
  CompiledSignatureSet(.MatchHelpers).cs   Index tổng hợp + Match/MatchStreamAsync
  LogicalSignaturePrefilter.cs  Fragment index (seed 4-byte balanced) cho logical thuần-AND
  SignatureTargetGroups.cs      Mirror cli_mtargets[] của ClamAV 1.5.4 (15 matcher root)
  ByteArrayContentComparer.cs   EqualityComparer<byte[]> cho digest (xxHash-based)
Models/
  Signature.cs, ContentSignature.cs, NdbSignature.cs, LogicalSignature.cs,
  HashSignature.cs, MetadataSignature.cs, CdbSignature.cs, LdbTargetDescription.cs,
  LdbRegexSubSignature.cs, LdbByteCompareSubSignature.cs, LdbFuzzyImageSubSignature.cs,
  ContentMatchOptions.cs, ByteCompareOptions.cs, ByteCompareComparison.cs,
  MetadataRange.cs, IconDatabase.cs
```

📌 Ngữ nghĩa từng định dạng: xem [`daily_CVD_Signature_Format_Analysis.md`](./daily_CVD_Signature_Format_Analysis.md).

---

## 3. Luồng hoạt động

### 3.1. Load & build

```text
SignatureParser.ParseFile(path, flevel)        ← chọn parser theo extension
        │  (lọc FLevel trước khi parse hex — tiết kiệm)
        ▼
IEnumerable<Signature>                         ← model bất biến, có SourceFile/SourceEntry
        │  SignatureDatabase.Add/Compile()  (ở project Database)
        ▼
CompiledSignatureSet.Add(signature)            ← phân bổ vào cấu trúc phù hợp
   ├─ fixed hex       → AhoCorasickMatcher theo target-group (NDB) hoặc content-AC
   ├─ flexible hex    → flexible-AC theo anchor + danh sách _unanchored*
   ├─ hash sigs       → hash bucket theo (algorithm, size?) — exact + wildcard
   ├─ .fp/.sfp        → false-positive buckets
   └─ logical         → LogicalSignaturePrefilter (seed-balanced fragment index)
        │  Build()
        ▼
FROZEN: mảng đóng băng, dense transition tables, immutable state cho scan
```

### 3.2. Match (in-memory)

`Match(data, label, includeNdb, collectAllMatches, ndbFilter, ndbPatternCandidates,
ndbCandidateFilter, targetGroup)`:

1. **Target-group AC trước** (như `cli_scan_buff`), generic root sau.
2. Mỗi hit đi qua: `hits` dedupe → NDB gate (`includeNdb` + `ndbFilter`) →
   `OffsetAllows` (ngữ nghĩa `cli_caloff`: `N,M` = `[N, N+M]` inclusive; `EOF-n`; `*`) → thêm Detection.
3. NDB bị filter loại → vẫn thêm vào `ndbPatternCandidates` để **EvaluateNdb có context**
   (offset EP/SE/S/VI cần executable info) chạy ở tầng Scanner.
4. Flexible content: candidate qua anchor AC → cap thu thập (4096/pattern, 65 536 tổng) →
   verify theo thứ tự offset → first-match hoặc all-match.
5. Hash buckets: chỉ hash algorithm có bucket; `.fp` khớp → toàn bộ layer thành **Trusted**.

### 3.3. MatchStreamAsync (streaming)

Chunked stream, **giữ state AC qua biên chunk**, rolling window `MaxFlexibleLookbehind`
cho flexible pattern, `IncrementalHash` có điều kiện (`NeedsHash`), `OffsetAllowsStreaming`
tương đương bản in-memory. Method này được tách cẩn thận để **biên dịch được cả C# 12**
(SDK 8) lẫn C# 14 (SDK 10) — Span locals của vòng lặp được trích vào local function
`MatchFlexibleChunk`.

---

## 4. API chính

| API | Ghi chú |
|-----|---------|
| `SignatureParser.ParseFile / ParseLines / ParseHashFile / ParseNdbFile / ParseLdbFile / ParseCdbFile / ParseMetadataFile / ParseIdbFile` | Static, throw `FormatException` kèm `path:line` khi DB hỏng |
| `CompiledSignatureSet.Match(...)` | Quét buffer in-memory |
| `CompiledSignatureSet.MatchStreamAsync(...)` | Quét stream (dùng cho file lớn hơn `MaxFullBufferSize`) |
| `CompiledSignatureSet.MatchesFalsePositive(data)` | `.fp/.sfp` trust check |
| `CompiledSignatureSet.FindLogicalCandidates(data) / IsLogicalSignaturePrefiltered(sig)` | Prefilter logical thuần-AND |
| `AhoCorasickMatcher.Scan / ScanUntil / FindMatchingIds` | Public matcher riêng (chunked, state-preserving) |
| `HexPattern.Parse / Matches / TryGetSearchAnchor / ToWideVariant` | Pattern engine |

---

## 5. Điểm hiệu năng có chủ đích

| Kỹ thuật | Vị trí | Lý do |
|----------|--------|-------|
| Sparse trie (edge-list int-index) → **frozen arrays** → **dense `int[256]`** cho 8192 state đầu | `AhoCorasick.cs` | DB thật 500K–2M states; freeze + `TrimExcess` giải phóng build-time lists |
| Flyweight 256 instance | `ExactByteAtom.cs` | Không alloc per-byte khi parse DB lớn |
| Anchor search (longest fixed run) cho flexible pattern | `MatchHelpers.cs` `MatchFlexibleCore` | Tránh backtracking ở mọi byte position |
| Seed-balanced fragment index | `LogicalSignaturePrefilter.cs` | Chọn seed 4-byte hiếm nhất theo vòng FNV — cắt candidate trước khi đếm subsig |
| BMH fast path khi set có đúng 1 fixed pattern | `CompiledSignatureSet.cs` | Bỏ AC overhead; thử **mọi occurrence** như `cli_bm_scanbuff` |
| Cap candidate | `MaxCollectedCandidatesPerPattern=4096`, `MaxCollectedCandidatesTotal=65536` | Anchor phổ biến (zero-run, MZ pad) trên file lớn không thể buffer O(filesize) |
| `MaxBacktrackingStates` (250K) + visited-set | `HexPattern.cs` | Chặn DoS của gap-heavy pattern; visited-set đảm bảo kết thúc O(atoms × length) |

## 6. Tương thích ClamAV (đã đối chiếu source 1.5.4)

| Chủ đề | Quyết định |
|--------|-----------|
| Offset `N,M` | Max-shift → match trong `[N, N+M]` **inclusive** (`cli_caloff` + `matcher-ac.c:1918`) |
| Bare `EOF` | **Bị từ chối** (không tồn tại trong `cli_caloff`) — chỉ `EOF-n` |
| `VI` offset | Hợp lệ (VersionInfo) — chỉ target PE/ELF/Mach-O |
| Target gate | `EP+/EP-/SL+/SE/Sn/VI` **fail lúc load** nếu target ∉ {1, 6, 9} |
| `[n-m]` hex | Gap thật — `cli_ac_addsig` chuyển thành dạng `{n-m}` (tối đa 2 lần dùng) |
| ICMP opcode | 29 = SLE, 30 = SLT (khớp `clambc.h`, dùng bởi project Bytecode) |
| `.ldb` expression | Right-associative: `0&1\|2` ≡ `0&(1\|2)` (do tầng Scanner evaluate, xem project Scanner) |
| `.ign`/`.ign2` | Filter **trước** khi parse (skip FLevel-first như `cli_loadndb`) |

## 7. Thread-safety

- Parser: static, thuần túy — an toàn mọi thread.
- `CompiledSignatureSet`: mutable khi `Add()`, **immutable sau `Build()`** (convention enforced
  bởi `_built` flag); scan path không mutate.
- `AhoCorasickMatcher.Build()` / `LogicalSignaturePrefilter.Build()`: lazy, **không thread-safe nếu
  gọi Build đồng thời từ 2 thread** — caller (CompiledSignatureSet) chịu trách nhiệm build trước.
- `HexPattern.ToWideVariant`: lazy cache benign-race (compute trùng, cùng giá trị).

## 8. Kiểm thử

- `Program.CompiledMatcherTests.cs` (50 asserts) — dày nhất: AC overlap/suffix/chunk-boundary,
  streaming, FP suppression, BMH fast path, alternates, LDB modifiers.
- `Program.NdbPolicyTests.cs` (35) — offset mọi dạng, `.ign/.ign2`, PUA, normalized targets.
- `Program.SignatureParsingTests.cs` (17), `Program.MetadataTests.cs` (32), `Program.LdbParityTests.cs`
  (12, parity với dòng LDB thật qua env opt-in).
