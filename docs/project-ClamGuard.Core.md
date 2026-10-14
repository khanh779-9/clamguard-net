# project-ClamGuard.Core

> Nền tảng chung cho toàn bộ hệ thống: codec hex, model domain dùng chung, cấu hình quét
> (`ScanOptions`/`ScanLimits`) và chính sách lọc kết quả. **Không tham chiếu project nào** —
> mọi project khác phụ thuộc vào đây.

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0` (kế thừa từ `Directory.Build.props`) |
| Dependency | Không có (project gốc của graph) |
| Compiler settings | `Nullable=enable`, `TreatWarningsAsErrors=true`, `Deterministic=true`, `LangVersion=latest` |
| Số file nguồn | 2 (`Hex.cs`, `Models.cs`) |

Vị trí trong dependency graph:

```text
ClamGuard.Core   ← không phụ thuộc ai
├── ClamGuard.Signatures
├── ClamGuard.Yara
├── ClamGuard.Bytecode
├── ClamGuard.Database   (→ Signatures, Yara, Bytecode)
├── ClamGuard.Scanner    (→ tất cả trên)
└── ClamGuard.Antivirus  (→ Core, Database, Scanner)
```

---

## 2. Thành phần chính

### 2.1. `Hex.cs` — codec hex tĩnh

| API | Vai trò |
|-----|---------|
| `HexCodec.TryDecode(string, out byte[])` | Hex → byte[]; fail khi ký tự không hợp lệ hoặc độ dài lẻ |
| `HexCodec.ToLowerHex(byte[])` | byte[] → hex lowercase (dùng cho hiển thị/manifest) |

Đúng ngữ nghĩa hex của ClamAV: chỉ ASCII, chấp nhận hoa/thường lẫn lộn. Là path nóng khi load
DB hàng trăm nghìn signature.

### 2.2. `Models.cs` — domain model & policy

**Enums:**

| Enum | Ý nghĩa |
|------|---------|
| `ScanVerdict` | `Clean`, `Malicious`, `PotentiallyUnwanted`, `StrongIndicator`, `Trusted`, `Timeout`, `Error` — kết quả phân loại cuối của một lần scan |
| `SignatureType` | Nhóm chữ ký: `Hash`, `Ndb`, `Logical`, `Content`, `Metadata`, `Trust`, … |
| `HashAlgorithmKind` | `Md5`, `Sha1`, `Sha256` — chọn theo **độ dài** chuỗi hex trong DB |
| `DatabaseFormat` | Định dạng DB khi load |

**Records chính:**

| Record | Trường đáng chú ý |
|--------|--------------------|
| `Detection(string Name, SignatureType Type, long? Offset, string SourceFile, string Detail)` | Một phát hiện — `Offset` nullable (hash detection không có offset) |
| `ScanResult(ScanVerdict Verdict, string FilePath, string? FileType, IReadOnlyList<Detection> Detections, long BytesScanned, TimeSpan Duration, DatabaseInfo? Database)` | Kết quả hoàn chỉnh, immutable — mọi tầng trả về kiểu này |
| `DatabaseInfo` | Thông tin DB đã nạp (tên, đường dẫn, version) |

**Cấu hình quét:**

| Class | Vai trò |
|-------|---------|
| `ScanOptions` | Tùy chọn người dùng: bật/tắt từng parser (`ScanArchive`, `ScanPE`, `ScanPDF`, `ScanHTML`, `ScanOneNote`, `ScanImageFuzzyHash`, …), heuristics (`EnableHeuristics`, `HeuristicExceedsMax`, `HeuristicEncryptedArchive/Doc`, `HeuristicPrecedence`), `DetectPUA`, `CollectAllMatches`, `MaxThreads`, `Recursive`, `FollowSymlinks`, `ExcludeDirectories/Extensions`, `YaraRuleDirectory`, `BytecodeDirectory`, `ContentScanners`. Mặc định bám ClamAV 1.5.x. `Default` trả về instance mới mỗi lần truy cập. |
| `ScanLimits` | Trần an toàn: `MaxArchiveDepth` (mặc định 17, validate 1..100), `MaxFileSize`, `MaxScanSize`, `MaxFiles`, `MaxFullBufferSize`, `MaxArchiveEntries`, `MaxArchiveExpandedBytes`, `MaxArchiveCompressionRatio`, `MaxEmbeddedStreamSize`, `MaxHtmlNormalize`, `StreamChunkSize`, `MaxFlexibleLookbehind`, `MaxPatternMatchesPerSignature`, `MaxLogicalDepth`… `Validate()` **recover** `MaxFileSize` về `[1GiB, 2GiB]` thay vì fail. |
| `UpdateOptions` | Tùy chọn update DB. |

`ScanOptions.MaxRecursion` (mặc định 17) được merge vào limits qua
`CreateEffectiveLimits()`: `MaxArchiveDepth = min(limits, MaxRecursion)` — mọi giới hạn cuối cùng
đi qua một điểm này.

**Contract mở rộng:**

```csharp
public interface IContentScanner
{
    IReadOnlyList<Detection> Scan(byte[] data, string path, CancellationToken ct);
    string Directory { get; }
}
```

Cho phép gắn scanner ngoài (Yara, Bytecode) vào pipeline qua `ScanOptions.ContentScanners`.

**Policy lọc detection:**

| Hàm | Vai trò |
|-----|---------|
| `IsPuaName(name)` | Nhận diện tiền tố `PUA.` |
| `IsHeuristicName(name)` / `IsHeuristic(detection)` | Nhận diện detection dạng heuristic (`Heuristics.*`) |
| `ScanOptions.FilterDetections(list)` | Áp dụng PUA/heuristic policy: `DetectPUA=false` lọc PUA nhưng giữ malware; `HeuristicExceedsMax=false` lọc heuristic; có `HeuristicPrecedence` cho phép heuristic thắng trước |
| `ScanOptions.HasBlockingDetections(list)` | Có detection "chặn" (malware, hoặc PUA/heuristic nếu bật) — dùng cho short-circuit early-exit |
| `IsExcludedDirectory(root, fullPath, excludes)` | Match **đúng path segment** (không substring), gồm cả hậu duệ |

📌 Chi tiết ngữ nghĩa offset/pattern của database xem
[`daily_CVD_Signature_Format_Analysis.md`](./daily_CVD_Signature_Format_Analysis.md).

---

## 3. Quy ước thiết kế

1. **Immutable result**: `Detection`/`ScanResult` là record — an toàn truyền qua thread, không
   ai mutate kết quả người khác.
2. **Validate-recover, không throw tùy tiện**: `ScanLimits.Validate()` normalize giá trị phi logic
   (≤ 0, overflow int) về default an toàn — quét tiếp thay vì crash (test
   `Program.ScanOptionsTests.cs` khóa hành vi này, kể cả case `MaxFileSize` âm do overflow).
3. **Một điểm cấu hình**: `Directory.Build.props` ở root áp cho mọi project — project này chủ động
   không khai báo gì thêm để kế thừa (`Nullable`, `TreatWarningsAsErrors`).
4. **Không dependency ngoài**: giữ project này *payload-free* để mọi tầng khác dùng được mà không
   kéo package.

## 4. Kiểm thử

Được phủ gián tiếp qua **mọi** suite trong `tests/ClamGuard.Tests` (mọi pipeline đều đi qua
`ScanOptions`/`ScanLimits`/`ScanVerdict`), và trực tiếp qua `Program.ScanOptionsTests.cs`
(24 assertion: defaults so với ClamAV 1.5.x, merge limits, PUA precedence, exclusion semantics,
normalization overflow/2 GiB ceiling…).
