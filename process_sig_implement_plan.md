# Kế Hoạch Tái Cấu Trúc & Module Hóa Hệ Thống Xử Lý Chữ Ký ClamAV (ClamGuard.Net)

`File: process_sig_implement_plan.md`

Tài liệu này chi tiết hóa toàn bộ hiện trạng, cấu trúc các loại tệp chữ ký ClamAV trích xuất trong thư mục cache (`C:\ProgramData\ClamGuard\cache\daily_28146_f035c4fd10fd33f9fadd5905acb78b7e`), thống kê các file mã nguồn hiện đang vượt quá 700 dòng trong hai project `ClamGuard.Scanner` và `ClamGuard.Signatures`, cùng lộ trình module hóa từng bước theo loại chữ ký và chức năng tái sử dụng.

> **Ghi chú cập nhật:** Đây là tài liệu phân tích/kế hoạch ban đầu; cấu trúc đã triển khai hiện tại được mô tả trong [`docs/architecture/source-structure.md`](docs/architecture/source-structure.md). Các hậu tố `.hdu`, `.hsu`, `.ndu`, `.ldu`, `.mdu`, `.msu` thuộc họ cơ sở dữ liệu PUA, không phải định dạng cập nhật gia tăng.

---

## 1. Bảng Phân Tích Toàn Bộ Các Loại Chữ Ký ClamAV Trong Thư Mục Cache

Dưới đây là danh sách toàn bộ các loại tệp thực tế có trong thư mục cache cơ sở dữ liệu `daily`:

| Tên tệp trong cache                              | Loại chữ ký           | Ý nghĩa & Cấu trúc dữ liệu                                                                                                                                                                | Kích thước mẫu                     | Nơi xử lý hiện tại                                         | Đề xuất module đích                            |
| :------------------------------------------------- | :----------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------- | :-------------------------------------------------------------- | :-------------------------------------------------- |
| **`daily.hdb`** / **`daily.hdu`**  | Hash / PUA Hash Database | `.hdb` chứa hash của tệp thông thường; `.hdu` thuộc họ chữ ký PUA. Mã băm (MD5 / SHA1 / SHA256) của toàn bộ file. Định dạng:`Hash:FileSize:VirusName[:MinFLevel[:MaxFLevel]]`                                                            | 1.6 KB / 2.5 KB                        | `SignatureParser.cs` & `CompiledSignatureSet.cs`            | `ClamGuard.Signatures/Parsing/Hash/`                        |
| **`daily.hsb`** / **`daily.hsu`**  | Hash / PUA Hash Signature Database | `.hsb` chứa SHA-256 hash cho file theo định dạng HSB; `.hsu` thuộc họ chữ ký PUA tương ứng.                                                                            | **3.88 MB** / 89 B               | `SignatureParser.cs` & `CompiledSignatureSet.cs`            | `ClamGuard.Signatures/Parsing/Hash/`                        |
| **`daily.mdb`** / **`daily.mdu`**  | Section MD5 / PUA          | `.mdb` chứa MD5 hash của từng section PE; `.mdu` thuộc họ chữ ký PUA tương ứng. Định dạng:`SectionSize:MD5:VirusName`                                                                                  | **744 KB** / 20 KB               | `SignatureParser.cs` & `PeSpecialized.cs`                   | `ClamGuard.Signatures/Parsing/Hash/` & `ClamGuard.Scanner/Pe/`      |
| **`daily.msb`** / **`daily.msu`**  | Section SHA256 / PUA       | `.msb` chứa SHA-256 hash của từng section PE; `.msu` thuộc họ chữ ký PUA tương ứng. Định dạng:`SectionSize:SHA256:VirusName`                                                                                                 | 161 B / 92 B                           | `SignatureParser.cs` & `PeSpecialized.cs`                   | `ClamGuard.Signatures/Parsing/Hash/` & `ClamGuard.Scanner/Pe/`      |
| **`daily.fp`** / **`daily.sfp`**   | False Positive / Soft FP | Whitelist mã băm an toàn tuyệt đối. Định dạng:`Hash:Size:Label`. Khớp mẫu này sẽ lập tức dừng quét và gán nhãn `Clean / Trusted`.                                       | 26.3 KB / 87 B                         | `SignatureParser.cs` & `CompiledSignatureSet.cs`            | `ClamGuard.Signatures/Parsing/Hash/`                        |
| **`daily.ndb`** / **`daily.ndu`**  | Normal / PUA Database     | `.ndb` chứa hex-pattern signatures theo offset hoặc floating; `.ndu` thuộc họ chữ ký PUA tương ứng. Định dạng:`Name:Target:Offset:HexPattern[:MinFLevel[:MaxFLevel]]`                                                              | 198 KB / 823 KB                        | `SignatureParser.cs` & `ScannerEngine.cs`                   | `ClamGuard.Signatures/Parsing/Content/Ndb/` & `ClamGuard.Scanner/Content/` |
| **`daily.sdb`**                            | Self-Protection NDB      | Chữ ký nhị phân bảo vệ chính ClamAV, được chạy quét ở Raw layer trước khi giải nén các lớp con.                                                                              | *(Khi có)*                          | `SignatureParser.cs` & `ScannerEngine.cs`                   | `ClamGuard.Signatures/Parsing/Content/Ndb/`                         |
| **`daily.ldb`** / **`daily.ldu`**  | Logical / PUA Database    | `.ldb` chứa chữ ký logic (76.8 MB trong mẫu); `.ldu` thuộc họ chữ ký PUA tương ứng, không phải bản vá cập nhật gia tăng. Gồm Target, Subsignatures, biểu thức Boolean (`0&1&2...`), Macro `$N$`, Byte-compare, PCRE Regex, Icon/Fuzzy Image. | **76.82 MB** / **3.52 MB** | `SignatureParser.cs`, `LdbRuntime.cs`, `ScannerEngine.cs` | `ClamGuard.Signatures/Parsing/Content/Ldb/` & `ClamGuard.Scanner/Content/Logical/`  |
| **`daily.cdb`**                            | Container Database       | Chữ ký phân tích thuộc tính metadata vùng nén/container (kích thước nén, tỷ lệ nén, số file con, mã hóa password).                                                            | 491 B                                  | `SignatureParser.cs`, `ArchiveScanner.cs`                   | `ClamGuard.Signatures/Parsing/Container/`                   |
| **`daily.crb`**                            | Container Rules          | Luật phân tích giới hạn cấu trúc file nén container.                                                                                                                                    | 21.3 KB                                | `SpecializedFileHandlers.cs`                                  | `ClamGuard.Scanner/Containers/`                             |
| **`daily.ftm`**                            | File Type Magic          | CSDL nhận diện định dạng file dựa vào magic bytes nhị phân.                                                                                                                            | 20.0 KB                                | `FileTypeMagicDetector.cs`                                    | `ClamGuard.Scanner/Detection/`                              |
| **`daily.idb`**                            | Icon Database            | Dữ liệu so khớp Icon đồ họa để phát hiện tệp giả mạo biểu tượng Windows PE.                                                                                                     | 36.4 KB                                | `IconDatabase.cs`, `LdbRuntime.cs`                          | `ClamGuard.Scanner/Image/`                                  |
| **`daily.ign`** / **`daily.ign2`** | Ignore Database          | Danh sách chữ ký cần vô hiệu hóa / bỏ qua do trùng lặp hoặc lỗi thời.                                                                                                              | 29 B / 554 B                           | `DatabaseLoader.cs`                                           | `Signatures/Parsing/`                             |
| **`daily.wdb`**                            | Whitelist Database       | Danh sách domain / URL sạch whitelist.                                                                                                                                                        | 10.7 KB                                | `DatabaseLoader.cs`                                           | `Signatures/Parsing/`                             |

---

## 2. Thống Kê Các File Mã Nguồn Hiện Đang Vượt Quá 1.000 Dòng

| File                                                              | Số dòng hiện tại  | Trách nhiệm chính hiện tại                        | Các khối code bị "ôm đồm" cần bóc tách                                                                                                                                                                                                                                      |
| :---------------------------------------------------------------- | :-------------------- | :----------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`src/ClamGuard.Scanner/ArchiveScanner.cs`**             | **2,086 dòng** | Bộ quét đệ quy các tệp nén / container          | Chứa code parser giải nén nội bộ cho hàng chục định dạng khác nhau: ZIP, RAR, 7z, TAR, GZ, ISO9660, UDF, DMG, CHM, OLE/MS Office, PDF, SWF, XAR.                                                                                                                          |
| **`src/ClamGuard.Scanner/ScannerEngine.cs`**              | **1,725 dòng** | Bộ điều phối luồng quét chính (`ScanAsync`)   | - Bộ Lexer + Parser phân tích cú pháp biểu thức logic (`0&1&...`).- Matcher PCRE Regex.- Thuật toán bóc tách PE Overlay.- Thuật toán bóc tách Mach-O Fat Slices.                                                                                                    |
| **`src/ClamGuard.Scanner/LdbRuntime.cs`**                 | **1,435 dòng** | Cung cấp ngữ cảnh runtime cho luật LDB             | - Toàn bộ thuật toán xử lý ảnh số:**Biến đổi cosine rời rạc 2D (DCT)** (dòng 1460-1495).- Bộ nội suy ảnh **Lanczos-3 resampling & kernel weights builder** (dòng 1496-1575) để tạo mã băm fuzzy icon.- Parser PE header & Mach-O header nội bộ. |
| **`src/ClamGuard.Signatures/Parsing/SignatureParser.cs`** | **1,145 dòng** | Bộ phân tích cú pháp text của toàn bộ chữ ký | Gom toàn bộ hàm parse của Hash (`.hdb`, `.hsb`, `.mdb`, `.msb`, `.fp`, `.imp`), Ndb (`.ndb`, `.sdb`), Ldb (`.ldb`, `.ldu`), Container (`.cdb`, `.zmd`, `.rmd`) vào chung 1 static class khổng lồ.                                                   |

---

## 3. Kiến Trúc Đề Xuất Sau Khi Tái Cấu Trúc (Module Hóa)

### 3.1. Project `ClamGuard.Signatures`

Tách `SignatureParser.cs` thành cấu trúc module hóa phân cấp:

```
src/ClamGuard.Signatures/
├── Parsing/
│   ├── SignatureParser.cs              # [Facade] Điều phối chính theo extension (.hdb, .ldb, v.v.), chỉ ~50-80 dòng
│   ├── Common/
│   │   ├── SignatureParserCommon.cs    # Các hàm dùng chung: ParseUInt, ParseSize, TryGetAlgorithm, ParseHex
│   │   └── HexPatternParser.cs         # Đã có sẵn: phân tích pattern hex nhị phân
│   ├── Hash/                           # Xử lý .hdb, .hsb, .hdu, .hsu, .fp, .sfp, .mdb, .msb, .imp
│   │   └── HashSignatureParser.cs      # Chuyên biệt bóc tách các trường băm SHA/MD5, section sizes
│   ├── Ndb/                            # Xử lý .ndb, .ndu, .sdb
│   │   └── NdbSignatureParser.cs       # Chuyên biệt bóc tách NDB fixed/floating hex patterns, macro groups
│   ├── Ldb/                            # Xử lý .ldb, .ldu
│   │   ├── LdbSignatureParser.cs       # Bóc tách cấu trúc tổng thể LDB (Name;Target;Expression;Subsignatures)
│   │   ├── LdbTargetParser.cs          # Bóc tách metadata Target:1, Engine:..., MinSize/MaxSize
│   │   └── LdbSubsigParser.cs          # Bóc tách từng loại subsignature: Hex, Macro $N$, Regex, ByteCompare
│   └── Container/                      # Xử lý .cdb, .zmd, .rmd
│       └── ContainerSignatureParser.cs # Bóc tách quy tắc kiểm tra container
```

### 3.2. Project `ClamGuard.Scanner`

Tách rời các khối thuật toán độc lập và phân chia theo loại chữ ký / chức năng:

```
src/ClamGuard.Scanner/
├── ScannerEngine.cs                    # Giữ vai trò Pipeline điều phối tổng thể (gọn gàng ~700 dòng)
├── Logical/                            # Chuyên sâu cho chữ ký .ldb
│   ├── LogicalExpressionEvaluator.cs   # Bóc từ ScannerEngine: Lexer, Parser boolean AST (Or, And, Not, Match count)
│   ├── LogicalContentMatcher.cs        # Matcher SIMD / AVX2 cho subsignatures
│   └── RegexContentMatcher.cs          # Matcher PCRE cho regex subsignatures
├── Image/                              # Bóc từ LdbRuntime: Xử lý đồ họa & Fuzzy Hash
│   └── FuzzyImageHasher.cs             # Chứa DCT 2D, Lanczos-3 resizer, Kernel weights, Image perceptual hash
├── Pe/                                 # Chuyên biệt cho chữ ký PE (.mdb, .msb, .imp, Overlay)
│   ├── PeSpecialized.cs                # Đã có sẵn: Section MD5/SHA256 matching
│   └── PeOverlayScanner.cs             # Bóc từ ScannerEngine: Quét vùng Overlay của PE file
├── Containers/                         # Bóc tách từ ArchiveScanner.cs khổng lồ (2,086 dòng)
│   ├── ArchiveScanner.cs               # Điều phối duyệt đệ quy (giảm xuống < 800 dòng)
│   ├── IsoDmgExtractor.cs              # Trích xuất riêng định dạng ISO9660, UDF, DMG (hệ thống đĩa)
│   ├── OfficeOleExtractor.cs           # Trích xuất riêng OLE2, RTF, Microsoft Office
│   └── PdfSwfExtractor.cs              # Trích xuất riêng PDF, SWF, compressed streams
└── LdbRuntime.cs                       # Giữ lại thuần túy context LdbScanContext & offset evaluation (~600 dòng)
```

---

## 4. Bảng Kế Hoạch Triển Khai Chi Tiết Từng Bước (Implementation Steps)

| Giai đoạn        | Thao tác chi tiết                                                                                                                                                                                                                                                                                                                                                        | Mục tiêu kiểm tra                                                                                                                  | Mức độ rủi ro                                                        |
| :----------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------- |
| **Bước 1** | **Bóc tách thuật toán Fuzzy Image Hash khỏi `LdbRuntime.cs`**:- Tạo `src/ClamGuard.Scanner/Image/FuzzyImageHasher.cs`.- Di chuyển các hàm `ComputeDct2`, `ResizeLanczos3`, `BuildWeights`, `Lanczos`, `ClampByte`, struct `RgbImage` sang file mới.- Gọi `FuzzyImageHasher.ComputeDct2(...)` từ `LdbRuntime.cs`.                     | Giảm ngay ~200 dòng trong`LdbRuntime.cs`. Chạy `dotnet test` kiểm tra toàn bộ suite test không đổi verdict.              | Thấp (0% phá vỡ API bên ngoài).                                     |
| **Bước 2** | **Module hóa `SignatureParser.cs` trong `ClamGuard.Signatures`**:- Tạo thư mục `Parsing/Common/`, `Parsing/Hash/`, `Parsing/Content/Ndb/`, `Parsing/Content/Ldb/`, `Parsing/Container/`.- Tách logic parse theo đúng bảng đối chiếu Mục 3.1.- `SignatureParser.cs` đóng vai trò chuyển tiếp gọi sang các class mới.                              | Giảm`SignatureParser.cs` từ 1,145 dòng xuống < 100 dòng. Đảm bảo tốc độ và tính toàn vẹn khi load cache `daily.*`. | Rất thấp (Logic giữ nguyên, chỉ phân tách class static/internal). |
| **Bước 3** | **Tách bộ xử lý biểu thức Logical & Overlay khỏi `ScannerEngine.cs`**:- Tạo `src/ClamGuard.Scanner/Content/Logical/LogicalExpressionEvaluator.cs`, chuyển toàn bộ logic parser cú pháp boolean (`TokenKind`, `Lexer`, `ParseOr`, `ParsePrimary`, `EvalValue`).- Tạo `src/ClamGuard.Scanner/Pe/PeOverlayScanner.cs` bóc tách xử lý overlay. | Giảm`ScannerEngine.cs` từ 1,725 dòng xuống ~800 dòng. Code gọn gàng, luồng scan đọc dễ hiểu.                            | Thấp.                                                                   |
| **Bước 4** | **Phân tách các Extractor chuyên biệt trong `ArchiveScanner.cs`**:- Tạo thư mục `Containers/` tách phần xử lý ISO/DMG/UDF và OLE/Office ra các class riêng biệt.                                                                                                                                                                                 | Giảm`ArchiveScanner.cs` từ 2,086 dòng xuống < 800 dòng. Dễ dàng bảo trì và bổ sung định dạng mới.                    | Trung bình (cần chạy test archive regression).                        |
| **Bước 5** | **Biên dịch & Chạy Regression Test**:- Chạy `dotnet build -c Release` (yêu cầu 0 lỗi, 0 cảnh báo).- Chạy toàn bộ test `dotnet test` (yêu cầu 100% tests Passed).                                                                                                                                                                                   | Đảm bảo hiệu năng và độ ổn định nguyên vẹn.                                                                              | Không.                                                                  |

---

## 5. Nguyên Tắc Thiết Kế Áp Dụng (Design Principles)

1. **Single Responsibility Principle (SRP)**: Mỗi file parser hoặc matcher chỉ xử lý duy nhất 1 nhóm chữ ký có cùng cơ chế hoạt động.
2. **Reuse Common Utilities (DRY)**: Các phép toán phân tích số nguyên (`ParseUInt`), quy đổi kích thước byte (`ParseSize`), nhận diện mã băm (`TryGetAlgorithm`) chỉ viết một lần duy nhất trong `SignatureParserCommon`.
3. **No Performance Degradation**: Không tạo thêm overhead boxing/unboxing hay cấp phát mảng thừa. Sử dụng `ReadOnlySpan<byte>` và `ref struct` ở các vùng xử lý nhị phân quan trọng.
4. **Preserve Compatibility**: Đảm bảo toàn bộ chữ ký trong cơ sở dữ liệu `daily` của ClamAV đều được nạp đầy đủ và chính xác 100% như hành vi chuẩn của ClamAV C/C++.
