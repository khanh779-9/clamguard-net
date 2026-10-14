# daily.cvd — Đặc tả định dạng chữ ký ClamAV (bản gộp)

> **Nguồn tài liệu**: gộp hai bản phân tích độc lập của Claude và ChatGPT về cùng một gói
> `daily.cvd` (**build 28146**, 07 Oct 2026, 23 439 346 byte, functionality level 90),
> sau đó **đối chiếu lại với mã nguồn ClamAV 1.5.4** và với engine **ClamGuard.NET** của repo này.
>
> **Nhãn nguồn thông tin** dùng xuyên suốt:
>
> | Nhãn | Ý nghĩa |
> |------|---------|
> | 📏 **Đo từ dữ liệu** | Số liệu đếm trực tiếp trên đúng gói daily.cvd build 28146 (thay đổi theo từng bản cập nhật) |
> | 📚 **Tài liệu** | Ngữ nghĩa theo tài liệu chính thức ClamAV (docs.clamav.net), không suy ra được từ dữ liệu |
> | ✅ **Đối chiếu source** | Đã kiểm chứng trực tiếp trong mã nguồn ClamAV 1.5.4 (`libclamav/`) |
> | 🛠️ **ClamGuard** | Phần đã được cài đặt trong repo này — trỏ tới file/class tương ứng |
>
> Tài liệu này là **quy luật đối chiếu** cho engine C#: mô tả cấu trúc từng file DB, định dạng từng
> record, ngữ nghĩa so khớp và các bẫy khi viết parser/matcher.

---

## Mục lục

1. [Container CVD](#1-container-cvd)
2. [Quy ước chung của mọi file DB](#2-quy-ước-chung)
3. [Bảng tổng hợp 25 file trong archive](#3-bảng-tổng-hợp-file)
4. [Chữ ký hash toàn file: `.hdb/.hdu/.hsb/.hsu`](#4-hash-toàn-file)
5. [Chữ ký hash section PE: `.mdb/.mdu/.msb/.msu`](#5-hash-section-pe)
6. [Whitelist hash: `.fp/.sfp`](#6-whitelist-hash)
7. [Chữ ký body: `.ndb/.ndu`](#7-ndbndu--chữ-ký-body)
8. [Chữ ký logic: `.ldb/.ldu`](#8-ldbldu--chữ-ký-logic)
9. [Metadata container: `.cdb`](#9-cdb--metadata-container)
10. [Chữ ký icon: `.idb`](#10-idb--chữ-ký-icon)
11. [Chứng chỉ PE: `.crb`](#11-crb--chứng-chỉ)
12. [File type magic: `.ftm`](#12-ftm--file-type-magic)
13. [Anti-phishing: `.pdb`, `.wdb`](#13-anti-phishing)
14. [Cấu hình & ignore: `.cfg`, `.ign`, `.ign2`](#14-cấu-hình--ignore)
15. [`daily.info` và `COPYING`](#15-dailyinfo-và-copying)
16. [Bẫy gặp trong dữ liệu thật](#16-bẫy-trong-dữ-liệu-thật)
17. [Hướng dẫn triển khai C#](#17-hướng-dẫn-triển-khai-c)
18. [Kế hoạch kiểm thử](#18-kế-hoạch-kiểm-thử)
19. [Bảng tra nhanh](#19-bảng-tra-nhanh)
20. [Phụ lục: mẫu 1 dòng từng loại](#20-phụ-lục--mẫu-1-dòng-từng-loại)
21. [Tài liệu tham khảo chính thức](#21-tài-liệu-tham-khảo)

---

## 1. Container CVD

CVD **không phải ZIP**: 512 byte đầu là header ASCII, phần còn lại là `tar.gz`.

```
[0x000 .. 0x1FF]  Header 512 byte, ASCII, đệm dấu cách (0x20) tới đủ 512
[0x200 .. EOF  ]  Payload = gzip chứa tar archive (bắt đầu bằng 1F 8B 08)
```

Header tách bằng `:` thành **9 trường**:

| # | Trường | Giá trị trong gói này | Ghi chú |
|---|--------|------------------------|---------|
| 0 | Magic | `ClamAV-VDB` | cố định |
| 1 | Build time | `07 Oct 2026 06-24 +0000` | định dạng `dd Mon yyyy HH-mm +zzzz` (dấu `-` giữa giờ:phút) |
| 2 | Version | `28146` | số bản dựng |
| 3 | Số chữ ký | `355728` | 📏 **không bằng** tổng dòng dữ liệu (356 255) — xem §16.1, đừng assert |
| 4 | Functionality level | `90` | engine có FLevel < 90 phải từ chối DB |
| 5 | MD5 payload | `f035c4fd10fd33f9fadd5905acb78b7e` | ✅ = MD5 của mọi byte từ offset 512 (đã kiểm chứng cả 2 bản phân tích) |
| 6 | DSIG (base64) | ~170 ký tự | chữ ký RSA của MD5 payload |
| 7 | Builder | `svc.clamav-publisher` | |
| 8 | Build time (epoch) | `1791354258` | = 2026-10-07 06:24:18 UTC |

**Tính toàn vẹn** (đã thực hiện trên gói này):
- 📏 23/23 file DB liệt kê trong `daily.info` khớp **kích thước + SHA-256**.
- 📏 MD5 payload khớp trường 5 của header.
- ⚠️ **Chưa xác minh DSIG** bằng public key của ClamAV — checksum chỉ chứng minh tính nhất quán
  header/payload, **không thay thế xác minh nguồn gốc**. Cần `sigtool` hoặc public key ClamAV.
  🛠️ ClamGuard: `ClamGuard.Database/Verification/ClamAvSignatureVerifier.cs` (RSA-PSS chuẩn RFC 8017
  cho `.info`, raw-RSA/MD5 cho dsig CVD) + `DatabaseVerifier.cs` (manifest).

**Giải nén**:

```bash
sigtool --info daily.cvd      # cơ chế chính thức khi có ClamAV
sigtool --unpack daily.cvd
# hoặc thủ công:
tail -c +513 daily.cvd | tar -xzf -
```

📌 Lưu ý tar: các file member có **mode 000** và mtime 1970 → trên Linux phải `chmod` sau khi giải nén.
Trong C# dùng `System.Formats.Tar` + `GZipStream` đọc thẳng stream, không cần ghi đĩa.
🛠️ ClamGuard: `ClamGuard.Database/Loading/CvdReader.cs` (đã cap kích thước, bounds-check header).

---

## 2. Quy ước chung

📏 Đo trên toàn bộ 24 file (build 28146):

- **Chỉ ASCII** (0 byte ≥ 0x80), **LF** là kết thúc dòng (0 dòng có CR), dòng cuối có `\n`.
  Phòng thủ: `TrimEnd('\r')` khi đọc — bản DB khác có thể dùng CRLF.
- Dòng bắt đầu `#` là **comment**. Gặp ở: `.cdb`, `.cfg`, `.crb`, `.idb`
  (đúng 1 dòng: `# There must always be one line in the file`). Không có dòng rỗng.
- Hầu hết file là `Trường1:Trường2:...` phân tách bằng **`:`**. Riêng `.ldb/.ldu/.crb` dùng **`;`**.
- **Hậu tố FLevel tùy chọn** cuối dòng: `:MinFLevel[:MaxFLevel]` — engine có FLevel ngoài khoảng
  (inclusive) thì **bỏ qua chữ ký đó** (không fail file). Một số file cho phép trường FLevel **rỗng**
  (xem §12 `.ftm`).
- Hex **không phân biệt hoa/thường** (`.ldb` có lẫn `6475706C` và `6475706c`); hash trong file băm
  đều lowercase nhưng nên so case-insensitive.
- Tên mã độc theo mẫu `Platform.Category.Family-ID-Variant` (ví dụ `Win.Ransomware.RansomHub-10037316-0`,
  `PUA.Win.Tool.ANVCracker-1`). Tiền tố **`PUA.`** = chỉ bật khi quét PUA.
  ⚠️ Tên **có thể chứa khoảng trắng** (📏 1 dòng `.ldb`: `Win.Loader. BadiisSet-10060291-1`) —
  đừng giả định tên không có space, đừng `\S+` trong regex kiểm tra.
- 📚 Hậu tố **`u`** (`.hdu .hsu .mdu .msu .ndu .ldu`) = bản **PUA/unofficial** của cùng định dạng —
  nạp riêng, chỉ bật bằng tùy chọn PUA. 🛠️ ClamGuard: `ScanOptions` PUA + `IncludePuaCategories`.
- 📚 `.hsb/.msb/.hsu/.msu/.sfp` = bản "**s**ha": **độ dài chuỗi hex quyết định thuật toán**
  (32 = MD5, 40 = SHA-1, 64 = SHA-256) — không suy luận từ extension.

---

## 3. Bảng tổng hợp file

📦 Giải nén được **25 file**: 23 file DB theo `daily.info` + `daily.info` + `COPYING`.

| File | Kích thước (byte) | Dòng | Phân tách | Trường | Loại chữ ký |
|------|------------------:|-----:|-----------|--------|-------------|
| `daily.hdb` | 1 640 | 23 | `:` | 3 | Hash MD5 toàn file |
| `daily.hdu` | 2 525 | 39 | `:` | 3 | Hash MD5 toàn file (PUA) |
| `daily.hsb` | 3 883 885 | 54 681 | `:` | 3 hoặc 4 | Hash MD5/SHA1/SHA256 toàn file (+FLevel) |
| `daily.hsu` | 89 | 1 | `:` | 3 | Như hsb (PUA) — chỉ dòng EICAR |
| `daily.mdb` | 744 257 | 11 575 | `:` | 3 | Hash MD5 **section PE** |
| `daily.mdu` | 19 999 | 315 | `:` | 3 | Như mdb (PUA) |
| `daily.msb` | 161 | 2 | `:` | 3 hoặc 4 | Hash section PE (MD5/SHA) |
| `daily.msu` | 92 | 1 | `:` | 3 | Như msb (PUA) |
| `daily.fp` | 26 373 | 483 | `:` | 3 | Whitelist hash MD5 (false-positive) |
| `daily.sfp` | 87 | 1 | `:` | 3 | Whitelist hash SHA |
| `daily.ndb` | 198 238 | 319 | `:` | 4/5/6 | Chữ ký hex theo body/offset |
| `daily.ndu` | 823 292 | 4 159 | `:` | 4/5/6 | Như ndb (PUA) |
| `daily.ldb` | 76 829 701 | 273 473 | `;` | 4 → 66 | Chữ ký logic (96 % tổng chữ ký) |
| `daily.ldu` | 3 528 282 | 10 166 | `;` | 4 → 23 | Như ldb (PUA) |
| `daily.cdb` | 491 | 6 | `:` | 10 | Metadata file trong container |
| `daily.idb` | 36 469 | 223 | `:` | 4 | Chữ ký icon (fuzzy hash) |
| `daily.crb` | 21 363 | 31 | `;` | 11 | Chứng chỉ số (trusted / revoked) |
| `daily.ftm` | 20 097 | 268 | `:` | 6/7/8 | Magic nhận dạng loại file |
| `daily.pdb` | 4 094 | 263 | `:` | 2 | Anti-phishing: danh sách host |
| `daily.wdb` | 10 745 | 185 | `:` | 3 | Anti-phishing: allow-list URL |
| `daily.cfg` | 424 | 22 | `:` | 4 | Cấu hình DCONF theo FLevel |
| `daily.ign` | 29 | 1 | `:` | 3 | Ignore legacy (theo DB:dòng) — chỉ dòng giả |
| `daily.ign2` | 554 | 22 | – | 1 | Ignore theo tên chữ ký |
| `daily.info` | 2 285 | 25 | `:` | 3 | Manifest (kích thước + SHA256 từng file) |
| `COPYING` | 17 992 | 340 | – | – | GPLv2, không phải chữ ký |

📚 **Không xuất hiện trong gói này** (nhưng ClamAV hỗ trợ ở cấp engine): `.cbc` (bytecode), `.gdb`,
`.imp` (import hash), `.yar/.yara`, `.wdb` dạng `Y:`… Sự vắng mặt không có nghĩa không cần hỗ trợ.
🛠️ ClamGuard: đã hỗ trợ `.gdb`, `.imp`, `.cbc` và (subset) `.yara` ở tầng loader/engine.

---

## 4. Hash toàn file

### 4.1 `.hdb` / `.hdu` — MD5 toàn file

```
MD5:FileSize:MalwareName
```

📏 23/23 và 39/39 dòng: hash đúng 32 hex, FileSize là số thập phân, không dòng nào có hậu tố FLevel.

```text
44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature
```

**Quy tắc**: tính MD5 của đúng đối tượng đang quét; nếu `(size, md5)` khớp bảng → phát hiện.
Index theo `Dictionary<(long size, string md5), ...>`, tách bảng theo độ dài hash.

### 4.2 `.hsb` / `.hsu` — MD5/SHA1/SHA256 toàn file

```
HASH:FileSize:MalwareName[:MinFL[:MaxFL]]
```

📏 Số liệu `.hsb` (54 681 dòng):

| Đặc điểm | Số lượng |
|----------|---------:|
| Hash 32 hex (MD5) | 54 584 |
| Hash 40 hex (SHA-1) | 2 |
| Hash 64 hex (SHA-256) | 95 |
| 3 trường (không FLevel) | 1 (dòng EICAR SHA-256) |
| MinFL = 73 / 90 / 74 / 81 | 54 614 / 49 / 15 / 2 |
| FileSize = `*` (bất kỳ) | 2 (CVE_2020_1381, CVE_2020_1529) |

⚠️ 📚 Khi size là `*`, tài liệu **bắt buộc** có MinFLevel (chống FP) — dòng nào không có sẽ bị
loader từ chối. Không dòng nào có MaxFL trong gói này.

⚠️ 📚 Với HTML/text được engine normalize trước, hash phải áp dụng cho **dạng dữ liệu mà engine
hash**, không phải raw file — hash raw sẽ không tương đương ClamAV.
🛠️ ClamGuard: `HashSignatureParser.cs` (từ chối wildcard-size thiếu MinFL), index bucket
theo `(algorithm, size)` trong `CompiledSignatureSet.cs`.

### 4.3 Cách chọn thuật toán

| Độ dài hex | Thuật toán |
|---:|---|
| 32 | MD5 |
| 40 | SHA-1 |
| 64 | SHA-256 |

---

## 5. Hash section PE

### 5.1 `.mdb` / `.mdu` / `.msb` / `.msu`

```
PESectionSize:SectionHash:MalwareName[:MinFL[:MaxFL]]
```

⚠️ **Thứ tự NGƯỢC với `.hdb`: size đứng TRƯỚC hash.**

📏 `.mdb`: 11 575 dòng, đều 3 trường, hash 32 hex (MD5). `.mdu`: 315 dòng tương tự.
📏 `.msb`: 2 dòng — 1 SHA-256 (EICAR, 3 trường), 1 MD5 kèm MinFL 73. `.msu`: 1 dòng EICAR SHA-256.

```text
45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Eicar-Test-Signature
91648:550a9b573224aa75418c852080b59af3:Win.Packer.Agent-6412293-0:73
```

📚 Hash tính trên **raw data của từng section PE** (không nhầm file offset với RVA/virtual size).
📚 Tài liệu ClamAV ghi nhận hạn chế hash section cho **PE32+ 64-bit** ở một số phiên bản — nếu cần
tương thích kết quả, kiểm thử bằng engine đích thay vì giả định PE 64-bit xử lý giống 32-bit.
🛠️ ClamGuard: `PeSpecializedMatcher.cs` (hash 1 lần/thuật toán/section) + `PeSpecializedMatcher.Parsing.cs`.

---

## 6. Whitelist hash

### 6.1 `.fp` / `.sfp`

```
HASH:FileSize:SignatureID
```

📏 `.fp`: 483 dòng MD5. `.sfp`: 1 dòng SHA-256. Trường thứ 3 **không phải tên mã độc** mà là
**ID chữ ký bị loại trừ** dạng `sid25347313-1`, `sid177969901-1-6459222-0`.

```text
# daily.fp
332feab1435662fc6c672e25beb37be3:2871808:sid25347313-1
# daily.sfp — cùng một file, 2 loại hash
6bed1a3a956a859ef4420feb2466c040800eaf01ef53214ef9dab53aeff1cff0:2871808:sid25347313-1
```

**Quy tắc**: `(size, hash)` khớp whitelist → **xoá sạch kết quả phát hiện** của layer đó
(và theo ClamAV, bỏ luôn quét con/lồng). Tách luồng riêng khỏi bảng detection.
🛠️ ClamGuard: trust semantics trong `CompiledSignatureSet.cs` — `.fp/.sfp` khớp → `ScanVerdict.Trusted`,
xoá bằng chứng layer, dừng descender.

---

## 7. `.ndb`/`.ndu` — chữ ký body

```
MalwareName:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]
```

📏 Phân bố trường: `.ndb` 4 = 308, 5 = 6, 6 = 5; `.ndu` 4 = 4 147, 5 = 10, 6 = 2
(mọi dòng 6 trường có MaxFL = 255). MinFL gặp: ndb {90, 70, 81, 74, 51}; ndu {19, 18, 58, 32, 73, 74}.

### 7.1 TargetType

📚 Bảng target của ClamAV (= index trong `cli_mtargets[]` — ✅ đối chiếu `matcher.h` 1.5.4 khớp):

| Giá trị | Loại file đích |
|--------:|----------------|
| 0 | Bất kỳ file |
| 1 | PE (Windows exe/dll) |
| 2 | OLE2 (doc/xls cũ) |
| 3 | HTML |
| 4 | Mail |
| 5 | Graphics |
| 6 | ELF |
| 7 | ASCII text |
| 8 | (không dùng) |
| 9 | Mach-O |
| 10 | PDF |
| 11 | Flash |
| 12 | Java class |

📏 Phân bố: ndb 1→149, 2→42, 3→17, 5→1, 6→31, 7→50, 9→3, 10→3, 12→3, 0→20;
ndu 1→4 021, 0→42, 3→68, 7→18, 2→5, 6→2, 11→1, 12→2.

### 7.2 Offset — các dạng ✅ (đối chiếu `cli_caloff()` trong `matcher.c` 1.5.4)

| Dạng | Ví dụ | Số lượng (ndb/ndu) | Ý nghĩa |
|------|-------|--------------------|---------|
| `*` | `*` | 279 / 4 014 | Bất kỳ vị trí |
| `N` | `0` | 28 / 26 | Offset tuyệt đối |
| `N,M` | `120,136` | 3 / 3 | Bắt đầu ở N, **max shift** M → khớp trong `[N, N+M]` (inclusive) |
| `EP+N` / `EP-N` | `EP+192` | 3 / 112 | Entry point ± N (chỉ target PE/ELF/Mach-O) |
| `EP+N,M` | `EP+0,100` | 2 / 2 | EP + N, trượt tối đa M |
| `SEn` | `SE0` | 2 / 0 | Toàn bộ section n (raw; max mở rộng thêm shift) |
| `Sn+M` | `S0+780912` | 0 / 1 | Section n + M byte |
| `SL+N` | — | 0 / 0 | Section cuối + N (📚 có trong spec dù không gặp) |
| `EOF-N` | `EOF-16015` | 1 / 0 | Cách cuối file N byte (✅ **chỉ có dạng `EOF-n`, bare `EOF` không hợp lệ**) |
| `EOF-N,M` | `EOF-500,500` | 1 / 1 | |
| `VI` | — | (gặp ở LDB) | Trong vùng VersionInfo của PE |

✅ **Ngữ nghĩa dấu phẩy**: `cli_caloff()` tách `,` thành `offdata[2] = max shift`;
match hợp lệ khi `offset_min ≤ offset ≤ offset_max` (inclusive — `matcher-ac.c` dòng 1918).
`"100,50"` = khớp trong `[100, 150]`. **KHÔNG** phải danh sách rời rạc, cũng **không có** range `a-b`
trong NDB (`cli_isnumber("0-63")` fail → `CL_EMALFDB`).
✅ **Ràng buộc target**: `EP/SL/SE/S/VI` bị ClamAV **từ chối lúc load** nếu target ∉ {1, 6, 9}.
🛠️ ClamGuard: validate tại `NdbSignatureParser.cs` (khớp 1.5.4, gồm VI + target gate),
evaluate tại `LdbRuntime.ResolveOffset()` (context-aware cho PE/ELF/Mach-O) và
`OffsetAllows/OffsetAllowsStreaming` cho đường stream.

Regex kiểm tra (đã chạy trên toàn bộ dữ liệu, 📏 0 dòng sai trừ ngoại lệ §16):

```
^(\*|\d+(,\d+)?|EP[+-]\d+(,\d+)?|S\d+\+\d+(,\d+)?|SE\d+(,\d+)?|SL\+\d+(,\d+)?|EOF-\d+(,\d+)?)$
```

### 7.3 HexSignature — cú pháp pattern

| Cú pháp | Ý nghĩa | ndb / ndu (📏 dòng chứa) |
|---------|---------|--------------------------|
| `hh` | Byte hex (case-insensitive) | — |
| `??` | 1 byte bất kỳ | 42 / 1 851 |
| `a?`, `?a` | Nibble cao/thấp cố định, nibble kia bất kỳ | 44 / 1 852 |
| `*` | Bất kỳ số byte nào (≥ 0) | 63 / 56 |
| `{n}` | ✅ Đúng n byte bất kỳ (1.5.4 thay bằng `"??" × n`) | 36 / 1 728 |
| `{n-m}` | Từ n đến m byte | 87 / 1 780 |
| `{-m}` | Tối đa m byte (0..m) | 18 / 44 |
| `{n-}` | Tối thiểu n byte (📚 có trong spec) | 0 / 0 |
| `[n-m]` | ✅ Khoảng n–m byte — **cú pháp thật** (`cli_ac_addsig` chuyển thành gap; tối đa 2 lần dùng, giới hạn `AC_CH_MAXDIST`) | 0 / 1 (`eb0668[4-4]c3`) |
| `(aa\|bb\|…)` | Lựa chọn thay thế (fixed-length cho dạng negated/generic có ràng buộc riêng) | 6 / 10 |
| `!(aa\|bb)` | Phủ định (📚 chỉ hợp lệ dạng fixed-length) | 0 / 0 |
| `(B)` / `(L)` / `(W)` | Word-boundary / line-boundary (CR, CRLF, biên file) / non-alphanumeric | 0 / 0 |

📌 `{n}`, `{n-m}`, `*`, `{-m}` **không cùng ngữ nghĩa** — `*` không giới hạn độ dài. Wildcard chia
pattern thành nhiều đoạn; ClamAV yêu cầu độ dài byte cố định tối thiểu để index AC.
🛠️ ClamGuard: `HexPatternParser.cs` + `HexPattern.cs` (atoms, dual representation fixed/atoms,
`MaxBacktrackingStates` guard) + `AhoCorasick.cs`/`BoyerMooreHorspoolMatcher.cs` cho matching.

**Chiến lược matcher** (cả 2 bản phân tích cùng kết luận): đừng chuyển pattern thành `string.Contains`
hay regex .NET nguyên khối — tách thành đoạn hex thuần (lập chỉ mục **Aho-Corasick**) + gap/alternate
đánh giá backtracking có chặn; pattern không hiểu thì **từ chối có cảnh báo**, không giản lược thành
literal (sẽ ra âm tính giả).

---

## 8. `.ldb`/`.ldu` — chữ ký logic

Loại phức tạp nhất (📏 273 473 + 10 166 dòng = **96 % tổng chữ ký**).

```
SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;...;SubsigN
```

📏 Số trường: tối thiểu 4; ldb 4→66. Phổ biến: 8 trường (5 subsig) = 165 392; 6 trường = 93 269;
23 trường (20 subsig) = 6 186. **Không được giả định số trường cố định.**

```text
Swf.Exploit.CVE-2016-1013-1;Engine:73-255,Target:11;(0&1&2);8e0f006f...;7374617274005217...;6475706C...
```

### 8.1 TargetDescriptionBlock (TDB)

Danh sách `Khóa:GiáTrị` cách nhau bởi dấu `,` — parse thành dictionary, **không phụ thuộc thứ tự**
(📏 thứ tự phổ biến: `Engine,Target` = 271 392 dòng; 26 dòng ldb **không có Engine** → dùng mức tối thiểu).

| Khóa | Ý nghĩa | Số dòng ldb/ldu 📏 | Ví dụ |
|------|---------|--------------------|-------|
| `Target` | Loại file (bảng §7.1) — **bắt buộc** | 273 473 / 10 166 | `0..12` |
| `Engine` | Khoảng FLevel `min-max` | 273 447 / 9 838 | `51-255`, `73-255`, `150-255` |
| `Container` | Container trực tiếp | 1 697 / 4 | `CL_TYPE_ZIP`, `CL_TYPE_PDF`, `CL_TYPE_OOXML_WORD` |
| `FileSize` | Khoảng kích thước byte | 356 / 114 | `4096-16384` |
| `NumberOfSections` | Số section PE | 7 / 0 | `5-15` |
| `HandlerType` | Handler re-typing (không ra alert — engine quét lại theo type khác) | 3 / 1 | `CL_TYPE_PDF`, `CL_TYPE_SCRIPT` |
| `Intermediates` | Chuỗi container trung gian | 1 / 0 | `CL_TYPE_MSEXE>CL_TYPE_AUTOIT` |
| `IconGroup1/2` | Nhóm icon liên kết `.idb` | 0 / 1 | `SHARPHOUND` |
| `EntryPoint` | Điều kiện entry point (📚 có trong spec) | 0 / 0 | |

### 8.2 LogicalExpression

Toán hạng = chỉ số subsig. ✅ Parser của ClamAV **right-associative**: `0&1|2` ≡ `0&(1|2)`
(theo `cli_ac_chklsig`).

| Cú pháp | Ý nghĩa |
|---------|---------|
| `0` | Subsig 0 phải khớp |
| `0&1&2` | AND (📏 269 585 dòng dạng thuần AND) |
| `(0\|1)` | OR |
| `A=N` / `A=0` | Số lần khớp bằng N; `=0` = phủ định (không được khớp) |
| `A>N` / `A<N` | So sánh số lần khớp |
| `(…)>X,Y` | Nhóm: tổng lần khớp > X **và** ít nhất Y subsig khác nhau khớp |
| Ngoặc lồng | Nhóm phức hợp |

⚠️ 📏 Dạng bất thường thật: `2>2,3&(3|4|5|6|7|8)>2,3` (`Win.Phishing.VbsAgent-10036542-0`) —
toán hạng đầu không có ngoặc; parser phải chịu được. Biểu thức có thể chứa **dấu cách**
(`0 & 1 > 200` trong dòng Locky) → bỏ whitespace khi lex.

### 8.3 Các loại subsig (📏 tổng ≈ 1 352 000 trên ldb+ldu)

| Loại | Số lượng | Cú pháp |
|------|---------:|---------|
| Hex thuần | 1 143 074 | như §7.3 |
| Hex + modifier | 207 117 | `hex::mod` |
| Hex có offset prefix | 2 007 | `Offset:hex[::mod]` |
| PCRE | 301 | `[Offset:]Trigger/regex/flags` |
| Fuzzy image hash | 109 | `fuzzy_img#16hex[#N]` |
| Byte-compare | 1 | `0(>>26#ib2#>512)` |
| Macro (📚 `${min-max}group$`) | 0 trong gói | tham chiếu nhóm NDB |

**(a) Modifier** — hậu tố `::` + tổ hợp: `w` (wide UTF-16LE), `i` (case-insensitive),
`a` (ASCII), `f` (full word). 📏 15 tổ hợp gặp (`w` 110 833, `i` 94 197, `awi` 722, `f` 215, …) —
**đọc từng ký tự**, không so chuỗi cố định.
⚠️ Với `::w`, hex trong file là dạng ASCII; engine **tự sinh** biến thể wide — không tự chèn `00`.

**(b) Offset prefix** — `Offset:hex`: 📏 `N` 1 930, `N,M` 36, `EOF-N` 9, `SEn` 6, `EP+N` 5,
**`VI` 10** (nội dung VersionInfo UTF-16LE, ví dụ `500072006f00…` = "Pro…"), `*` 1.

**(c) PCRE** — `[Offset:]Trigger/regex/flags`:
- `Trigger` = biểu thức logic trên các subsig **đứng trước** (`0&1`, `0`, `(0>150)&1`) — PCRE chỉ
  chạy khi trigger đúng (tối ưu quan trọng).
- 📏 Offset trước trigger: 368 trường hợp (vd `EOF-1:0&1/\./`).
- 📏 Flag gặp: `i` 43, `s` 15, `m` 10, `g` 10, `U` 3; 📚 còn `r` (rolling), `e`, `a`, `A`.
- Regex là **PCRE**: `(?P<name>…)` phải đổi thành `(?<name>…)`, `(?P=name)` → `\k<name>`;
  phần lớn còn lại tương thích .NET Regex.
- ⚠️ Dấu `;` trong regex được viết `\x3b` để không gãy tách trường — xem §16.2.

**(d) Fuzzy image** — `fuzzy_img#hash16hex[#distance]` (📏 108 dòng không distance, 1 dòng `#0`).
Hash là perceptual hash 64-bit của ảnh nhúng trong tài liệu — không so byte.
🛠️ ClamGuard: `FuzzyImageHasher.cs` (pHash 64-bit: Lanczos3 → DCT) + `ImageDecoder.cs` (có cap 4096px/64MiB).

**(e) Byte-compare** — 📏 1 trường hợp: `0(>>26#ib2#>512)` = sau khi subsig 0 khớp, dịch `>>26` byte,
đọc số nguyên (`i`), big-endian (`b`), 2 byte, so `>512`. 📚 Cú pháp đầy đủ gồm shift `>>/<<`,
options `h/d/a/i` + `l/b` + `e`, 1–2 phép so sánh.
🛠️ ClamGuard: `LdbSubsigParser.cs` + `TryReadByteCompareValue` (ScannerEngine.Normalization.cs).

**(f) Macro** — 📚 `${min-max}group$` tham chiếu nhóm NDB; không xuất hiện trong gói này.
🛠️ ClamGuard: hỗ trợ đầy đủ (`MacroSubSignatures` + macro positions).

### 8.4 Quy trình đánh giá

1. Kiểm tra `Engine`, `Target` (+ Container/FileSize/Sections…) — không thỏa → bỏ.
2. Đếm lần khớp từng subsig (hex qua AC; PCRE chỉ khi trigger đúng; fuzzy/byte-compare riêng).
3. Thay số đếm vào `LogicalExpression`, đánh giá AST.
4. Đúng → báo `SignatureName`. Áp dụng ignore-list/PUA ở lớp policy.
🛠️ ClamGuard: `ScannerEngine.Content.cs` (`EvaluateLogical` — prefilter anchor, macro-on-demand,
đánh giá nhóm song song NDB/logical/PE) + `LogicalExpressionEvaluator.cs` (AST, right-assoc,
chặn tham chiếu tương lai).

---

## 9. `.cdb` — metadata container

```
VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
```

📏 5 dòng, đều đúng 10 trường và **kết thúc bằng `:`** (Res2 rỗng). Tất cả nhắm `CL_TYPE_ZIP`.

| # | Trường | Giá trị gặp |
|---|--------|-------------|
| 1 | VirusName | `Win.Trojan.Agent-1435085`, `Email.Trojan.Toa-1`… |
| 2 | ContainerType | `CL_TYPE_ZIP` (📚 RAR/MAIL/7Z/TAR… cũng hợp lệ) |
| 3 | ContainerSize | `*` hoặc số / khoảng `a-b` |
| 4 | FileNameREGEX | regex PCRE tên file con, vd `Courrt.{1,15}\.scr$`, `^[^/\\]+\.(doc|xls|ppt|pdf|png|gif|jpeg)\.js$` |
| 5 | FileSizeInContainer | `*` / số / khoảng (thường là kích thước **nén**; 📚 MAIL/TAR/CPIO có quy tắc đổi chỗ với trường 6) |
| 6 | FileSizeReal | `*` / số / khoảng (sau giải nén) |
| 7 | IsEncrypted | `*`, `0`, `1` |
| 8 | FilePos | `*` / số (tính từ 1) |
| 9 | Res1 | 📚 Với **ZIP/RAR = CRC32 hex**; loại khác bỏ qua. 📏 Trong gói: `*` |
| 10 | Res2 | rỗng (không dùng) |

📌 **Mẹo parse**: regex ở trường 4 có thể chứa `:` → tách 3 trường đầu từ trái, 6 trường cuối từ
phải, phần giữa là regex. Giữ trường rỗng khi `Split(':')` (RemoveEmptyEntries sẽ phá Res2).
🛠️ ClamGuard: `ContainerSignatureParser.cs` (bug-for-bug với `cli_loadcdb`, bao gồm zero-endpoint quirk
của `cli_matchmeta`) — match tại `ArchiveScanner.cs` (`MatchCdbSignatures`).

---

## 10. `.idb` — chữ ký icon

```
IconName:Group1:Group2:IconHash
```

📏 222 dòng, đều 4 trường; `IconHash` luôn **124 ký tự hex = 62 byte**.
`Group1/Group2` liên kết với `IconGroup1/IconGroup2` trong TDB của `.ldb`; `UNUSED` = không dùng nhóm.
📏 Cặp phổ biến: `DOCUMENT:BIFROSE` (48), `DOCUMENT:UNUSED` (43), `FAVBI:UNUSED` (21).
⚠️ Tên nhóm có thể là chuỗi hex (`5375737061636b6564` = "Suspacked") — **đừng giải mã**, đó chỉ là tên.

Fuzzy hash 62 byte: vector metric (color/gray/bright/dark/edge/noedge + r/g/b sums + count) theo
`pe_icons.c` — so khớp **gần đúng** ảnh icon để phát hiện PE giả dạng file khác bằng icon.
🛠️ ClamGuard: `IdbSignatureParser.cs` (validate biên metric) + `IconDecoder.cs` + `IconMetrics.cs`
(port `pe_icons.c`: PrepareForClam, Sobel, Lab diff) + `HasIconGroup` (gated `PE_CONF_MATCHICON`).

---

## 11. `.crb` — chứng chỉ

```
Name;Trusted;Subject;Serial;Pubkey;Exponent;CodeSign;TimeSign;CertSign;NotBefore;Comment[;MinFL[;MaxFL]]
```

📏 30 dòng, đều 11 trường. Dùng cho xác minh **Authenticode của PE** (tin cậy / thu hồi), không phải
so chuỗi signature.

| # | Trường | Giá trị 📏 |
|---|--------|-----------|
| 2 | Trusted | `1` (8 dòng) = tin cậy; `0` (22 dòng) = thu hồi/chặn |
| 3 | Subject | SHA-1 40 hex (30/30) |
| 4 | Serial | SHA-1 40 hex; **có thể rỗng** (1 dòng) |
| 5 | Pubkey | modulus hex 258–1 026 ký tự |
| 6 | Exponent | luôn `010001` (📚 engine hiện hardcode/ignore) |
| 7–9 | CodeSign/TimeSign/CertSign | `0`/`1` |
| 10 | NotBefore | rỗng ở cả 30 dòng |
| 11 | Comment | rỗng hoặc mô tả |

📌 `Split(';')` **không RemoveEmptyEntries** — trường rỗng là dữ liệu.
🛠️ ClamGuard: kiểm chứng chữ ký qua `ClamAvSignatureVerifier.cs`; certificate rules load trong
`DatabaseLoader.Specialized.cs`.

---

## 12. `.ftm` — file type magic

```
MagicType:Offset:HexMagic:TypeName:RequiredType:DetectedType[:MinFL[:MaxFL]]
```

📏 268 dòng: 6 trường = 104, 7 = 152, 8 = 12.

| MagicType | Số dòng 📏 | Ý nghĩa 📚 |
|-----------|-----------:|------------|
| `0` | 197 | So sánh bytes trực tiếp tại offset cố định |
| `1` | 69 | Magic dạng body-signature (wildcard), tìm trong vùng — offset có thể `*` |
| `4` | 2 | Partition magic (HFS+/HFSX, offset 1024) |

- `RequiredType`: gần như luôn `CL_TYPE_ANY`; `DetectedType` = `CL_TYPE_GZ`, `CL_TYPE_MAIL`,
  `CL_TYPE_HTML`, `CL_TYPE_MACHO_UNIBIN`, `CL_TYPE_IGNORED`…
- `HexMagic` dùng cú pháp §7.3: `?`, `(a|b)`, `{n-m}`, `{-n}`, `*`.
- ⚠️ 📏 Ngoại lệ: 3 dòng có MinFL **rỗng** (`0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121`)
  → parser phải chấp nhận trường FLevel rỗng.
- 📚 `CL_TYPE_IGNORED` = engine bỏ qua loại file này (không quét nội dung).
🛠️ ClamGuard: `FileTypeMagicDetector.cs` (mode 0 direct + mode 1 content, `MaxSearchCandidates`
65 536, PatternCache) + load trong `DatabaseLoader.Specialized.cs`.

---

## 13. Anti-phishing

### 13.1 `.pdb` — danh sách host theo dõi

```
H:DisplayedHostname[:FuncLevelSpec]
R:DisplayedURLRegex[:FuncLevelSpec]
```

📏 263 dòng, **đều `H:`** (`H:searscard.com`, `H:capitalone.com`…). `H:` khớp hostname đơn giản
(có thể khớp subdomain theo quy tắc ClamAV); `R:` là regex URL.
📚 Đây **không phải** signature quét byte — engine chạy sau khi parse/normalize HTML/mail và trích
cặp (RealURL, DisplayedURL). Tìm chuỗi `capitalone.com` trong bytes là **sai ngữ nghĩa**.

### 13.2 `.wdb` — allow-list chống FP phishing

```
M:RealHostname:DisplayedHostname[:FL]
X:RealURLRegex:DisplayedURLRegex[:FL]
Y:RealURLRegex[:FL]        (📚 ClamAV 1.6+)
```

📏 185 dòng: `M:` 89, `X:` 96, không có `Y:`.

```text
M:email.chase.com:www.chasefrauddetector.com
X:.+\.hvb\.de([/?].*)?:.+\.hypovereinsbank\.de
```

📚 Quy tắc match `X:`: **hai URL được nối bằng `:` thành một chuỗi** trước khi so regex (không phải
2 regex độc lập); regex mặc định neo đầu/cuối; engine tự thêm `/` cuối vào regex và input.
Link thật khớp vế 1 + URL hiển thị khớp vế 2 → **hợp lệ, không báo phishing**.
🛠️ ClamGuard: load trong `DatabaseLoader.Specialized.cs` (chống XXE, từ chối dòng trống).

---

## 14. Cấu hình & ignore

### 14.1 `.cfg` (DCONF)

```
Category:FlagsHex:MinFL:MaxFL
```

📏 21 dòng, 5 nhóm: `PE` (7), `DOCUMENT` (7), `ARCHIVE` (2), `BYTECODE` (2), `OTHER` (3).
Ví dụ: `PE:0xb4ff:13:23`, `BYTECODE:0x0:51:51`.

📚 Mask = bit bật/tắt module con trong nhóm (định nghĩa bit nằm trong source từng phiên bản —
đừng đoán từ tên category). Hiệu lực khi FLevel engine ∈ `[MinFL, MaxFL]`.
🛠️ ClamGuard: `DynamicConfiguration.cs` (resolve "assignment tuần tự, entry sau thắng" đúng semantics)
— flags được map qua `DynamicConfigFlags` theo source 1.5.4.

### 14.2 `.ign` / `.ign2`

- 📚 `.ign` (legacy): `DBFile:LineNumber:SignatureName[:MD5]` — 📏 chỉ có dòng giả
  `fake:1:Dont_remove_this_line`. Ưu tiên `.ign2` cho thiết kế mới.
- `.ign2`: mỗi dòng 1 **tên chữ ký** bỏ qua (📏 22 dòng: 1 giả `fake_dont_remove_this_line` +
  21 thật). 📚 Có thể kèm `:MD5-của-entry` — ignore **chỉ khi entry chưa thay đổi**; nếu signature
  được cập nhật (checksum lệch) thì không bỏ qua nữa.
- 📚 Policy: giữ suppression ở layer riêng, không xóa record khỏi DB đã parse (khó audit khi reload).
🛠️ ClamGuard: `IgnoreRuleSet.cs` (giải phóng SourceEntry sau filter; kiểm MD5 có điều kiện).

---

## 15. `daily.info` và `COPYING`

📏 `daily.info` 25 dòng:
1. Bản sao header CVD với MD5 + DSIG thay bằng `X`:
   `ClamAV-VDB:07 Oct 2026 06-24 +0000:28146:355728:90:X:X:svc.clamav-publisher:1791354258`
2. 23 dòng `TênFile:KíchThước:SHA256` — **đã kiểm chứng cả 23 khớp** (không liệt kê chính nó + COPYING).
3. Dòng cuối `DSIG:<base64>`.

📚 Parser phải phân biệt header/DSIG với record 3 trường.
`COPYING` = GPLv2 (17 992 byte), không phải chữ ký.

---

## 16. Bẫy trong dữ liệu thật

📏 + 📚 tổng hợp từ cả hai bản phân tích:

1. **Header `sigs` = 355 728 ≠ tổng dòng** (356 255). Cách ClamAV đếm khác — đừng assert theo nó.
   (📌 Đối chiếu: ClamGuard hiển thị **355 243** signature sau khi lọc FLevel/PUA/ign — 3 con số
   khác nhau là bình thường, mỗi con số có ngữ nghĩa riêng.)
2. **`;` literal trong PCRE của `.ldb`**: dòng `Win.Phishing.VbsAgent…` chứa `…|^^|;;)…` → tách `;`
   ngây thơ sinh mảnh rỗng. Khuyến nghị: phát hiện subsig ≠ số toán hạng cần thiết → log + bỏ chữ ký.
3. **Biểu thức bất thường** không ngoặc: `2>2,3&(…)>2,3`.
4. **Tên có dấu cách**: `Win.Loader. BadiisSet-10060291-1` → regex tên không dùng `\S+`.
5. **FLevel rỗng** trong `.ftm` (`::121`).
6. **26 dòng `.ldb` không có `Engine:`** → mặc định FLevel tối thiểu.
7. **FileSize = `*`** ở 2 dòng `.hsb` (phải kèm MinFL).
8. **Serial rỗng** ở 1 dòng `.crb`.
9. `.cdb` kết thúc bằng `:` → giữ phần tử rỗng khi split.
10. LF là chuẩn nhưng nên `TrimEnd('\r')` phòng CRLF.
11. Modifier `::` nhiều thứ tự (`wa`/`aw`/`iaw`…) → đọc từng ký tự.
12. Hex lẫn hoa/thường trong `.ldb`.
13. **Mỗi extension một parser riêng** — không dùng parser chung; `Split` không bỏ entry rỗng;
    không tự tiện `Trim()` hay xoá `:`/`;` cuối dòng (phishing spec yêu cầu colon bắt buộc).
14. **FLevel ≠ version string** `1.2.3` — là số functionality level engine, so sánh inclusive theo
    từng format (`.ldb/.ndb/.ftm/.cfg/.pdb/.wdb` không tự đồng nhất quy tắc).
15. **`daily.ldb` 76.8 MB** → dùng stream reader; hash/detection trả tên nguyên văn (không lowercase).
16. 📚 **Không ám thị chữ ký** (`(?P<>)`, PCRE syntax) sang .NET mà không chuyển đổi tương đương;
    `Regex` .NET có thể cho kết quả khác engine ClamAV về anchor/flags.

---

## 17. Hướng dẫn triển khai C#

### 17.1 Đọc CVD

```csharp
using System.Formats.Tar;
using System.IO.Compression;

byte[] head = new byte[512];
using var fs = File.OpenRead(path);
fs.ReadExactly(head);
var h = Encoding.ASCII.GetString(head).TrimEnd(' ', '\0').Split(':');
// h[0]="ClamAV-VDB", h[2]=version, h[3]=sigCount(metadata), h[4]=flevel, h[5]=md5 payload

fs.Position = 512;
var md5 = Convert.ToHexString(MD5.HashData(fs)).ToLowerInvariant();  // so với h[5]

fs.Position = 512;
using var gz = new GZipStream(fs, CompressionMode.Decompress);
using var tar = new TarReader(gz);
while (tar.GetNextEntry() is { } e)
{
    if (e.DataStream is null) continue;
    using var sr = new StreamReader(e.DataStream, Encoding.Latin1);
    // e.Name = "daily.hdb" ... → chọn parser theo phần mở rộng
}
```

🛠️ ClamGuard: `CvdReader.cs` — streaming, cap kích thước, bounds-check header.

### 17.2 Chọn parser theo extension

| Ext | Parser |
|-----|--------|
| hdb, hdu, hsb, hsu | `Hash:Size:Name[:min[:max]]` — thuật toán theo độ dài hash |
| mdb, mdu, msb, msu | `Size:Hash:Name[:min[:max]]` — hash section PE |
| fp, sfp | whitelist `Hash:Size:Id` |
| ndb, ndu | `Name:Target:Offset:Hex[:min[:max]]` |
| ldb, ldu | split `;` → name, TDB, expr, subsigs |
| cdb | 10 trường, regex ở giữa |
| idb | 4 trường, hash 124 hex |
| crb | split `;` (11 trường, giữ rỗng) |
| ftm | `Type:Offset:Hex:Name:Req:Det[:min[:max]]` |
| pdb, wdb | `Type:Value[:Value2]` |
| cfg | `Cat:MaskHex:min:max` |
| ign / ign2 | bỏ qua theo (DB:dòng) / theo tên |
| info, COPYING | kiểm manifest / bỏ qua |

### 17.3 Regex kiểm tra từng dòng (📏 đã chạy trên toàn bộ build 28146)

```csharp
const string H32 = @"[0-9a-fA-F]{32}", H40 = @"[0-9a-fA-F]{40}", H64 = @"[0-9a-fA-F]{64}";
const string NAME = @"[^:;\s][^:;]*";   // KHÔNG dùng \S+ — tên có thể chứa space

var Rx = new Dictionary<string,string> {
 ["hdb"]=$@"^{H32}:\d+:{NAME}(:\d+){{0,2}}$",
 ["hsb"]=$@"^({H32}|{H40}|{H64}):(\d+|\*):{NAME}(:\d+){{0,2}}$",
 ["mdb"]=$@"^\d+:({H32}|{H40}|{H64}):{NAME}(:\d+){{0,2}}$",
 ["fp"] =$@"^({H32}|{H40}|{H64}):\d+:{NAME}$",
 ["ndb"]=$@"^{NAME}:\d+:(\*|\d+(,\d+)?|EP[+-]\d+(,\d+)?|S\d+\+\d+(,\d+)?|SE\d+(,\d+)?|SL\+\d+(,\d+)?|EOF-\d+(,\d+)?):[^:]+(:\d+){{0,2}}$",
 ["idb"]=$@"^{NAME}:[^:]+:[^:]+:[0-9a-fA-F]{{124}}$",
 ["ftm"]=@"^[014]:(\*|\d+|\d+,\d+|EOF-\d+):[^:]+:[^:]+:CL_TYPE_\w+:CL_TYPE_\w+(:\d*){{0,2}}$",
 ["cfg"]=@"^[A-Z]+:0x[0-9a-f]+:\d+:\d+$",
 ["wdb"]=@"^[MX]:[^:]+:[^:]+$",
 ["pdb"]=@"^[HRDSMXY]:[^:]+(:.*)?$",
 ["crb"]=@"^[^;]+;[01];[0-9a-f]{{40}};([0-9a-f]{{40}})?;[0-9a-fA-F]+;[0-9a-fA-F]+;[01];[01];[01];[^;]*;[^;]*(;\d+){{0,2}}$",
 ["ldb"]=@"^[^;:\s][^;:]*;[^;]+;[^;]+;[^;]+(;[^;]+)*$",
};
```

📏 Kết quả kiểm chứng: hdb 23/23, hdu 39/39, hsb 54 681/54 681, mdb 11 575/11 575, mdu 315/315,
fp 483/483, ndb 319/319, idb 222/222, cdb 5/5, cfg 21/21, pdb 263/263, wdb 185/185, ftm 268/268,
ldu 10 166/10 166, crb 30/30, ign2 22/22, **ldb 273 471/273 473** (2 ngoại lệ §16.2 và tên có space).

### 17.4 Thứ tự đối chiếu 1 file

1. Xác định loại file (`.ftm`) → `CL_TYPE_*`.
2. Hash toàn file + size → `.fp/.sfp` (whitelist — khớp thì **dừng**), rồi `.hdb/.hsb`.
3. Nếu PE: hash từng section → `.mdb/.msb`.
4. Quét hex `.ndb` (theo Target/Offset).
5. Quét `.ldb` (đếm subsig → biểu thức logic).
6. Nếu container: `.cdb` trên metadata file con.
7. PE có icon: `.idb`; PE có chữ ký số: `.crb`.
8. Lọc `.ign2` / FLevel / PUA ở lớp policy, sau khi có candidate.

### 17.5 Hiệu năng

- 📏 `.ldb` ≈ 1,35 triệu subsig: dựng **một** Aho-Corasick cho các đoạn hex thuần (tách tại
  `*`/`{}`), PCRE chỉ chạy khi trigger đúng, nạp lười/lazy nếu cần.
- Hash: index theo `(algorithm, size)` hoặc `(size, hash)`, tách bảng theo độ dài hash.
- 🛠️ ClamGuard: đã hiện thực tất cả — AC frozen + dense tables, prefilter anchor cho logical,
  memoize normalize/context, hash-once-per-section (xem commit `fix(scanner)`/`perf`).

### 17.6 Kiến trúc phân lớp (khuyến nghị chung)

```
CvdReader (header/manifest/verify)  →  SignatureDatabaseLoader (parser theo ext)
  →  CompiledSignatureSet (AC/hash buckets/prefilter)  →  ScannerPipeline
  (file-type → container → normalize → hash → pattern → logical → PE → policy)
  →  DetectionResult (name, evidence, PUA/suppression context)
```

📌 Thứ tự triển khai thực tế: file-hash → NDB cơ bản → FTM → LDB → container → PE section/icon
→ phishing → policy DBs. 📚 **Parse đủ database ≠ tương thích ClamAV** — phần khó nhất là
normalize/preprocess, unpack lồng nhau, PE parsing, heuristic phishing và FLevel per-version.

---

## 18. Kế hoạch kiểm thử

- **Parser**: đúng số record mỗi extension như bảng §3; dòng có field rỗng, delimiter cuối,
  `*` size, FLevel rỗng, tên dài; `.ldb` subsig thay đổi; record hỏng → lỗi kèm file+dòng+lý do.
- **Hash**: EICAR có cả MD5 lẫn SHA-256 trong DB; sai size 1 byte → không khớp; đổi 1 byte file →
  không khớp; `.mdb/.msb` hash **section** chứ không phải hash cả file.
- **Body/Logical**: fixture cho từng token `??`, `a?`, `?a`, `*`, `{n}`, `{n-m}`, `[n-m]`, alternate,
  offset `EOF/EP/SE/S/VI`; LDB: AND/OR/phủ định/count/target/Engine range. Đối chiếu `clamscan`
  với custom DB khi có.
- **Lồng/normalize**: ZIP với file con mở rộng kép (`.cdb`); PE 32/64 (section hash); HTML/mail
  display-URL ≠ real-URL (`.pdb/.wdb`); HTML khác khoảng trắng/hoa thường (normalize).
- 📌 Chỉ dùng **EICAR** làm mẫu kiểm tra đường đi — không dùng mẫu malware thật ngoài môi trường cô lập.

---

## 19. Bảng tra nhanh

| Extension | Mẫu cấu trúc | Vai trò khi quét |
|---|---|---|
| `.hdb/.hdu` | `MD5:Size:Name` | Hash toàn file MD5; `.hdu` = PUA |
| `.hsb/.hsu` | `Hash:Size:Name[:FL]` | Hash toàn file theo độ dài hash |
| `.mdb/.mdu`, `.msb/.msu` | `SectionSize:SectionHash:Name[:FL]` | Hash section PE (size trước hash) |
| `.fp/.sfp` | `Hash:Size:Label` | Allow-list false-positive (xoá detection) |
| `.ndb/.ndu` | `Name:Target:Offset:HexPattern[:FL]` | Byte pattern + wildcard + offset |
| `.ldb/.ldu` | `Name;TDB;Expr;Subsig…` | Nhiều subsig + biểu thức logic (AST) |
| `.idb` | `Name:Group1:Group2:FuzzyHash(124hex)` | Icon fuzzy, liên kết qua LDB IconGroup |
| `.cdb` | `Name:ContainerType:…:FileNameRegex:…` | Metadata file con trong container |
| `.pdb` | `H:Host` / `R:Regex` | Heuristic phishing (sau normalize) |
| `.wdb` | `M:RealHost:DisplayedHost`, `X:/Y:` | Allow-list phishing |
| `.ftm` | `Type:Offset:Magic:Name:Req:Det[:FL]` | Nhận diện file type |
| `.cfg` | `Category:Flags:StartFL:EndFL` | Cấu hình engine theo FLevel |
| `.crb` | `Name;Trusted;Subject;…` | Tin cậy/thu hồi chứng chỉ PE |
| `.ign2` / `.ign` | Tên sig [:MD5Entry] / legacy | Bỏ qua chữ ký |
| `.info` | `Name:Size:SHA256` + header/DSIG | Manifest toàn vẹn archive |

---

## 20. Phụ lục — mẫu 1 dòng từng loại

```text
hdb : 943e487c31a3d7929cb19a433ff25329:11250688:Win.Ransomware.RansomHub-10037316-0
hdu : c43ac9caa088f1cf5e4c388feda73e5a:16920:PUA.Win.Tool.ANVCracker-1
hsb : b09c6279c1e0760c3e383f85d0488329:69488:Pdf.Dropper.Agent-8087615-0:73
hsb* : cb9e4424771c1f84279aceb0ca31f93e:*:Win.Exploit.CVE_2020_1381-8449591-1:73
hsb(sha256): 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Test-Signature
mdb : 51200:a87eeb45beeabc044bfeb435241dd164:Win.Trojan.Kronos-1
msb : 91648:550a9b573224aa75418c852080b59af3:Win.Packer.Agent-6412293-0:73
fp  : 332feab1435662fc6c672e25beb37be3:2871808:sid25347313-1
sfp : 6bed1a3a956a859ef4420feb2466c040800eaf01ef53214ef9dab53aeff1cff0:2871808:sid25347313-1
ndb : Win.Malware.Emotet-6450824-0:1:EP+0,15:83e0038935{4}893d{4}8925{4}892d{4}891d{4}a1{4}ffd0:70
ndu : PUA.Win.Packer.PECompact-3:1:EP+0:eb0668[4-4]c3:58
ldb : Js.Ransomware.Locky-30743;Engine:51-255,Target:7;0 & 1 > 200;222e73706c697428276d73656d736527293b;6d73656d7365
ldu : PUA.Win.Tool.Hacktool-1833;Engine:51-255,Target:1;(0&1&2);64756d705f75736564686173686573;6773656364756d70;2d2d69616d73657276696365
cdb : Email.Trojan.Toa-1:CL_TYPE_ZIP:*:Courrt.{1,15}\.scr$:*:*:*:*:*:
idb : Win.Trojan.GenericFD-2:DOCUMENT:BIFROSE:20bc70f03b0d02032ad0d100060017049000c073160bfb00…(124 hex)
crb : Trusted.CA.Microsoft-4546341-1;1;adf79877…(40);f5ceafcf…(40);a902bdc1…(modulus);010001;1;1;1;;Microsoft Root Authority MD5 1997-2020 00:c1:…
ftm : 1:*:3c5441424c45(3e|20|09|0a|0b|0c|0d|2f):HTML data:CL_TYPE_ANY:CL_TYPE_HTML
pdb : H:capitalone.com
wdb : X:.+\.commerzbank\.com([/?].*)?:.+\.commerzbank\.de
cfg : PE:0xb4ff:13:23
ign : fake:1:Dont_remove_this_line
ign2: Win.Trojan.Ramnit-6197
```

---

## 21. Tài liệu tham khảo

1. [Creating signatures / Database formats](https://docs.clamav.net/manual/Signatures.html)
2. [Body-based Signature Content Format](https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html)
3. [Extended Signatures](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html)
4. [Logical Signatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html)
5. [Hash-based Signatures](https://docs.clamav.net/manual/Signatures/HashSignatures.html)
6. [Container Metadata Signatures](https://docs.clamav.net/manual/Signatures/ContainerMetadata.html)
7. [Phishing Signatures](https://docs.clamav.net/manual/Signatures/PhishSigs.html)
8. [File Type Magic](https://docs.clamav.net/manual/Signatures/FileTypeMagic.html)
9. [Dynamic Configuration](https://docs.clamav.net/manual/Signatures/DynamicConfig.html)
10. [Trusted and Revoked EXE Certificates](https://docs.clamav.net/manual/Signatures/AuthenticodeRules.html)
11. [Allow List Databases](https://docs.clamav.net/manual/Signatures/AllowLists.html)
12. [Database Info](https://docs.clamav.net/manual/Signatures/DatabaseInfo.html)
13. [Signature Naming Guidelines](https://docs.clamav.net/manual/Signatures/SignatureNames.html)
14. [File Types and Target Types](https://docs.clamav.net/appendix/FileTypes.html)

> **Lưu ý cuối**: tài liệu mô tả record đã thấy trong build 28146 và diễn giải theo tài liệu chính
> thức + source 1.5.4 — là cơ sở thiết kế parser/matcher, **không đảm bảo tương thích 100 % ClamAV**.
> Các phần khó nhất: normalize/preprocess, unpack lồng, PE parsing, grammar wildcard, logic
> expression, icon/phishing và khác biệt FLevel giữa các phiên bản engine.
