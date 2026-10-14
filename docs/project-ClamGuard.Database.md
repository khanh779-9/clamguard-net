# project-ClamGuard.Database

> Tầng **nạp, xác thực và cập nhật** cơ sở dữ liệu chữ ký: giải container CVD/CLD, parse tất cả
> file DB đặc thù (kể cả FTM/DCONF/phishing/certificate), kiểm tra tính toàn vẹn (manifest + chữ
> ký RSA) và apply bản vá CDIFF khi update.

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core`, `ClamGuard.Signatures`, `ClamGuard.Yara` (DB `.yar`), `ClamGuard.Bytecode` (DB `.cbc`) |
| Số file nguồn | 15 |

```text
Loading/       CvdReader, DatabaseLoader, DatabaseLoader.Specialized, IgnoreRuleSet
Storage/       SignatureDatabase, SpecialDatabaseModels, DynamicConfiguration
Verification/  DatabaseVerifier, ClamAvSignatureVerifier, DetachedCmsVerifier
Update/        DatabaseUpdater, CdiffPatchApplier
DatabaseManager.cs
Models/        DatabaseLoadResult, DatabaseLoadError
```

## 2. Luồng nạp database

```text
DatabaseManager.LoadAndCompile(directory, failOnInvalidFile, pua…, cacheDirectory)
  → DatabaseLoader.LoadDirectory
      ├─ CvdReader: header 512B/9 trường → verify MD5 payload → giải tar.gz → extract
      ├─ Chọn daily.cld vs daily.cvd theo version (cld thắng khi bằng version — parity ClamAV)
      ├─ Persistent cache: tái dùng thư mục extract cũ (cùng version)
      ├─ Theo extension → parser (project Signatures) hoặc special-db loaders (§3)
      ├─ IgnoreRuleSet (.ign/.ign2) lọc TRƯỚC khi parse
      └─ DatabaseVerifier: manifest (header copy, dup-entry, size, sha256, unlisted-file)
  → SignatureDatabase.Compile()  → CompiledSignatureSet (project Signatures)
  → publish qua Volatile.Write (generation tăng dần) — scan đang chạy thấy state cũ nguyên vẹn
```

## 3. Các loader đặc thù (`DatabaseLoader.Specialized.cs`)

| Loại file | Xử lý |
|-----------|-------|
| `.ftm` | File-type magic rules → `SpecialDatabases.FileTypes` |
| `.cfg` | DCONF → `DynamicConfiguration` (resolve "assignment tuần tự, entry sau thắng") |
| `.pdb/.wdb` | Phishing domain/allow-list (XML-safe) |
| `.crb` | Certificate trust/revoked (validate pubkey hex) |
| `.cat/.ioc` | Special DB khác |
| `.yar/.yara` | Qua project Yara |
| `.cbc` | Qua project Bytecode |
| `.info` | Manifest (header copy với MD5/DSIG thay `X`, 23 dòng `name:size:sha256`, DSIG) |

XML parsing luôn `DtdProcessing.Prohibit` + `XmlResolver = null` (chống XXE); dòng trống `.wdb`
bị từ chối có chủ đích.

## 4. Verification (`Verification/`)

| Class | Vai trò | Chi tiết kỹ thuật |
|-------|---------|--------------------|
| `DatabaseVerifier` | Kiểm manifest archive | Header copy khớp, không dup-entry, size + SHA-256 từng member, phát hiện file **không liệt kê**; legacy CVD phải có dsig hợp lệ |
| `ClamAvSignatureVerifier` | Chữ ký CVD/daily.info | **PSS2**: RSA-PSS/SHA-256/salt-32 chuẩn **RFC 8017** (trace MGF1/EM layout); **legacy CVD**: raw-RSA trên MD5 16 byte với radix-64 biến thể lowercase-first/little-endian của ClamAV; public key hardcode 3 key của ClamAV |
| `DetachedCmsVerifier` | Chứng chỉ detached (update online) | Gọi `openssl cms -verify` — resolve nghiêm ngặt: `AppContext.BaseDirectory` → `C:\Program Files\OpenSSL*\bin` → PATH (**đúng tên** `openssl.exe`, không PATHEXT); **không tìm thấy = fail-closed** (không bao giờ coi là Verified); drain cả stdout+stderr trước `WaitForExit` (chống pipe deadlock); timeout kill entire process tree |

📌 Chỉ `.cvd` có dsig; `.cld/.cud` không có theo thiết kế ClamAV. Detached verification chỉ chạy
trong `DatabaseUpdater` khi có thư mục certificates.

## 5. Update (`Update/`)

### 5.1. `DatabaseUpdater`

Flow: **download → verify → smoke-test → atomic replace**. URL của ClamAV; temp file có GUID;
`File.Delete(temp)` có bảo vệ.

### 5.2. `CdiffPatchApplier` — apply bản vá `daily.cdiff`

Thứ tự an toàn (hardened):

1. **Parse metadata only**: header `ClamAV-Diff:v:len`, footer signature, digest
   `SHA256(patch[0..footer])` — tính được **mà không cần giải nén**.
2. **Verify chữ ký TRƯỚC decompress** + early-reject `expectedScriptBytes > MaxScriptBytes`.
3. **Decompress bounded**: chunk-read 64KB, vượt `MaxScriptBytes` → `InvalidDataException` ngay
   (tối đa ~32MB + buffer trong RAM — decompression bomb vô hiệu).
4. Script dạng text: lệnh `OPEN/ CLOSE/ XCHG/ ADD/ MOVE/ UNLINK/` lên file DB.
5. **Staging + atomic publish**: `DatabaseUpdater.ApplyCdiffAsync` copy live DB → thư mục staging
   sibling (cùng volume), apply patch lên staging; thành công mới `File.Move(overwrite)` từng file
   + đồng bộ các file bị UNLINK; **thất bại bất kỳ đâu → live dir nguyên vẹn**, staging dọn sạch.
6. **Fidelity dòng**: đọc newline style của từng file (`\r\n` vs `\n`) và ghi lại đúng style —
   output byte-identical với upstream `cdiff.rs` cho DB LF chuẩn.
7. Bug tiềm ẩn đã sửa: `Close()` từng gọi `File.Replace` khi `StreamWriter` chưa dispose → mọi
   CLOSE-with-edits fail trên Windows; giờ dispose tường minh trước khi replace.

📌 Tham chiếu logic: `libclamav_rust/src/cdiff.rs` (ClamAV 1.5.4) — pop `\n`, ADD giữ raw script
bytes, MOVE rewrite src theo style src + append theo style dst.

## 6. `DatabaseManager` & `SignatureDatabase`

```csharp
var manager = new DatabaseManager();                 // empty state
var state = manager.LoadAndCompile(dir, true);       // load + compile + publish
state.Database; state.Compiled; state.Generation;    // snapshot immutable
manager.Current;                                     // Volatile.Read — scan luôn thấy state nhất quán
```

- Publish qua `Volatile.Write` — **không khóa scan**: scan đang giữ `CompiledState` cũ cứ hoàn
  tất với state đó; scan mới thấy generation mới.
- `SignatureDatabase` cache typed arrays (`NdbSignatures`, `LogicalSignatures`, `MetadataSignatures`,
  `CdbSignatures`, `HashSignatures`) — invalidate khi `Add`/`AddRange`; `Compile()` pre-materialize
  để tránh LINQ lặp per-file.
- `HasSelfProtectionSignatures` cached (`.sdb` self-protection — engine tự quét).

## 7. Thread-safety & vòng đời

- `DatabaseManager.Current` là điểm read-volatile duy nhất — race generation giữa 2 lần
  `LoadAndCompile` đồng thời bị chấp nhận (publish tuần tự, generation đơn điệu).
- Load là thao tác nặng (bytes + compile AC) — gọi từ background; UI layer (project Antivirus)
  có single-flight wrapper.

## 8. Kiểm thử

`Program.DatabaseTests.cs` (13): hex parse, HDB, CVD header hợp lệ + malformed, raw-tar extract,
cld/cvd selection (mới hơn/thua/bằng), truncated payload, LDB precedence `0&1|2`.
Update/CDIFF + DetachedCmsVerifier được kiểm bằng harness riêng (13/13 PASS trong đợt hardening —
gzip bomb reject, staging rollback, newline fidelity, XCHG mismatch).
