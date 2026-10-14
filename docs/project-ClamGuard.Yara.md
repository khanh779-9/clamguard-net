# project-ClamGuard.Yara

> **Emulator subset của YARA** chạy managed: parse rule (strings + conditions cơ bản), scan
> buffer và trả về match. ⚠️ Không phải binding libyara — tên class mang "Yara" để đồng bộ khái
> niệm, tài liệu class ghi rõ phạm vi subset và cơ chế warning cho mọi construct chưa hỗ trợ.

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core` |
| Số file nguồn | 3 (`YaraEngine.cs`, `YaraModels.cs`, `YaraContentScanner.cs`) |

## 2. Phạm vi hỗ trợ (trung thực)

| Nhóm | Hỗ trợ | Không hỗ trợ (→ warning, rule bị bỏ qua có ghi log) |
|------|--------|------------------------------------------------------|
| Strings | Plain `"..."`, hex thuần | Hex wildcard `??`, jump `{n}`/`{n-m}` |
| Modifiers | `nocase`, `ascii`, `xor` (xor trên byte gốc, so case-insensitive) | `wide` trên **regex** (warn), tổ hợp lạ |
| Regex literals | `/.../` với escape `\/` đúng | |
| Conditions | `and/or/not`, count, `filesize` (bytes) | `filesize > 100KB` (suffix KB/MB), `N of (...)`, glob `($a*)`, `for`, modules (`pe.`…), condition không nhận diện |
| Id | **Case-sensitive** (đúng YARA) | |
| Khác | MaxRules truncate → warning | |

## 3. Điểm kỹ thuật chính

### 3.1. Comment stripper bằng state machine (fix CRITICAL)

Bản cũ dùng `Regex.Replace(text, @"//.*?$")` — phá hủy string chứa `//`
(`$a = "http://evil.com"` mất quote đóng → rule parse fail → **âm tính giả hàng loạt**, URL cực
phổ biến trong rule YARA). Nay là state machine tôn trọng:

- string `"..."` với `\` escape; char `'...'`;
- regex literal `/.../` — một `/` chỉ mở regex khi đứng ở **value boundary** (sau `=`, `(`,
  whitespace, toán tử); trong regex `\/` là escape;
- `//` và `/* */` chỉ bị xoá khi ở ngoài literal; unterminated `/*` giữ nguyên văn.

### 3.2. Cơ chế warning (không còn silent-drop)

`YaraEngine.Warnings` (`IReadOnlyList<string>`, public) + `YaraMatch.Warnings` (per-rule,
init-only, default rỗng). Mọi trường hợp rule bị bỏ/silent-false đều phát warning, ví dụ:

```text
rule 'X': hex string '$a': wildcards ('?') unsupported; string ignored
rule 'X': unsupported condition 'filesize > 100KB' ignored
YARA rule limit reached (MaxRules = N); additional rules were ignored
```

Load-time validation (`ValidateConsume`) bắt token không consumable **trước** khi scan — rule
không hỗ trợ không được báo "không match" mà là "bị bỏ qua có lý do".

### 3.3. Scan

`YaraEngine` naive scan O(rules × filesize) — chấp nhận cho use-case test/sample; không dành cho
DB lớn (khác hẳn Aho-Corasick của project Signatures). Xoá/xor/nocase áp đúng thứ tự biến thể.
`YaraContentScanner` là adapter `IContentScanner` (gắn qua `ScanOptions.YaraRuleDirectory`);
project Database nạp `.yar` như special-DB.

## 4. Hướng phát triển

1. **Đổi tên/document** đã làm (subset emulator). Nếu cần YARA đầy đủ: binding libyara native
   hoặc chuyển rule sang LDB/NDB của engine.
2. Bổ sung hex wildcard + `of` conditions là bước mở rộng tự nhiên nhất (đã có warning scaffolding).
3. Perf: nếu rule set lớn, chuyển sang pattern index tương tự prefilter của Signatures.

## 5. Kiểm thử

`Program.YaraBytecodeTests.cs`: inline rule `condition: $mz and $hello` match `$hello` qua nested
archive; harness behavioral 27/27 trong đợt hardening (URL trong string sống sót qua comment
stripper, xor+nocase, case-sensitive id…).
