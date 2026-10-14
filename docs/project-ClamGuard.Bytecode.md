# project-ClamGuard.Bytecode

> Máy ảo cho **bytecode ClamAV (`.cbc`)** — tương đương `libclamav/bytecode*` của ClamAV nhưng
> chạy managed, an toàn bộ nhớ: pointer qua handle-table bounds-checked thay vì pointer thật.

---

## 1. Thông tin project

| Thuộc tính | Giá trị |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core` |
| Số file nguồn | 18 (13 Models, Parser, Engine, VM + VM.Api, ContentScanner) |
| Định dạng đầu vào | `.cbc` — **file ASCII text**, magic `ClamBC`, số nibble-encoded `0x60+n` LSB-first, section `T` (types) / `E` (API) / `G` (globals) / `A` / `B` (functions/blocks) / `S` |

```text
Models/    ClamBcProgram (metadata, eligibility), ClamBcFunction/Instruction/Operand/Type/Pointer,
           state objects (Buffer/Map/InflateState/PdfObject/MapValue), BytecodeModels (caps)
Parsing/   ClamBcParser.cs
Runtime/   ClamBcEngine.cs (facade), ClamBcVirtualMachine.cs (interpreter core),
           ClamBcVirtualMachine.Api.cs (API handlers), BytecodeBudgetExceededException.cs
Scanning/  BytecodeContentScanner.cs (adapter IContentScanner)
```

## 2. Load & eligibility

```csharp
var engine = ClamBcEngine.LoadDirectory(directory, options);  // hoặc LoadText
IReadOnlyList<BytecodeMatch> hits = engine.Scan(fileBytes, options, ct);
```

- Parser **bỏ qua an toàn** file malformed (`FormatException/OverflowException/IndexOutOfRange/
  ArgumentException` → skip, không fail DB).
- `ClamBcProgram.IsCompatible(engineFLevel)` + `IsEligibleForFile(data)` lọc trước khi chạy VM
  (magic/điều kiện theo metadata của program).
- `locals` cap 65 536 — file .cbc độc không thể ép `new int[total]` unbounded.
- Opcode numbering **khớp `clambc.h` 1.5.4**: `ADD=1…XOR=13, TRUNC/SEXT/ZEXT=14-16, BRANCH/JMP/
  RET/RET_VOID=17-20, ICMP_EQ=21…ICMP_SLE=29, ICMP_SLT=30, SELECT=31, CALL=32/33, COPY=34, GEP=37,
  MEMSET=40…` (✅ đã đối chiếu; thứ tự `SLE=29/SLT=30` theo LLVM là **đúng sẵn** trong code).

## 3. Máy ảo (`ClamBcVirtualMachine`)

### 3.1. Ngân sách vận hành (chống DoS)

| Cap | Mặc định/phạm vi | Hành vi khi vượt |
|-----|------------------|-------------------|
| `MaxInstructions` (fuel) | validate 1..100M | `BytecodeBudgetExceededException` → **skip program này**, scan file tiếp tục |
| `MaxRuntime` | validate ≤ 10 phút | như trên (check mỗi 1024 instr) |
| `MaxCallDepth` | 1..1024 | skip |
| `MaxAllocatedBytesPerRule` / `MaxExtractedBytes` / `MaxBufferBytes` | ≤ 512MB | allocation bị từ chối → skip |
| `MaxApiObjects` | 1..100K | API tạo object thất bại |

⚠️ Điểm thiết kế quan trọng: budget **không phải** user-cancellation — budget ném exception
riêng (`BytecodeBudgetExceededException`), `Run()` bắt và trả kết quả "bytecode skipped".
Chỉ `CancellationToken` của người dùng mới hủy scan thật.

### 3.2. Bộ nhớ & pointer

- **Không `unsafe`, không `GCHandle`**: pointer = handle `ulong` → `(byte[], offset)` trong
  dictionary, mọi đọc/ghi bounds-checked — không có GC interop hazard như VM native.
- File được quét là `ReadOnlyMemory<byte>` **chia sẻ** giữa mọi program trong một lần scan
  (copy 1 lần/không phải mỗi program); VM chỉ đọc — mọi pointer ghi được là bản copy riêng.
- `SDiv` xử lý đúng `long.MinValue / -1`; GEP/Memset/Memcpy/Memcmp clamp bounds.

### 3.3. Ngữ pháp số học

`Bin` (add/sub/mul/and/or/xor/shift) **wrap về đúng width của instruction type** (`i8/i16/i32/i64`)
như LLVM/ClamAV VM — kết quả 64-bit thô chỉ dùng khi width = 64. So sánh signed/unsigned tách
nhóm opcode đúng thứ tự `clambc.h`.

## 4. API layer (`ClamBcVirtualMachine.Api.cs`)

Cung cấp surface API của ClamAV bytecode cho program gọi (`pdf_*`, `json_*`, `matchicon`,
`extract_*`, `buffer_*`, `inflate_*`, PE helpers…):

| Nhóm | Ghi chú trung thực |
|------|---------------------|
| PE (`pe_getx`, section parse) | `TryParsePeSections` đúng `IMAGE_SECTION_HEADER` offsets, bounds qua span |
| PDF (`pdf_getobj`, phase/flags) | Parse object table; materialize object theo yêu cầu |
| `inflate_process` | One-shot + `st.Done=true` — approximation (đổi chủ đề nâng cấp tương lai) |
| `matchicon` | Placeholder so khớp bytes (chưa nối IconMetrics) |
| `json_*` | Parse cả file như JSON (gated bởi `\{`/`\[`) |
| env/reliability | Trả giá trị cố định an toàn |

## 5. Tích hợp quét

`BytecodeContentScanner` là `IContentScanner`: `Directory` (nạp `.cbc`), `Scan(data, path, ct)`
→ engine.Scan → danh sách `BytecodeMatch` (name/rule/offset/return). Được ScannerEngine gắn qua
`ScanOptions.BytecodeDirectory`; project Database nạp `.cbc` như special-DB.

## 6. Kiểm thử

`Program.YaraBytecodeTests.cs` (5): ClamBC program format 7 hợp lệ (1 function, RET constant),
malformed loader rejection, byte-compare zero-shift rejection. ⚠️ Coverage còn mỏng so với VM —
opcode API (PDF/inflate/map) và runtime caps chưa được chứng minh bằng test; cần test vector `.cbc`
thật để hiệu chỉnh semantics.
