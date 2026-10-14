# project-ClamGuard.Bytecode

> Virtual machine for **ClamAV bytecode (`.cbc`)** — the managed counterpart of
> `libclamav/bytecode*`, memory-safe by design: pointers are bounds-checked handle-table entries
> instead of raw pointers.

---

## 1. Project facts

| Property | Value |
|---|---|
| Target framework | `net8.0` |
| Dependency | `ClamGuard.Core` |
| Source files | 18 (13 Models, Parser, Engine, VM + VM.Api, ContentScanner) |
| Input format | `.cbc` — an **ASCII text** file, magic `ClamBC`, numbers nibble-encoded `0x60+n` LSB-first, sections `T` (types) / `E` (API) / `G` (globals) / `A` / `B` (functions/blocks) / `S` |

```text
Models/    ClamBcProgram (metadata, eligibility), ClamBcFunction/Instruction/Operand/Type/Pointer,
           state objects (Buffer/Map/InflateState/PdfObject/MapValue), BytecodeModels (caps)
Parsing/   ClamBcParser.cs
Runtime/   ClamBcEngine.cs (facade), ClamBcVirtualMachine.cs (interpreter core),
           ClamBcVirtualMachine.Api.cs (API handlers), BytecodeBudgetExceededException.cs
Scanning/  BytecodeContentScanner.cs (IContentScanner adapter)
```

## 2. Load & eligibility

```csharp
var engine = ClamBcEngine.LoadDirectory(directory, options);  // or LoadText
IReadOnlyList<BytecodeMatch> hits = engine.Scan(fileBytes, options, ct);
```

- The parser **safely skips** malformed files (`FormatException/OverflowException/IndexOutOfRange/
  ArgumentException` -> skip, never fails the database).
- `ClamBcProgram.IsCompatible(engineFLevel)` + `IsEligibleForFile(data)` filter before the VM runs
  (magic/conditions from program metadata).
- `locals` are capped at 65,536 — a hostile `.cbc` cannot force an unbounded `new int[total]`.
- Opcode numbering **matches `clambc.h` 1.5.4**: `ADD=1...XOR=13, TRUNC/SEXT/ZEXT=14-16,
  BRANCH/JMP/RET/RET_VOID=17-20, ICMP_EQ=21...ICMP_SLE=29, ICMP_SLT=30, SELECT=31, CALL=32/33,
  COPY=34, GEP=37, MEMSET=40...` (verified; the `SLE=29/SLT=30` LLVM order is already correct).

## 3. The VM (`ClamBcVirtualMachine`)

### 3.1. Operational budget (DoS protection)

| Cap | Default/range | Behavior on exhaustion |
|-----|---------------|------------------------|
| `MaxInstructions` (fuel) | validated 1..100M | `BytecodeBudgetExceededException` -> **skip this program**, the file scan continues |
| `MaxRuntime` | validated <= 10 minutes | same (checked every 1024 instructions) |
| `MaxCallDepth` | 1..1024 | skip |
| `MaxAllocatedBytesPerRule` / `MaxExtractedBytes` / `MaxBufferBytes` | <= 512MB | allocation refused -> skip |
| `MaxApiObjects` | 1..100K | object creation fails |

Key design point: the budget is **not** user cancellation — it throws a dedicated exception
(`BytecodeBudgetExceededException`) that `Run()` catches and converts to "bytecode skipped".
Only the user's `CancellationToken` cancels the actual scan.

### 3.2. Memory & pointers

- **No `unsafe`, no `GCHandle`**: a pointer is a `ulong` handle -> `(byte[], offset)` in a
  dictionary, all reads/writes bounds-checked — no GC interop hazard like the native VM.
- The scanned file is a `ReadOnlyMemory<byte>` **shared** across all programs of one scan
  (copied once per scan, not per program); the VM only reads it — every writable pointer targets
  a private copy.
- `SDiv` handles `long.MinValue / -1` correctly; GEP/Memset/Memcpy/Memcmp clamp bounds.

### 3.3. Numeric semantics

`Bin` (add/sub/mul/and/or/xor/shift) **wraps to the LLVM instruction width** (`i8/i16/i32/i64`)
like ClamAV's typed VM — the raw 64-bit value is only used when width = 64. Signed/unsigned
comparisons follow the `clambc.h` opcode groups.

## 4. API layer (`ClamBcVirtualMachine.Api.cs`)

Implements the ClamAV bytecode API surface (`pdf_*`, `json_*`, `matchicon`, `extract_*`,
`buffer_*`, `inflate_*`, PE helpers...):

| Group | Honest status |
|-------|---------------|
| PE (`pe_getx`, section parsing) | `TryParsePeSections` uses correct `IMAGE_SECTION_HEADER` offsets, span bounds-checked |
| PDF (`pdf_getobj`, phase/flags) | Object table parsed; objects materialized on demand |
| `inflate_process` | One-shot + `st.Done=true` — an approximation (a future upgrade) |
| `matchicon` | Placeholder byte comparison (not wired to IconMetrics yet) |
| `json_*` | Parses the whole file as JSON (gated on `{`/`[`) |
| env/reliability | Safe fixed values |

## 5. Scan integration

`BytecodeContentScanner` is an `IContentScanner`: `Directory` (loads `.cbc` files),
`Scan(data, path, ct)` -> engine.Scan -> `BytecodeMatch` list (name/rule/offset/return). It is
attached by ScannerEngine through `ScanOptions.BytecodeDirectory`; project Database loads `.cbc`
as a special database.

## 6. Testing

`Program.YaraBytecodeTests.cs` (5): a valid format-7 ClamBC program (1 function, RET constant),
malformed loader rejection, byte-compare zero-shift rejection. Coverage is thin relative to the
VM — API opcodes (PDF/inflate/map) and the runtime caps are not yet proven by tests; real `.cbc`
test vectors are needed to calibrate semantics.
